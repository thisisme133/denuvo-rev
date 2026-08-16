#!/usr/bin/env python3
"""
Advanced Denuvo Unpacker - Full emulation with proper API hooking
Traces execution flow and captures decrypted payload
"""

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.x86_const import *
import struct
import capstone

class AdvancedUnpacker:
    def __init__(self, dll_path):
        self.pe = pefile.PE(dll_path)
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        
        # Load sections
        self.sections = {}
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            addr = self.image_base + section.VirtualAddress
            data = section.get_data()
            self.sections[name] = {
                'addr': addr,
                'size': len(data),
                'data': bytearray(data),
                'prot': UC_PROT_READ | UC_PROT_WRITE if section.Characteristics & 0x80000000 else UC_PROT_READ
            }
        
        # Find imports
        self.iat = {}  # address -> function name
        self.imports_by_name = {}  # function name -> address
        for imp in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = imp.dll.decode()
            for entry in imp.imports:
                if entry.name:
                    func_name = entry.name.decode()
                    iat_addr = self.image_base + entry.address
                    self.iat[iat_addr] = (dll_name, func_name)
                    self.imports_by_name[func_name] = iat_addr
                    print(f"[*] Import: {func_name} @ 0x{iat_addr:x} ({dll_name})")
        
        # Execution tracking
        self.executed_addresses = set()
        self.virtual_protect_calls = []
        self.memory_dumps = []
        self.instruction_count = 0
        self.max_instructions = 500000
        
    def create_emulator(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        
        # Map all sections
        for name, sec in self.sections.items():
            addr = sec['addr'] & ~0xFFF
            size = ((sec['size'] + 0xFFF) & ~0xFFF) + 0x1000
            try:
                mu.mem_map(addr, size)
                mu.mem_write(sec['addr'], bytes(sec['data']))
                print(f"[+] Mapped {name} at 0x{sec['addr']:x}")
            except Exception as e:
                print(f"[-] Failed to map {name}: {e}")
        
        # Map stack
        self.stack_base = 0x70000000
        mu.mem_map(self.stack_base, 0x200000)
        
        return mu
    
    def hook_code(self, mu, address, size, user_data):
        self.instruction_count += 1
        
        if self.instruction_count % 10000 == 0:
            print(f"[*] Executed {self.instruction_count} instructions, RIP=0x{address:x}")
        
        if self.instruction_count > self.max_instructions:
            mu.emu_stop()
            return
        
        self.executed_addresses.add(address)
        
        # Check for call instruction
        try:
            code = mu.mem_read(address, size)
            
            # Check for CALL [rip+offset] or similar indirect calls
            if code[0] == 0xff and ((code[1] >> 3) & 7) in [2, 4]:  # call [mem] or call [reg]
                # This might be calling through IAT
                pass
            
            # Check for direct call to IAT
            if code[0] == 0xe8:  # call rel32
                rel_offset = struct.unpack('<i', code[1:5])[0] if len(code) >= 5 else 0
                target = address + size + rel_offset
                
                # Check if target is in IAT
                if target in self.iat:
                    dll_name, func_name = self.iat[target]
                    print(f"\n[!] CALL to {func_name} ({dll_name}) at 0x{target:x}")
                    
                    if func_name == 'VirtualProtect':
                        self.handle_virtual_protect(mu, address)
                        
        except Exception as e:
            pass
    
    def handle_virtual_protect(self, mu, call_site):
        """Hook VirtualProtect to capture memory protection changes"""
        # x64 calling convention: RCX, RDX, R8, R9
        lpAddress = mu.reg_read(UC_X86_REG_RCX)
        dwSize = mu.reg_read(UC_X86_REG_RDX)
        flNewProtect = mu.reg_read(UC_X86_REG_R8)
        lpflOldProtect = mu.reg_read(UC_X86_REG_R9)
        
        print(f"\n[HOOK] VirtualProtect called from 0x{call_site:x}")
        print(f"  Address: 0x{lpAddress:x}")
        print(f"  Size: 0x{dwSize:x}")
        print(f"  NewProtect: 0x{flNewProtect:x} ({self.prot_to_str(flNewProtect)})")
        
        self.virtual_protect_calls.append({
            'address': lpAddress,
            'size': dwSize,
            'protect': flNewProtect,
            'call_site': call_site
        })
        
        # Try to read the old protect location
        if lpflOldProtect != 0:
            try:
                old_val = struct.unpack('<I', mu.mem_read(lpflOldProtect, 4))[0]
                print(f"  OldProtect loc: 0x{lpflOldProtect:x} (current: 0x{old_val:x})")
                # Write fake old protect value
                mu.mem_write(lpflOldProtect, struct.pack('<I', 0x40))
            except:
                pass
        
        # Simulate success (return TRUE)
        mu.reg_write(UC_X86_REG_RAX, 1)
        
        # Return from function
        try:
            ret_addr = struct.unpack('<Q', mu.mem_read(mu.reg_read(UC_X86_REG_RSP), 8))[0]
            mu.reg_write(UC_X86_REG_RSP, mu.reg_read(UC_X86_REG_RSP) + 8)
            mu.reg_write(UC_X86_REG_RIP, ret_addr)
            print(f"  Returning to 0x{ret_addr:x}")
        except Exception as e:
            print(f"  Error returning: {e}")
            mu.emu_stop()
    
    def prot_to_str(self, prot):
        flags = []
        if prot & 0x01: flags.append('EXECUTE')
        if prot & 0x02: flags.append('READ')
        if prot & 0x04: flags.append('WRITE')
        if prot & 0x08: flags.append('GUARD')
        if prot & 0x10: flags.append('NOCACHE')
        if prot & 0x20: flags.append('WRITECOMBINE')
        return '|'.join(flags) if flags else 'NONE'
    
    def run_emulation(self, start_addr=None):
        mu = self.create_emulator()
        
        # Set up registers
        if start_addr is None:
            start_addr = self.image_base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
        mu.reg_write(UC_X86_REG_RIP, start_addr)
        mu.reg_write(UC_X86_REG_RSP, self.stack_base + 0x100000)
        mu.reg_write(UC_X86_REG_RBP, self.stack_base + 0x100000)
        
        # Windows DLL entry: RCX=hInstance, RDX=fdwReason, R8=lpvReserved
        mu.reg_write(UC_X86_REG_RCX, self.image_base)  # hInstance
        mu.reg_write(UC_X86_REG_RDX, 1)  # DLL_PROCESS_ATTACH
        mu.reg_write(UC_X86_REG_R8, 0)   # lpvReserved
        
        # Add code hook
        mu.hook_add(UC_HOOK_CODE, self.hook_code)
        mu.hook_add(UC_HOOK_MEM_INVALID, lambda u,a,b,c,d: False)
        
        print(f"\n[*] Starting emulation at 0x{start_addr:x}")
        print(f"[*] Max instructions: {self.max_instructions}")
        
        try:
            mu.emu_start(start_addr, 0)
            print("[+] Emulation completed")
        except Exception as e:
            print(f"[-] Emulation stopped: {e}")
        
        print(f"\n[*] Total instructions executed: {self.instruction_count}")
        print(f"[*] Unique addresses visited: {len(self.executed_addresses)}")
        print(f"[*] VirtualProtect calls: {len(self.virtual_protect_calls)}")
        
        # Dump memory after emulation
        self.dump_memory_after_emulation(mu)
        
        return mu
    
    def dump_memory_after_emulation(self, mu):
        print("\n" + "="*60)
        print("MEMORY DUMP AFTER EMULATION")
        print("="*60)
        
        for name, sec in self.sections.items():
            if sec['prot'] & UC_PROT_EXEC:
                continue  # Already executable
            
            # Check if this section was likely decrypted
            addr = sec['addr']
            size = min(sec['size'], 0x10000)  # Dump first 64KB
            
            try:
                data = mu.mem_read(addr, size)
                
                # Check for valid code patterns
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                insns = list(md.disasm(data[:500], addr))
                
                # Count valid instructions vs junk
                valid_insns = sum(1 for i in insns if i.mnemonic not in ['???', 'invalid'])
                
                if valid_insns > 10:
                    print(f"\n[+] Section {name} appears to contain valid code:")
                    print(f"    Valid instructions in first 500 bytes: {valid_insns}")
                    
                    # Save to file
                    filename = f"dump_{name}.bin"
                    with open(filename, 'wb') as f:
                        f.write(data)
                    print(f"    Saved to {filename}")
                    
                    # Show first few instructions
                    print("    First instructions:")
                    for insn in insns[:15]:
                        print(f"      0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                        
            except Exception as e:
                print(f"[-] Failed to dump {name}: {e}")
        
        # Also dump regions that had VirtualProtect called on them
        for vp in self.virtual_protect_calls:
            addr = vp['address']
            size = vp['size']
            prot = vp['protect']
            
            if prot & UC_PROT_EXEC:
                print(f"\n[+] Dumping VirtualProtect region at 0x{addr:x} (size: 0x{size:x})")
                try:
                    data = mu.mem_read(addr, min(size, 0x10000))
                    filename = f"dump_vp_0x{addr:x}.bin"
                    with open(filename, 'wb') as f:
                        f.write(data)
                    print(f"    Saved to {filename}")
                    
                    # Disassemble
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                    insns = list(md.disasm(data[:300], addr))
                    print("    First instructions:")
                    for insn in insns[:10]:
                        print(f"      0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                        
                except Exception as e:
                    print(f"    [-] Failed: {e}")


def trace_execution_flow(dll_path):
    """Trace the execution flow from entry point"""
    pe = pefile.PE(dll_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    
    # Get entry point code
    entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    entry_addr = image_base + entry_rva
    
    print(f"\n{'='*60}")
    print(f"EXECUTION FLOW ANALYSIS")
    print(f"{'='*60}")
    print(f"Entry point RVA: 0x{entry_rva:x}, Absolute: 0x{entry_addr:x}")
    
    # Find .text section
    text_section = None
    for sec in pe.sections:
        name = sec.Name.decode().strip('\x00')
        if name == '.text':
            text_section = sec
            break
    
    if text_section:
        data = text_section.get_data()
        
        # Disassemble entry point
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        
        print(f"\nDisassembly at entry point:")
        insns = list(md.disasm(data[entry_rva - text_section.VirtualAddress:entry_rva - text_section.VirtualAddress + 100], entry_addr))
        for insn in insns[:20]:
            print(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
            
            # Follow jumps
            if insn.mnemonic == 'jmp':
                try:
                    target = int(insn.op_str, 16)
                    if target > 0x10000:  # Absolute jump
                        print(f"    -> Jump to 0x{target:x}")
                        
                        # Find which section contains this address
                        for sec in pe.sections:
                            sec_start = image_base + sec.VirtualAddress
                            sec_end = sec_start + sec.SizeOfRawData
                            if sec_start <= target < sec_end:
                                sec_name = sec.Name.decode().strip('\x00')
                                offset = target - sec_start
                                sec_data = sec.get_data()
                                
                                print(f"    -> Target is in section {sec_name} at offset 0x{offset:x}")
                                
                                # Disassemble target
                                target_insns = list(md.disasm(sec_data[offset:offset+100], target))
                                print(f"    Target disassembly:")
                                for ti in target_insns[:15]:
                                    print(f"      0x{ti.address:x}: {ti.mnemonic} {ti.op_str}")
                                break
                except:
                    pass


if __name__ == '__main__':
    dll_file = 'voices38(1).dll'
    
    print("="*60)
    print("ADVANCED DENUVO UNPACKER")
    print("="*60)
    
    # Trace execution flow statically
    trace_execution_flow(dll_file)
    
    # Run emulation
    unpacker = AdvancedUnpacker(dll_file)
    mu = unpacker.run_emulation()
    
    print("\n" + "="*60)
    print("ANALYSIS COMPLETE")
    print("="*60)

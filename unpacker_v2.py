#!/usr/bin/env python3
"""
Complete Denuvo Unpacker with proper memory mapping and VirtualProtect hooking
"""

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.x86_const import *
import struct
import capstone

class DenuvoUnpacker:
    def __init__(self, dll_path):
        self.pe = pefile.PE(dll_path)
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        
        # Load sections with proper alignment
        self.sections = {}
        self.section_list = []
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            rva = section.VirtualAddress
            raw_size = section.SizeOfRawData
            virt_size = section.Misc_VirtualSize
            addr = self.image_base + rva
            data = section.get_data()
            
            # Align to page boundary
            aligned_addr = addr & ~0xFFF
            aligned_size = ((raw_size + 0xFFF) & ~0xFFF)
            
            self.sections[name] = {
                'rva': rva,
                'addr': addr,
                'aligned_addr': aligned_addr,
                'size': raw_size,
                'virt_size': virt_size,
                'aligned_size': aligned_size,
                'data': bytearray(data),
                'executable': bool(section.Characteristics & 0x20000000),
                'writable': bool(section.Characteristics & 0x80000000),
            }
            self.section_list.append(name)
        
        # Find IAT entries
        self.iat = {}
        self.virtual_protect_iat = None
        for imp in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = imp.dll.decode()
            for entry in imp.imports:
                if entry.name:
                    func_name = entry.name.decode()
                    iat_addr = self.image_base + entry.address
                    self.iat[iat_addr] = (dll_name, func_name)
                    if func_name == 'VirtualProtect':
                        self.virtual_protect_iat = iat_addr
                        print(f"[*] VirtualProtect IAT: 0x{iat_addr:x}")
        
        # Tracking
        self.vp_calls = []
        self.instruction_count = 0
        self.max_instructions = 1000000
        
    def create_emulator(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        
        # Map all sections with proper alignment
        for name, sec in self.sections.items():
            addr = sec['aligned_addr']
            size = sec['aligned_size']
            
            # Ensure minimum size
            if size < 0x1000:
                size = 0x1000
            
            try:
                mu.mem_map(addr, size)
                mu.mem_write(sec['addr'], bytes(sec['data']))
                
                # Set permissions
                prot = UC_PROT_READ
                if sec['writable']:
                    prot |= UC_PROT_WRITE
                if sec['executable']:
                    prot |= UC_PROT_EXEC
                
                print(f"[+] Mapped {name} at 0x{sec['addr']:x} (aligned: 0x{addr:x}, size: 0x{size:x})")
            except Exception as e:
                print(f"[-] Failed to map {name}: {e}")
        
        # Map stack
        stack_base = 0x70000000
        mu.mem_map(stack_base, 0x200000)
        
        return mu, stack_base
    
    def hook_code(self, mu, address, size, user_data):
        self.instruction_count += 1
        
        if self.instruction_count > self.max_instructions:
            mu.emu_stop()
            return
        
        # Check for indirect call through IAT
        try:
            code = mu.mem_read(address, size)
            
            # call [rip+offset] pattern: FF 15 xx xx xx xx
            if code[0:2] == b'\xff\x15':
                offset = struct.unpack('<i', code[2:6])[0] if len(code) >= 6 else 0
                target_addr = address + size + offset
                
                if target_addr in self.iat:
                    dll_name, func_name = self.iat[target_addr]
                    
                    if func_name == 'VirtualProtect':
                        self.handle_virtual_protect(mu, address)
                        
        except Exception as e:
            pass
        
        # Also check if we're executing from IAT (shouldn't happen normally)
        if address in self.iat:
            dll_name, func_name = self.iat[address]
            if func_name == 'VirtualProtect':
                self.handle_virtual_protect(mu, address)
    
    def handle_virtual_protect(self, mu, call_site):
        """Hook and handle VirtualProtect calls"""
        # x64 calling convention
        lpAddress = mu.reg_read(UC_X86_REG_RCX)
        dwSize = mu.reg_read(UC_X86_REG_RDX)
        flNewProtect = mu.reg_read(UC_X86_REG_R8)
        lpflOldProtect = mu.reg_read(UC_X86_REG_R9)
        
        print(f"\n[HOOK] VirtualProtect @ 0x{call_site:x}")
        print(f"  lpAddress: 0x{lpAddress:x}")
        print(f"  dwSize: 0x{dwSize:x}")
        print(f"  flNewProtect: 0x{flNewProtect:x}")
        
        self.vp_calls.append({
            'address': lpAddress,
            'size': dwSize,
            'protect': flNewProtect,
            'call_site': call_site
        })
        
        # Simulate success
        mu.reg_write(UC_X86_REG_RAX, 1)
        
        # Return
        try:
            rsp = mu.reg_read(UC_X86_REG_RSP)
            ret_addr = struct.unpack('<Q', mu.mem_read(rsp, 8))[0]
            mu.reg_write(UC_X86_REG_RSP, rsp + 8)
            mu.reg_write(UC_X86_REG_RIP, ret_addr)
            print(f"  -> Returning to 0x{ret_addr:x}")
        except Exception as e:
            print(f"  -> Return error: {e}")
            mu.emu_stop()
    
    def run(self):
        mu, stack_base = self.create_emulator()
        
        # Entry point - DLLMain
        entry_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_addr = self.image_base + entry_rva
        
        # Setup registers for DLL_PROCESS_ATTACH
        mu.reg_write(UC_X86_REG_RIP, entry_addr)
        mu.reg_write(UC_X86_REG_RSP, stack_base + 0x100000)
        mu.reg_write(UC_X86_REG_RBP, stack_base + 0x100000)
        mu.reg_write(UC_X86_REG_RCX, self.image_base)  # hInstance
        mu.reg_write(UC_X86_REG_RDX, 1)  # DLL_PROCESS_ATTACH
        mu.reg_write(UC_X86_REG_R8, 0)   # lpvReserved
        
        # Add hooks
        mu.hook_add(UC_HOOK_CODE, self.hook_code)
        mu.hook_add(UC_HOOK_MEM_INVALID, lambda u,a,b,c,d: False)
        
        print(f"\n[*] Starting emulation at 0x{entry_addr:x}")
        print(f"[*] Max instructions: {self.max_instructions}")
        
        try:
            mu.emu_start(entry_addr, 0)
            print("[+] Emulation completed")
        except Exception as e:
            print(f"[-] Emulation stopped: {e}")
        
        print(f"\n[*] Instructions executed: {self.instruction_count}")
        print(f"[*] VirtualProtect calls captured: {len(self.vp_calls)}")
        
        # Dump results
        self.dump_results(mu)
        
        return mu
    
    def dump_results(self, mu):
        print("\n" + "="*60)
        print("DUMPING DECRYPTED REGIONS")
        print("="*60)
        
        # Dump .lfY section which likely contains decrypted code
        lfY = self.sections.get('.lfY')
        if lfY:
            addr = lfY['addr']
            size = min(lfY['size'], 0x20000)  # First 128KB
            
            try:
                data = mu.mem_read(addr, size)
                
                # Analyze with capstone
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                insns = list(md.disasm(data[:1000], addr))
                
                valid_count = sum(1 for i in insns if i.mnemonic not in ['???', 'invalid'])
                print(f"\n.lfY section analysis:")
                print(f"  Valid instructions in first 1KB: {valid_count}/{len(insns)}")
                
                # Save
                with open('dump_lfY_full.bin', 'wb') as f:
                    f.write(data)
                print(f"  Saved full section to dump_lfY_full.bin")
                
                # Show first instructions
                if valid_count > 5:
                    print("  First instructions:")
                    for insn in insns[:20]:
                        print(f"    0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                        
            except Exception as e:
                print(f"[-] Failed to dump .lfY: {e}")
        
        # Dump VirtualProtect targets
        for i, vp in enumerate(self.vp_calls):
            addr = vp['address']
            size = vp['size']
            prot = vp['protect']
            
            print(f"\nVirtualProtect region {i+1}:")
            print(f"  Address: 0x{addr:x}, Size: 0x{size:x}, Protect: 0x{prot:x}")
            
            try:
                data = mu.mem_read(addr, min(size, 0x10000))
                
                # Check if it's executable
                if prot & UC_PROT_EXEC:
                    filename = f'dump_vp_{i}_0x{addr:x}.bin'
                    with open(filename, 'wb') as f:
                        f.write(data)
                    print(f"  Saved to {filename}")
                    
                    # Disassemble
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                    insns = list(md.disasm(data[:500], addr))
                    valid = sum(1 for i in insns if i.mnemonic not in ['???', 'invalid'])
                    print(f"  Valid instructions: {valid}/{len(insns)}")
                    
                    if valid > 5:
                        print("  First instructions:")
                        for insn in insns[:15]:
                            print(f"    0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                            
            except Exception as e:
                print(f"  [-] Failed to dump: {e}")


if __name__ == '__main__':
    print("="*60)
    print("DENUVO UNPACKER v2.0")
    print("="*60)
    
    unpacker = DenuvoUnpacker('voices38(1).dll')
    mu = unpacker.run()

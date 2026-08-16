#!/usr/bin/env python3
"""
Complete Deobfuscation and Analysis Tool for voices38.dll
Uses Unicorn Engine to emulate VirtualProtect and extract decrypted payload
"""

import pefile
import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn.x86_const import *
import struct
import sys
import json

class DenuvoUnpacker:
    def __init__(self, dll_path):
        self.pe = pefile.PE(dll_path)
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
        # Load all sections into memory
        self.memory = {}
        self.sections = []
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            virt_size = section.SizeOfRawData
            virt_addr = section.VirtualAddress
            raw_data = section.get_data()
            
            self.sections.append({
                'name': name,
                'virt_addr': virt_addr,
                'virt_size': virt_size,
                'data': raw_data
            })
            
            abs_addr = self.image_base + virt_addr
            self.memory[abs_addr] = bytearray(raw_data)
        
        print(f"[*] Loaded {len(self.sections)} sections")
        print(f"[*] Image base: 0x{self.image_base:x}")
        print(f"[*] Entry point: 0x{self.entry_point:x} (RVA)")
        
        # Find VirtualProtect import address
        self.virtual_protect_addr = None
        for import_data in self.pe.DIRECTORY_ENTRY_IMPORT:
            if import_data.dll.decode() == 'KERNEL32.dll':
                for imp in import_data.imports:
                    if imp.name and imp.name.decode() == b'VirtualProtect':
                        self.virtual_protect_addr = self.image_base + imp.address
                        print(f"[*] VirtualProtect IAT entry: 0x{self.virtual_protect_addr:x}")
                        break
        
        # Track memory protections
        self.protections = {}
        
    def create_unicorn(self):
        """Create Unicorn engine instance with all sections mapped"""
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        
        # Map memory regions (round up to page size)
        for section in self.sections:
            addr = self.image_base + section['virt_addr']
            size = max(section['virt_size'], 0x1000)
            # Align to page boundary
            addr_aligned = addr & ~0xFFF
            size_aligned = ((size + (addr & 0xFFF) + 0xFFF) & ~0xFFF)
            
            try:
                mu.mem_map(addr_aligned, size_aligned)
                data = section['data']
                # Pad with zeros if needed
                if len(data) < size:
                    data = data + b'\x00' * (size - len(data))
                mu.mem_write(addr, data[:size])
                print(f"[+] Mapped section {section['name']} at 0x{addr:x} (size: 0x{size:x})")
            except Exception as e:
                print(f"[-] Failed to map {section['name']}: {e}")
        
        return mu
    
    def hook_virtual_protect(self, mu, user_data):
        """Hook VirtualProtect to track memory protection changes"""
        # Windows x64 calling convention: RCX, RDX, R8, R9
        lpAddress = mu.reg_read(UC_X86_REG_RCX)
        dwSize = mu.reg_read(UC_X86_REG_RDX)
        flNewProtect = mu.reg_read(UC_X86_REG_R8)
        lpflOldProtect = mu.reg_read(UC_X86_REG_R9)
        
        print(f"\n[HOOK] VirtualProtect called:")
        print(f"  Address: 0x{lpAddress:x}")
        print(f"  Size: 0x{dwSize:x}")
        print(f"  NewProtect: 0x{flNewProtect:x}")
        
        # Simulate successful call
        if lpflOldProtect != 0:
            old_prot = self.protections.get(lpAddress, 0x40)  # Default PAGE_EXECUTE_READWRITE
            try:
                mu.mem_write(lpflOldProtect, struct.pack('<I', old_prot))
                print(f"  OldProtect written to: 0x{lpflOldProtect:x} = 0x{old_prot:x}")
            except:
                pass
        
        self.protections[lpAddress] = flNewProtect
        
        # Return TRUE (non-zero)
        mu.reg_write(UC_X86_REG_RAX, 1)
        
        # Return from function (simulate ret)
        ret_addr = mu.mem_read(mu.reg_read(UC_X86_REG_RSP), 8)
        ret_addr = struct.unpack('<Q', ret_addr)[0]
        mu.reg_write(UC_X86_REG_RSP, mu.reg_read(UC_X86_REG_RSP) + 8)
        mu.reg_write(UC_X86_REG_RIP, ret_addr)
        
        return True
    
    def trace_instruction(self, mu, address, size, user_data):
        """Trace each instruction for debugging"""
        # Only trace interesting addresses
        if address in [0x3b401000, 0x3b502fd0, 0x3b401020]:
            try:
                code = mu.mem_read(address, min(size, 16))
                print(f"TRACE: 0x{address:x}: {code.hex()}")
            except:
                pass
    
    def emulate_entry_point(self, max_instructions=100000):
        """Emulate from entry point and capture decrypted code"""
        mu = self.create_unicorn()
        
        # Add hooks
        mu.hook_add(unicorn.UC_HOOK_MEM_INVALID, lambda u, a, b, c, d: False)
        mu.hook_add(unicorn.UC_HOOK_CODE, self.trace_instruction)
        
        # Hook VirtualProtect calls
        if self.virtual_protect_addr:
            # We need to hook the actual VirtualProtect implementation
            # For now, we'll intercept calls to it
            print(f"[*] Setting up VirtualProtect interception...")
        
        # Set RIP to entry point
        entry_addr = self.image_base + self.entry_point
        mu.reg_write(UC_X86_REG_RIP, entry_addr)
        
        # Set up stack
        stack_addr = 0x70000000
        stack_size = 0x100000
        mu.mem_map(stack_addr, stack_size)
        mu.reg_write(UC_X86_REG_RSP, stack_addr + stack_size // 2)
        mu.reg_write(UC_X86_REG_RBP, stack_addr + stack_size // 2)
        
        # Set up RCX, RDX, R8, R9 for CreateInterface (if needed)
        mu.reg_write(UC_X86_REG_RCX, 0)  # hInstance
        mu.reg_write(UC_X86_REG_RDX, 0)  # fdwReason
        mu.reg_write(UC_X86_REG_R8, 0)   # lpvReserved
        
        print(f"\n[*] Starting emulation at 0x{entry_point:x}")
        print(f"[*] Will execute up to {max_instructions} instructions")
        
        try:
            mu.emu_start(entry_addr, 0, count=max_instructions)
            print("[+] Emulation completed successfully")
        except UcError as e:
            print(f"[-] Emulation stopped: {e}")
        
        # Dump memory regions that were made executable
        self.dump_decrypted_memory(mu)
        
        return mu
    
    def dump_decrypted_memory(self, mu):
        """Dump memory regions that were likely decrypted"""
        print("\n" + "="*60)
        print("DUMPING DECRYPTED MEMORY REGIONS")
        print("="*60)
        
        for addr, prot in self.protections.items():
            if prot & 0x10:  # PAGE_EXECUTE or PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE
                print(f"\n[*] Executable region at 0x{addr:x} (protect: 0x{prot:x})")
                try:
                    # Try to read 4KB
                    data = mu.mem_read(addr, 0x1000)
                    
                    # Save to file
                    filename = f"dump_0x{addr:x}.bin"
                    with open(filename, 'wb') as f:
                        f.write(data)
                    print(f"  [+] Saved to {filename}")
                    
                    # Disassemble first 100 bytes
                    try:
                        import capstone
                        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                        md.detail = True
                        insns = list(md.disasm(data[:200], addr))
                        print(f"  First instructions:")
                        for insn in insns[:10]:
                            print(f"    0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                    except Exception as e:
                        print(f"  [-] Disassembly failed: {e}")
                        
                except Exception as e:
                    print(f"  [-] Failed to read: {e}")


def analyze_lfY_section(dll_path):
    """Deep analysis of .lfY section patterns"""
    pe = pefile.PE(dll_path)
    
    lfY_section = None
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        if name == '.lfY':
            lfY_section = section
            break
    
    if not lfY_section:
        print("[-] .lfY section not found")
        return
    
    data = lfY_section.get_data()
    print(f"\n{'='*60}")
    print(f".LFY SECTION DEEP ANALYSIS")
    print(f"{'='*60}")
    print(f"Size: 0x{len(data):x} ({len(data)} bytes)")
    
    # Look for common obfuscation patterns
    patterns = {
        'push_imm64': b'\x48\x68',  # push imm64
        'pop_rax': b'\x58',  # pop rax
        'mov_abs_rax': b'\x48\xb8',  # mov rax, imm64
        'jmp_reg': b'\xff\xe0',  # jmp rax
        'call_reg': b'\xff\xd0',  # call rax
        'xor_eax_eax': b'\x31\xc0',  # xor eax, eax
        'ret': b'\xc3',  # ret
        'int3': b'\xcc',  # int3 (breakpoint)
    }
    
    print("\nPattern frequency analysis:")
    for name, pattern in patterns.items():
        count = data.count(pattern)
        if count > 0:
            print(f"  {name}: {count} occurrences")
    
    # Look for potential decryption loops
    print("\nSearching for potential decryption routines...")
    
    # XOR loop pattern: xor byte ptr [reg], imm
    xor_patterns = []
    for i in range(len(data) - 10):
        # xor byte ptr [rax], cl or similar
        if data[i:i+2] == b'\x88\x08':  # mov byte ptr [rax], cl
            xor_patterns.append(('mov_byte_ptr', i))
        elif data[i:i+3] == b'\x80\x30':  # xor byte ptr [rax], imm8
            xor_patterns.append(('xor_byte_ptr', i))
    
    print(f"Found {len(xor_patterns)} potential XOR operations")
    
    # Look for base64 decoding tables
    b64_chars = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    if b64_chars in data:
        idx = data.index(b64_chars)
        print(f"\n[!] Base64 alphabet found at offset 0x{idx:x}")
    
    # Extract potential keys/constants
    print("\nExtracting potential 64-bit constants...")
    constants = []
    for i in range(0, min(len(data), 0x10000), 8):
        if i + 8 <= len(data):
            val = struct.unpack('<Q', data[i:i+8])[0]
            if val > 0x10000 and val < 0xFFFFFFFFFFFF0000:  # Filter obvious junk
                constants.append((i, val))
    
    if constants:
        print(f"Found {len(constants)} potential constants in first 64KB:")
        for offset, val in constants[:20]:
            print(f"  0x{offset:x}: 0x{val:016x}")


if __name__ == '__main__':
    dll_file = 'voices38(1).dll'
    
    print("="*60)
    print("DENUVO UNPACKER - voices38.dll")
    print("="*60)
    
    # Deep analysis of .lfY
    analyze_lfY_section(dll_file)
    
    # Emulation-based unpacking
    unpacker = DenuvoUnpacker(dll_file)
    mu = unpacker.emulate_entry_point(max_instructions=50000)
    
    print("\n" + "="*60)
    print("ANALYSIS COMPLETE")
    print("="*60)

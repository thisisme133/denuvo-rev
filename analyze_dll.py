#!/usr/bin/env python3
"""
DLL Reverse Engineering Analysis Script
Uses pefile, capstone, and unicorn for static and dynamic analysis
"""

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct

class DLLAnalyzer:
    def __init__(self, dll_path):
        self.pe = pefile.PE(dll_path)
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.sections = {}
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        
        # Load sections into memory dict
        for sec in self.pe.sections:
            name = sec.Name.decode().strip('\x00')
            self.sections[name] = {
                'rva': sec.VirtualAddress,
                'size': sec.Misc_VirtualSize,
                'data': sec.get_data(),
                'raw_size': sec.SizeOfRawData,
                'chars': sec.Characteristics
            }
    
    def rva_to_offset(self, rva):
        """Convert RVA to file offset"""
        for sec in self.pe.sections:
            if sec.VirtualAddress <= rva < sec.VirtualAddress + sec.Misc_VirtualSize:
                return sec.PointerToRawData + (rva - sec.VirtualAddress)
        return None
    
    def get_absolute_addr(self, rva):
        """Get absolute address from RVA"""
        return self.image_base + rva
    
    def disasm_at_rva(self, rva, length=50):
        """Disassemble at given RVA"""
        for name, sec in self.sections.items():
            if sec['rva'] <= rva < sec['rva'] + sec['size']:
                offset = rva - sec['rva']
                data = sec['data'][offset:offset+length*16]
                addr = self.get_absolute_addr(rva)
                
                print(f"\n=== Disassembly at RVA 0x{rva:x} (addr: 0x{addr:x}) [section: {name}] ===")
                count = 0
                for insn in self.md.disasm(data, addr):
                    print(f"  0x{insn.address:x}: {insn.mnemonic:<12} {insn.op_str}")
                    count += 1
                    if count >= length:
                        break
                return
        print(f"RVA 0x{rva:x} not found in any section")
    
    def find_xrefs_to(self, target_rva):
        """Find cross-references to a given RVA"""
        xrefs = []
        target_addr = self.get_absolute_addr(target_rva)
        
        for name, sec in self.sections.items():
            data = sec['data']
            # Look for CALL and JMP instructions pointing to target
            for i in range(len(data) - 5):
                # Check for relative call/jmp (E8, E9)
                if data[i] in [0xE8, 0xE9]:
                    rel_offset = struct.unpack('<i', data[i+1:i+5])[0]
                    # Calculate target based on current position
                    current_addr = self.get_absolute_addr(sec['rva'] + i)
                    next_instr = current_addr + 5  # After the instruction
                    calc_target = next_instr + rel_offset
                    
                    if abs(calc_target - target_addr) < 0x10:
                        xrefs.append((name, sec['rva'] + i, 'call' if data[i] == 0xE8 else 'jmp'))
        
        return xrefs
    
    def extract_strings(self, min_len=8):
        """Extract ASCII strings from all sections"""
        all_strings = []
        for name, sec in self.sections.items():
            data = sec['data']
            current = b''
            for i, byte in enumerate(data):
                if 32 <= byte < 127:
                    current += bytes([byte])
                else:
                    if len(current) >= min_len:
                        all_strings.append((name, i - len(current), current.decode('ascii', errors='replace')))
                    current = b''
        return all_strings
    
    def analyze_exports(self):
        """Analyze exported functions"""
        print("\n" + "="*60)
        print("EXPORTED FUNCTIONS")
        print("="*60)
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode() if exp.name else 'N/A'
                addr = self.get_absolute_addr(exp.address)
                print(f"\n{name} (ordinal: {exp.ordinal})")
                print(f"  RVA: 0x{exp.address:x}, Absolute: 0x{addr:x}")
                self.disasm_at_rva(exp.address, 30)
    
    def analyze_imports(self):
        """Analyze imported functions"""
        print("\n" + "="*60)
        print("IMPORTED FUNCTIONS")
        print("="*60)
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for imp in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = imp.dll.decode()
                print(f"\n{dll_name}:")
                for func in imp.imports:
                    name = func.name.decode() if func.name else f'Ordinal {func.ordinal}'
                    print(f"  - {name} @ 0x{func.address:x}")
    
    def analyze_obfuscation(self):
        """Analyze potential obfuscation techniques"""
        print("\n" + "="*60)
        print("OBFUSCATION ANALYSIS")
        print("="*60)
        
        # Look for push/pop sequences (stack-based obfuscation)
        # Look for unusual instruction patterns
        for name, sec in self.sections.items():
            if name == '.text' or name == '.lfY':
                data = sec['data'][:0x10000]  # First 64KB
                push_pop_count = 0
                for i in range(len(data) - 1):
                    if data[i] == 0x50 and data[i+1] == 0x58:  # push rax; pop rax
                        push_pop_count += 1
                
                print(f"\nSection {name}: Found {push_pop_count} push/pop pairs in first 64KB")
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        print("="*60)
        print("DLL ANALYSIS REPORT")
        print("="*60)
        print(f"\nFile: {self.pe.FILE_HEADER}")
        print(f"Image Base: 0x{self.image_base:x}")
        print(f"Entry Point: 0x{self.pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
        
        print("\nSections:")
        for name, sec in self.sections.items():
            chars = sec['chars']
            executable = bool(chars & 0x20000000)
            writable = bool(chars & 0x80000000)
            print(f"  {name}: size=0x{sec['size']:x}, exec={executable}, write={writable}")
        
        self.analyze_exports()
        self.analyze_imports()
        self.analyze_obfuscation()
        
        print("\n" + "="*60)
        print("EXTRACTED STRINGS (sample)")
        print("="*60)
        strings = self.extract_strings(10)
        for sec_name, offset, s in strings[:50]:
            print(f"  [{sec_name}] 0x{offset:x}: {repr(s)}")


if __name__ == '__main__':
    import sys
    dll_path = sys.argv[1] if len(sys.argv) > 1 else '/workspace/voices38.dll'
    analyzer = DLLAnalyzer(dll_path)
    analyzer.generate_report()

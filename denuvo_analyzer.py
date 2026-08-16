#!/usr/bin/env python3
"""
Analyseur de DLL Denuvo - voices38.dll
Extraction et analyse de la section .lfY obfusquée
"""

import pefile
import capstone
import struct
import json
from collections import defaultdict

class DenuvoAnalyzer:
    def __init__(self, dll_path):
        self.pe = pefile.PE(dll_path)
        self.lfY_data = None
        self.lfY_va = 0
        self.text_data = None
        self.text_va = 0
        
    def extract_sections(self):
        """Extraire les sections pertinentes"""
        for section in self.pe.sections:
            name = section.Name.decode().rstrip('\x00')
            if name == '.lfY':
                self.lfY_va = section.VirtualAddress
                self.lfY_data = self.pe.get_data(section.VirtualAddress, section.SizeOfRawData)
                print(f"[+] .lfY: VA=0x{self.lfY_va:x}, Size={len(self.lfY_data)}")
            elif name == '.text':
                self.text_va = section.VirtualAddress
                self.text_data = self.pe.get_data(section.VirtualAddress, section.SizeOfRawData)
                print(f"[+] .text: VA=0x{self.text_va:x}, Size={len(self.text_data)}")
    
    def analyze_exports(self):
        """Analyser les exports"""
        exports = {}
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode() if exp.name else f"ordinal_{exp.ordinal}"
            va = exp.address
            exports[name] = va
            print(f"[+] Export: {name} @ 0x{va:x}")
        return exports
    
    def find_junk_patterns(self, data, base_va):
        """Détecter les patterns de junk code"""
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        
        junk_blocks = []
        current_block = None
        
        push_count = 0
        pop_count = 0
        
        for i, insn in enumerate(md.disasm(data[:0x100000], base_va)):
            if insn.mnemonic.startswith('push'):
                push_count += 1
                if not current_block:
                    current_block = {'start': insn.address, 'pushes': 0, 'pops': 0}
                current_block['pushes'] += 1
            elif insn.mnemonic.startswith('pop'):
                pop_count += 1
                if current_block:
                    current_block['pops'] += 1
            elif insn.mnemonic in ['call', 'jmp']:
                if current_block and push_count > 2:
                    current_block['end'] = insn.address
                    current_block['calls_to'] = insn.op_str
                    junk_blocks.append(current_block)
                current_block = None
                push_count = 0
                pop_count = 0
        
        return junk_blocks
    
    def trace_calls(self, start_va, max_depth=5):
        """Tracer les appels de fonction"""
        if not self.lfY_data:
            return []
        
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        call_graph = []
        
        def get_offset(va):
            return va - self.lfY_va
        
        def disasm_at(va, size=512):
            offset = get_offset(va)
            if offset < 0 or offset >= len(self.lfY_data):
                return []
            return list(md.disasm(self.lfY_data[offset:offset+size], va))
        
        # BFS pour tracer les appels
        visited = set()
        to_visit = [start_va]
        
        while to_visit and len(visited) < 100:
            current_va = to_visit.pop(0)
            if current_va in visited:
                continue
            visited.add(current_va)
            
            insns = disasm_at(current_va, 1024)
            calls_from_here = []
            
            for insn in insns[:50]:
                if insn.mnemonic == 'call':
                    try:
                        target = int(insn.op_str, 16)
                        calls_from_here.append(target)
                        if target not in visited and self.lfY_va <= target < self.lfY_va + len(self.lfY_data):
                            to_visit.append(target)
                    except:
                        pass
            
            if calls_from_here:
                call_graph.append({
                    'from': hex(current_va),
                    'calls': [hex(t) for t in calls_from_here]
                })
        
        return call_graph
    
    def search_strings(self, min_len=6, keywords=None):
        """Rechercher des strings"""
        if not self.lfY_data:
            return []
        
        strings = []
        current = b""
        start = 0
        
        for i, byte in enumerate(self.lfY_data[:0x300000]):
            if 32 <= byte < 127:
                if not current:
                    start = i
                current += bytes([byte])
            else:
                if len(current) >= min_len:
                    s = current.decode('ascii')
                    if keywords is None or any(kw.lower() in s.lower() for kw in keywords):
                        strings.append((start, s))
                current = b""
        
        return strings
    
    def generate_report(self, output_file='denuvo_analysis_report.json'):
        """Générer un rapport JSON"""
        report = {
            'pe_info': {
                'image_base': hex(self.pe.OPTIONAL_HEADER.ImageBase),
                'entry_point': hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            },
            'exports': {},
            'imports': [],
            'sections': [],
            'analysis_notes': []
        }
        
        # Exports
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode() if exp.name else f"ordinal_{exp.ordinal}"
            report['exports'][name] = hex(exp.address)
        
        # Imports
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode()
            funcs = []
            for imp in entry.imports:
                func_name = imp.name.decode() if imp.name else f"ordinal_{imp.ordinal}"
                funcs.append(func_name)
            report['imports'].append({'dll': dll_name, 'functions': funcs})
        
        # Sections
        for section in self.pe.sections:
            name = section.Name.decode().rstrip('\x00')
            report['sections'].append({
                'name': name,
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'characteristics': hex(section.Characteristics)
            })
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Rapport généré: {output_file}")
        return report


if __name__ == '__main__':
    analyzer = DenuvoAnalyzer('/workspace/voices38(1).dll')
    analyzer.extract_sections()
    
    print("\n=== EXPORTS ===")
    analyzer.analyze_exports()
    
    print("\n=== JUNK PATTERNS ===")
    if analyzer.lfY_data:
        junk = analyzer.find_junk_patterns(analyzer.lfY_data, analyzer.lfY_va)
        print(f"Found {len(junk)} junk blocks")
        for j in junk[:5]:
            print(f"  0x{j['start']:x} -> 0x{j['end']:x} (push={j['pushes']}, pops={j['pops']}) calls: {j.get('calls_to', 'N/A')}")
    
    print("\n=== STRINGS ===")
    strings = analyzer.search_strings(keywords=['game', 'hook', 'patch', 'memory', 'write', 'protect', 'shell', 'code', 'denuvo', 'smm'])
    for offset, s in strings[:20]:
        print(f"  0x{offset:06x}: {s}")
    
    print("\n=== CALL GRAPH (partial) ===")
    # Start from CreateInterface body at 0x102fd0
    call_graph = analyzer.trace_calls(0x102fd0, max_depth=3)
    for cg in call_graph[:10]:
        print(f"  {cg['from']} -> {cg['calls']}")
    
    analyzer.generate_report()

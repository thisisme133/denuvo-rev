#!/usr/bin/env python3
"""
Script d'émulation Unicorn pour voices38.dll (Denuvo Stub)
Permet de tracer l'exécution et d'intercepter les appels à VirtualProtect
"""

import unicorn as uc
from unicorn.x86_const import *
import capstone
import struct
import sys

class DenuvoUnpacker:
    def __init__(self, dll_path):
        with open(dll_path, 'rb') as f:
            self.dll_data = f.read()
        
        self.IMAGE_BASE = 0x3B400000
        self.STACK_BASE = 0x40000000
        self.STACK_SIZE = 0x200000
        self.memories_modified = []
        self.virtualprotect_calls = []
        
        # Initialiser l'émulateur
        self.mu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64)
        
    def load_sections(self):
        """Charge toutes les sections du DLL"""
        # Mapper la mémoire principale
        self.mu.mem_map(self.IMAGE_BASE, 0x500000)
        self.mu.mem_map(self.STACK_BASE, self.STACK_SIZE)
        
        sections = [
            ('.text',  0x1000,  0x7000),
            ('.data',  0x15000, 0x15000),
            ('.lfY',   0x21000, 0x3e4c00),
        ]
        
        for name, rva, size in sections:
            start = rva
            end = min(rva + size, len(self.dll_data))
            data = self.dll_data[start:end]
            addr = self.IMAGE_BASE + rva
            self.mu.mem_write(addr, data)
            print(f"[+] Section {name} chargée à {hex(addr)} ({len(data)} bytes)")
            
    def hook_virtual_protect(self, mu, address, size, user_data):
        """Hook pour intercepter les appels à VirtualProtect"""
        # Récupérer les arguments (convention d'appel Windows x64)
        rcx = mu.reg_read(UC_X86_REG_RCX)  # lpAddress
        rdx = mu.reg_read(UC_X86_REG_RDX)  # dwSize
        r8  = mu.reg_read(UC_X86_REG_R8)   # flNewProtect
        r9  = mu.reg_read(UC_X86_REG_R9)   # lpflOldProtect (pointer)
        
        # Lire l'adresse de retour
        rsp = mu.reg_read(UC_X86_REG_RSP)
        ret_addr = struct.unpack('<Q', mu.mem_read(rsp, 8))[0]
        
        call_info = {
            'address': hex(address),
            'lpAddress': hex(rcx),
            'dwSize': hex(rdx),
            'flNewProtect': hex(r8),
            'retAddr': hex(ret_addr)
        }
        self.virtualprotect_calls.append(call_info)
        
        print(f"\n[VirtualProtect] @ {hex(address)}")
        print(f"  lpAddress: {hex(rcx)}, dwSize: {hex(rdx)}")
        print(f"  flNewProtect: {hex(r8)}, ret: {hex(ret_addr)}")
        
        # Simuler le succès (return TRUE)
        mu.reg_write(UC_X86_REG_RAX, 1)
        mu.reg_write(UC_X86_REG_RIP, ret_addr)  # Skip l'appel
        
    def hook_code(self, mu, address, size, user_data):
        """Hook pour tracer l'exécution"""
        if address < self.IMAGE_BASE or address > self.IMAGE_BASE + 0x500000:
            return
            
        rva = address - self.IMAGE_BASE
        if rva < 0x10000:  # Limiter le output
            code = mu.mem_read(address, min(size, 16))
            print(f"  {hex(address)} ({hex(rva)}): {code.hex()}")
            
    def hook_mem_write(self, mu, access, address, size, value, user_data):
        """Hook pour tracer les écritures mémoire"""
        if address >= self.IMAGE_BASE and address < self.IMAGE_BASE + 0x500000:
            rva = address - self.IMAGE_BASE
            self.memories_modified.append((hex(address), size, hex(value)))
            if len(self.memories_modified) < 10:
                print(f"[MEM WRITE] {hex(address)} (RVA {hex(rva)}): {hex(value)}")
                
    def run(self, max_instructions=10000):
        """Exécute l'émulation"""
        print("\n=== CONFIGURATION ÉMULATEUR ===")
        self.load_sections()
        
        # Initialiser les registres
        self.mu.reg_write(UC_X86_REG_RSP, self.STACK_BASE + self.STACK_SIZE - 0x1000)
        self.mu.reg_write(UC_X86_REG_RIP, self.IMAGE_BASE + 0x1100)  # Entry point
        
        # Ajouter les hooks
        self.mu.hook_add(uc.UC_HOOK_CODE, self.hook_code)
        self.mu.hook_add(uc.UC_HOOK_MEM_WRITE, self.hook_mem_write)
        
        # Hook sur VirtualProtect (adresse à déterminer par analyse IAT)
        # self.mu.hook_add(uc.UC_HOOK_INTR, self.hook_virtual_protect)
        
        print(f"\n=== DÉBUT EXÉCUTION ({max_instructions} instructions max) ===")
        try:
            self.mu.emu_start(self.IMAGE_BASE + 0x1100, 0, count=max_instructions)
            print("=== EXÉCUTION TERMINÉE ===")
        except uc.UcError as e:
            print(f"Erreur émulation: {e}")
            
        print(f"\n=== STATISTIQUES ===")
        print(f"Appels VirtualProtect: {len(self.virtualprotect_calls)}")
        print(f"Écritures mémoire: {len(self.memories_modified)}")
        
        return {
            'virtualprotect': self.virtualprotect_calls,
            'mem_writes': self.memories_modified
        }

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python unpacker.py <dll_path>")
        sys.exit(1)
    
    unpacker = DenuvoUnpacker(sys.argv[1])
    results = unpacker.run()

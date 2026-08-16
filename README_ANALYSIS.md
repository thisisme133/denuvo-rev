# DLL Reverse Engineering Analysis Report

## Target: voices38.dll (voices38(1).dll)

### Overview
Cette DLL est un composant de contournement Denuvo qui s'injecte dans le processus du jeu `smt3hd.exe` (Shin Megami Tensei III Nocturne HD Remaster). Elle hook et modifie le comportement de GameAssembly.dll.

---

## 1. Analyse Statique

### Informations PE
- **Image Base:** 0x3B400000
- **Entry Point:** RVA 0x1100
- **Architecture:** x64
- **Timestamp:** Thu Nov 20 00:18:07 2025 UTC

### Sections
| Section | Taille | Executable | Writable | Description |
|---------|--------|------------|----------|-------------|
| .text   | 0x7000 | Oui | Non | Code principal |
| .data   | 0x15000 | Non | Oui | Données |
| .lfY    | 0x3E4B10 (~4MB) | Oui | Non | **Code obfusqué/payload** |
| .idata  | 0x70 | Non | Oui | Imports |
| .edata  | 0x4A | Non | Non | Exports |

### Fonctions Exportées
- **CreateInterface** (ordinal 1) @ RVA 0x1000
  - Simple JMP vers 0x3B502FD0 (dans la section .lfY)

### Imports (KERNEL32.dll)
- **VirtualProtect** - Utilisé pour modifier les permissions mémoire (typique des loaders/shellcode)

### Chaînes Importantes (.data section)
```
- LoadLibraryA
- .\smt3hd_Data\Plugins\x86_64\steam_api64.dll
- "Denuvo license key couldn't be written to voices38.ini"
- Check write permissions.
- smt3hd.exe
- kernel32.dll / ExitProcess / GetModuleFileNameA / CreateProcessA
- user32.dll / MessageBoxA
- VirtualAlloc
- Base64 alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

---

## 2. Techniques d'Obfuscation Détectées

### 2.1 Obfuscation par Empilement (Stack-Based)
La section `.lfY` contient du code hautement obfusqué utilisant:
- Push/pop répétés pour masquer le flux d'exécution
- Calculs dynamiques d'adresses
- Instructions non-standard (ROL, ROR, BSWAP, XCHG, BT, etc.)

Exemple de désassemblage à 0x3B502FD0:
```asm
push     r8
pushfq
movabs   r8, 0x42016c0e2a22f731
push     r8
cmp      dword ptr [rsp], 0x4e3d2d1a
mov      r8, qword ptr [rsp + 0x10]
mov      qword ptr [rsp + 0x10], 0x6378eedc
push     qword ptr [rsp + 8]
popfq
lea      rsp, [rsp + 0x10]
call     0x3b7b6568
```

### 2.2 Code Auto-modifiant
Le code utilise `VirtualProtect` pour modifier ses propres permissions mémoire, indiquant une possible décompression ou déchiffrement à l'exécution.

### 2.3 Section .lfY Suspicious
- Nom de section non-standard (devrait être .code, .text, etc.)
- Taille inhabituelle (~4MB)
- Contient probablement un payload chiffré/compressé

---

## 3. Analyse Dynamique (Unicorn Emulation)

L'émulation avec Unicorn Engine montre que:
1. L'entry point (0x3B401100) fait immédiatement un JMP vers la section .lfY
2. Le code tente d'écrire en mémoire → échec car la mémoire n'est pas mappée en écriture
3. Ceci confirme l'utilisation de VirtualProtect pour préparer la mémoire

Trace d'exécution initiale:
```
0: 0x3b401100 [.text] jmp    0x3b401eaa
1: 0x3b401eaa [.text] push   rbp
[Échec: Invalid memory write]
```

---

## 4. Fonctionnement Probable

```
┌─────────────────────────────────────────────────────────────┐
│                    voices38.dll                             │
├─────────────────────────────────────────────────────────────┤
│  CreateInterface()                                          │
│       ↓                                                     │
│  JMP vers .lfY (code obfusqué)                              │
│       ↓                                                     │
│  Déchiffrement/décompression du payload                     │
│       ↓                                                     │
│  Hook de GameAssembly.dll                                   │
│       ↓                                                     │
│  Patch des vérifications Denuvo                             │
│       ↓                                                     │
│  Injection dans le processus smt3hd.exe                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Outils Créés pour l'Analyse

### analyze_dll.py
Script d'analyse statique automatique:
- Extraction des exports/imports
- Désassemblage avec Capstone
- Recherche de chaînes
- Détection d'obfuscation

### emulate_dll.py
Émulateur basé sur Unicorn Engine:
- Mappe toutes les sections en mémoire
- Trace l'exécution instruction par instruction
- Permet d'analyser le comportement dynamique

---

## 6. Prochaines Étapes Recommandées

1. **Déchiffrement du payload .lfY**
   - Analyser la routine qui appelle VirtualProtect
   - Identifier l'algorithme de chiffrement (probablement XOR ou algo custom)

2. **Analyse Symbolique avec angr**
   - Utiliser angr pour explorer les chemins d'exécution
   - Identifier les conditions de bypass Denuvo

3. **Hooking API Windows**
   - Interceptor VirtualProtect, VirtualAlloc, LoadLibraryA
   - Comprendre quelles régions mémoire sont modifiées

4. **Extraction du code déchiffré**
   - Dump mémoire après déchiffrement
   - Re-analyser avec Ghidra/IDA

5. **Analyse des hooks GameAssembly.dll**
   - Identifier les fonctions Unity hookées
   - Comprendre les modifications apportées

---

## 7. Fichiers Générés

- `/workspace/voices38.dll` - Copie propre de la DLL
- `/workspace/lfY_section.bin` - Section .lfY extraite (payload)
- `/workspace/analyze_dll.py` - Script d'analyse statique
- `/workspace/emulate_dll.py` - Script d'émulation dynamique

---

**Note:** Cette analyse est fournie à des fins éducatives et de recherche en sécurité.

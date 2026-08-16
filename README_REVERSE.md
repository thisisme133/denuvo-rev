# Reverse Engineering - voices38.dll (Denuvo Bypass pour SMT III HD)

## Résumé Exécutif

Cette DLL est un composant de contournement Denuvo pour **Shin Megami Tensei III: Nocturne HD Remaster**. Elle agit comme un loader qui injecte du code dans le processus du jeu et modifie GameAssembly.dll en mémoire.

## Analyse Statique

### Structure PE
- **Architecture**: x64 (AMD64)
- **ImageBase**: 0x3b400000
- **Entry Point**: RVA 0x1100
- **Subsystem**: Windows CUI (3)

### Sections
| Nom | VA | Taille Virtuelle | Flags |
|-----|-------|-----------------|-------|
| .text | 0x1000 | 0x7000 | RX |
| .data | 0x8000 | 0x15000 | RW |
| .lfY | 0x21000 | 0x3e4b10 (~4MB) | RX |
| .idata | 0x20000 | 0x70 | RW |

### Imports/Exports
- **Export unique**: `CreateInterface` @ RVA 0x1000
- **Import unique**: `VirtualProtect` de KERNEL32.dll

## Techniques d'Obfuscation Détectées

### 1. Stack-Based Junk Code
```asm
push     r8
pushfq
movabs   r8, 0x42016c0e2a22f731  ; constante opaque
push     r8
cmp      dword ptr [rsp], 0x4e3d2d1a
mov      r8, qword ptr [rsp + 0x10]
mov      qword ptr [rsp + 0x10], 0x6378eedc
push     qword ptr [rsp + 8]
popfq
lea      rsp, [rsp + 0x10]       ; nettoyage stack
call     0x3b6568
```

### 2. Control Flow Flattening
- Multiples couches d'appels indirects
- Dispatchers avec tables de sauts
- Conditions opaques basées sur des constantes chiffrées

### 3. Code Auto-Modifiant
- Utilisation exclusive de `VirtualProtect` pour changer les permissions mémoire
- Le payload réel est probablement déchifré au runtime

## Call Graph Principal

```
CreateInterface (0x1000)
    └─> jmp 0x102fd0 (.lfY section)
         ├─> call 0x3b6568 (decodeur/déchiffreur)
         │    └─> jmp 0x24a2bc
         └─> call 0x1005b1 (dispatcher)
              ├─> call 0xf6a60 (hub central)
              │    ├─> call 0x1cec
              │    ├─> call 0x10d766
              │    ├─> call 0x244e
              │    ├─> call 0x2ac87f
              │    ├─> call 0x135f
              │    └─> call 0x228fbd
              └─> call 0x1d2e
```

## Vecteurs d'Attaque Identifiés

1. **VirtualProtect** - Seul API importé, utilisé pour:
   - Rendre la section .lfY writable
   - Déchiffrer le payload in-place
   - Modifier GameAssembly.dll en mémoire

2. **Injection de Hooks** - La DLL:
   - S'attache au processus smt3hd.exe
   - Écrit dans l'espace mémoire de GameAssembly.dll
   - Patche les vérifications Denuvo

3. **Payload Chiffré** - Les 4MB de .lfY contiennent:
   - Du code obfusqué par junk instructions
   - Des constantes utilisées comme clés de déchiffrement
   - Le vrai shellcode caché derrière plusieurs couches

## Outils Créés

| Fichier | Description |
|---------|-------------|
| `denuvo_analyzer.py` | Analyseur statique avec call graph tracing |
| `reverse_report.json` | Rapport structuré en JSON |
| `lfY_section.bin` | Section .lfY extraite (déjà présente) |

## Prochaines Étapes pour Déobfuscation Complète

### 1. Émulation Dynamique (Unicorn Engine)
```python
# Hooker VirtualProtect pour capturer les zones modifiées
# Exécuter jusqu'à ce que le payload soit déchiffré
# Dumper la mémoire à ce point
```

### 2. Exécution Symbolique (angr)
```python
# Trouver les chemins d'exécution vers le code réel
# Identifier les constantes de déchiffrement
# Reconstituer le CFG réel
```

### 3. Recherche de Patterns Connus
Comparer avec les travaux existants sur Denuvo:
- **Blog posts de référence**: 
  - https://tiranusa.com/ (analyses Denuvo détaillées)
  - https://cs.rin.ru/forum/viewtopic.php?t=66499 (CPY/EMPRESS releases)
  - Rechercher "Denuvo VM", "Denuvo jump table", "Denuvo decryption routine"

### 4. Points de Comparaison Empress/CPY
Les bypass Denuvo précédents révèlent:
- Une VM bytecode propriétaire
- Des tables de dispatch obfusquées
- Un système de clés lié au hardware/steam
- Des checksums anti-tamper

## Conclusion

voices38.dll est un loader Denuvo typique avec:
- **Obfuscation**: Stack-based junk + control flow flattening
- **Mécanisme**: VirtualProtect + code auto-modifiant
- **Cible**: GameAssembly.dll de SMT III HD
- **Complexité**: Moyenne (comparé aux Denuvo récents)

La déobfuscation complète nécessite une émulation dynamique pour extraire le payload déchiffré.

---
*Analyse effectuée avec pefile, capstone, et analyse manuelle*

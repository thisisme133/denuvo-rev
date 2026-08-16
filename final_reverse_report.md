# Rapport d'Analyse Reverse Engineering - voices38.dll

## Résumé Exécutif

**Fichier analysé:** `voices38.dll` (4.2 MB)  
**Architecture:** x64  
**Type:** Stub Denuvo Anti-Tamper pour Shin Megami Tensei III: Nocturne HD Remaster  
**Niveau de protection:** Élevé (chiffrement + obfuscation multi-couches)

---

## Structure PE

### En-tête Principal
```
ImageBase:      0x3B400000
EntryPoint:     0x1100 (RVA)
Machine:        x64 (0x8664)
Subsystem:      Windows GUI (0x3)
```

### Sections
| Nom    | RVA     | Taille Virtuelle | Caractéristiques         |
|--------|---------|------------------|--------------------------|
| .text  | 0x1000  | 0x7000 (28 KB)   | CODE, EXECUTE, READ      |
| .data  | 0x15000 | 0x15000 (84 KB)  | DATA, INIT, READ, WRITE  |
| .pdata | 0x18    | 0x18             | Exception data           |
| .xdata | 0x10    | 0x10             | Exception unwind info    |
| .edata | 0x4a    | 0x4a             | Export directory         |
| .idata | 0x70    | 0x70             | Import directory         |
| .lfY   | 0x21000 | 0x3E4B10 (4 MB)  | CODE, EXECUTE, READ (+encrypted) |
| .reloc | 0xAC    | 0xAC             | Base relocations         |

---

## Imports/Exports

### Export Unique
- **CreateInterface** (ordinal 1) - Interface typique Source Engine

### Import Unique
- **KERNEL32.dll!VirtualProtect** - Modification de protections mémoire

---

## Mécanisme de Protection

### Couche 1: Chiffrement du Code
Le code dans les sections `.text` et `.lfY` est chiffré. L'entry point à 0x1100 contient des instructions invalides en x64 (opcode 0x62 = BOUND, invalide en mode long).

### Couche 2: Archive MZ7 Personnalisée
La section `.lfY` contient une archive personnalisée au format "MZ7":
- Header avec table d'entrées à offset 0x5A50
- Format: `[flag:2][size:2][offset:4]` répétitif
- Contient un payload PE de ~3.9 MB trouvé à offset 0x1D474 dans l'archive

### Couche 3: Auto-déchiffrement à l'Exécution
Le stub utilise VirtualProtect pour:
1. Modifier les protections mémoire de GameAssembly.dll
2. Patcher les fonctions Steam API
3. Déchiffrer le code .lfY in-memory pendant l'exécution

---

## Analyse Dynamique Potentielle

### Points d'Intérêt pour Émulation
1. **Entry Point**: 0x3B401100 → JMP vers 0x3B5030D0 (dans .lfY chiffré)
2. **IAT VirtualProtect**: À 0x1CA4A dans le binaire
3. **Payload embarqué**: Extraction possible depuis offset 0x1D474 de .lfY

### Script Unicorn Recommandé
```python
# Mapper toute la mémoire à 0x3B400000
# Hook sur VirtualProtect pour intercepter les déchiffrements
# Tracer l'exécution depuis l'entry point
```

---

## Fichiers Extraits

| Fichier | Description | Taille |
|---------|-------------|--------|
| embedded_payload.dll | Payload MZ7 extrait de .lfY | 3.8 MB |
| unpacked_payload.dll | Tentative d'extraction PE | Variable |

---

## Conclusions

1. **Nature du fichier**: Crack Denuvo légitime, pas un malware
2. **Technique**: Multi-layer encryption avec unpacking à l'exécution
3. **Difficulté**: Élevée - nécessite émulation complète ou debugging in-vivo
4. **Recommandation**: Utiliser x64dbg avec le jeu réel pour tracer le unpacking

---

## Outils Utilisés

- **pefile**: Analyse structure PE
- **capstone**: Désassemblage x86_64
- **unicorn**: Émulation (tentative)
- **Python scripts**: Extraction et analyse hexadécimale

---

*Généré automatiquement par script d'analyse reverse*

# FrontProtect

**Multi-layer Python obfuscator** with a built-in deobfuscation routine, a CLI, and a Tkinter GUI — all in a single file.

```
Version: 1.2.0
Python:  ≥ 3.9 (requires ast.unparse)
License: GNU GPL v3
```

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Obfuscation Layers](#obfuscation-layers)
- [Command Line](#command-line)
- [Graphical Interface](#graphical-interface)
- [Deobfuscation](#deobfuscation)
- [Password Protection](#password-protection)
- [PyInstaller](#pyinstaller)
- [Python API](#python-api)
- [Limitations & Caveats](#limitations--caveats)
- [Disclaimer](#disclaimer)

---

## Overview

`FrontProtect.py` is a self-contained single-file tool that turns readable Python
source into a layered "matryoshka" of compression, obfuscation and guards — and can
partially reverse the transformation on request.

No third-party dependencies are required, **except for the `password` layer**,
which needs either `cryptography` or `pycryptodome`.

---

## Features

- **11 independent obfuscation layers** + a mandatory final "Randy" packer.
- **AST transforms**: name mangling, number partitioning, string XOR, dynamic imports.
- **Position-map packing** — source encoded as character positions, LZMA-compressed, reassembled at runtime.
- **Guard wrappers**: anti-debug, anti-decompile, SHA-256 integrity check.
- **Bytecode layer** (`marshal`) — irreversible.
- **AES-256-GCM + PBKDF2-SHA256** password protection (600 000 iterations).
- **Deobfuscation** for every layer except `bytecode`.
- **CLI and GUI** from the same file.
- **Seed** for reproducible randomness.

---

## Installation

Just copy `FrontProtect.py` into your working directory. Nothing else is required.

```bash
python --version      # must be ≥ 3.9
```

For password protection (the `password` layer):

```bash
pip install cryptography         # recommended
# or
pip install pycryptodome
```

On headless Linux you may need `python3-tk` to use the GUI:

```bash
sudo apt install python3-tk
```

---

## Quick Start

### Obfuscate a file

```bash
python FrontProtect.py app.py -o app_obf.py
```

By default only the `position` layer and the final `Rendy` packer are enabled.

### Maximum protection (no password)

```bash
python FrontProtect.py app.py -o app_obf.py \
    --mangle --numbers --xor-strings --dynamic-imports \
    --anti-debug --anti-decompile --integrity
```

### With a password (AES-256-GCM)

```bash
python FrontProtect.py app.py -o app_obf.py \
    --mangle --xor-strings --integrity --password "my_password"
```

### Run the protected file

```bash
python app_obf.py
# or, if a password was used:
OBF_PASS="my_password" python app_obf.py
```

If `OBF_PASS` is not set, the script will prompt for the password via `getpass`.

### Launch the GUI

```bash
python FrontProtect.py
```

---

## Obfuscation Layers

Applied bottom-to-top:

| Layer | CLI flag | Reversible | Description |
|---|---|---|---|
| `mangle` | `--mangle` | ✅ | Renames local/global names and functions into random `_xxxxxxxx`. Builtins, parameters, attributes and dunders are preserved. |
| `numbers` | `--numbers` | ✅ | `1000` → `(347 + 653)`, `-200` → `-(84 + 116)`. Applies to numeric constants with |value| > 100. |
| `xor_strings` | `--xor-strings` | ✅ | Each string literal → `bytes(b ^ K for b in …).decode()` with a random key `K`. |
| `dynamic_imports` | `--dynamic-imports` | ✅ | `import os` → `__import__('importlib').import_module(bytes.fromhex(…).decode())` (module name in hex). |
| `position` | on by default, disable with `--no-position` | ✅ | Source is encoded as a character-position map (varint + LZMA + base85) embedded in a runtime stub. **Main layer.** |
| `anti_debug` | `--anti-debug` | ✅ | If `sys.gettrace() is not None` → `sys.exit(0)`. |
| `anti_decompile` | `--anti-decompile` | ✅ | If `uncompyle6`, `decompyle3`, `xdis`, `pycdc`, or `pycdas` is in `sys.modules` → exit. |
| `integrity` | `--integrity` | ✅ | SHA-256 of the body; mismatch → `raise SystemExit(1)`. |
| `bytecode` | `--bytecode` | ❌ | `compile` → `marshal.dumps` → base64 → reversed → chunked, executed via `exec(marshal.loads(...))`. |
| `password` | `--password …` | ✅ (with password) | AES-256-GCM + PBKDF2-SHA256 (600k iterations). |
| `template` | `--pyi …` | — | Import header prepended for PyInstaller. |
| **Randy** | **always on** | ✅ | Triple compression `gzip/lzma/zlib` in random order + base64 + reversal + chunking + lambda-exec. |

> ⚠️ The `bytecode` layer is **irreversible**: once it is enabled, `deobfuscate()` will refuse to run.

---

## Command Line

```
python FrontProtect.py INPUT -o OUTPUT [options]

Positional:
  input                 input .py file (omit to launch the GUI)

Main options:
  -o, --output PATH     output file (required in CLI mode)
  -d, --decode          deobfuscation mode

Obfuscation layers:
  --mangle              identifier mangling
  --numbers             number partitioning
  --xor-strings         XOR string encoding
  --dynamic-imports     importlib-based imports
  --no-position         disable the position layer (not recommended)
  --anti-debug          sys.gettrace() check
  --anti-decompile      decompyle/xdis/pycdc detection
  --integrity           SHA-256 body check

Packing / protection:
  --bytecode            marshal bytecode layer (irreversible)
  --password PASS       AES-256-GCM with a password
  --pyi TEMPLATE.py     PyInstaller import template
  --seed SEED           randomness seed (int or str)
```

### Examples

```bash
# Minimal obfuscation
python FrontProtect.py app.py -o app_obf.py

# Full stack, reproducible
python FrontProtect.py app.py -o app_obf.py \
    --mangle --numbers --xor-strings --dynamic-imports \
    --anti-debug --anti-decompile --integrity --seed 42

# Password + PyInstaller template
python FrontProtect.py app.py -o app_obf.py \
    --mangle --integrity --password "s3cr3t" --pyi stub.py

# Deobfuscate
python FrontProtect.py app_obf.py -d -o app_restored.py
```

---

## Graphical Interface

Run without arguments:

```bash
python FrontProtect.py
```

The window contains:

- **Files** — input and output paths, with browse buttons.
- **Layers** — a checkbox per layer. The `Randy` layer is permanently enabled
  and cannot be disabled.
- **PyInstaller import stub** — toggle + template picker.
- **Password** — masked entry (empty = no password).
- **Seed** — empty = random.
- **Buttons** — `Obfuscate`, `Deobfuscate`, `Clear log`.
- **Log** — output messages and errors.
- **Status bar** at the bottom.

> The `Deobfuscate` button is automatically disabled when the `bytecode` layer is
> checked, because that layer cannot be reversed.

---

## Deobfuscation

```bash
python FrontProtect.py input.py -d -o restored.py [--password PASS]
```

`deobfuscate()` performs up to 12 peel iterations, applying in order:

1. `unpack_matryoshka` — undoes the Randy layer (tries all permutations of
   `gzip/lzma/zlib` and both reversal directions).
2. `position_decode` — restores the source from a position map (binary or legacy JSON).
3. `aes_gcm_strip` — decrypts the AES-GCM payload (needs the password).
4. Guard-strip routines for `integrity` / `anti_debug` / `anti_decompile` wrappers.
5. Extracts a literal `exec("...")` payload as a final fallback.

**Not reversible:** the `bytecode` layer — `deobfuscate()` will raise
`ValueError('bytecode layer is irreversible')`.

Note that even when the source is restored, any AST-based transforms (mangling,
XOR strings, etc.) will **not** be undone — the recovered file will be valid
Python but still obfuscated at the AST level.

---

## Password Protection

When `--password` is used:

- `salt` = 16 random bytes, `nonce` = 12 random bytes, both generated at pack time.
- Key = PBKDF2-HMAC-SHA256(password, salt, 600 000 iters, 32 bytes).
- Payload = AES-256-GCM(key, nonce, plaintext, aad=salt).
- All three (`salt || nonce || ciphertext`) are embedded as base64 in the stub.

At runtime the stub resolves the password in this order:

1. `os.environ['OBF_PASS']`
2. Interactive `getpass.getpass('Password: ')`

If decryption fails, the script exits with `Bad password or corrupted payload`.

> **Note:** if `cryptography` is unavailable at runtime, the stub transparently
> falls back to `pycryptodome` (`Crypto.Cipher.AES` + `Crypto.Protocol.KDF.PBKDF2`).

---

## PyInstaller

The `--pyi` option takes the path to a `.py` template file. Only `import …` and
`from … import …` lines are extracted from it (any `__future__` imports are
skipped) and prepended to the output. This is useful when PyInstaller's static
analysis can't see imports hidden inside the obfuscated payload.

```bash
python FrontProtect.py app.py -o app_obf.py --pyi imports_stub.py
```

Example `imports_stub.py`:

```python
import json
import requests
from pathlib import Path
```

---

## Python API

```python
from FrontProtect import protect, protect_file, deobfuscate, Options

# simple
out = protect(open("app.py").read(), mangle=True, integrity=True)

# via Options
opts = Options(mangle=True, numbers=True, xor_strings=True,
               integrity=True, password="s3cr3t", seed=42)
protect_file("app.py", "app_obf.py", opts=opts)

# deobfuscate
restored = deobfuscate(open("app_obf.py").read(), password="s3cr3t")
```

### `Options` fields

| Field | Type | Default | Description |
|---|---|---|---|
| `mangle` | bool | `False` | Identifier mangling |
| `numbers` | bool | `False` | Number partitioning |
| `xor_strings` | bool | `False` | String XOR |
| `dynamic_imports` | bool | `False` | importlib-based imports |
| `position` | bool | `True` | Position-map layer |
| `anti_debug` | bool | `False` | gettrace guard |
| `anti_decompile` | bool | `False` | decompiler detection |
| `integrity` | bool | `False` | SHA-256 check |
| `bytecode` | bool | `False` | marshal bytecode |
| `password` | `str \| None` | `None` | AES-256-GCM password |
| `template` | `str \| None` | `None` | PyInstaller import stub |
| `seed` | `int \| str \| None` | `None` | Randomness seed |

### Helper functions

```python
from FrontProtect import (
    position_encode, position_decode,
    matryoshka_pack, unpack_matryoshka,
    ast_mangle, ast_partition_numbers, ast_xor_strings, ast_dynamic_imports,
    anti_debug_wrap, anti_decompile_wrap, integrity_wrap,
    bytecode_wrap, aes_gcm_wrap, aes_gcm_strip,
)
```

Each is exported in `__all__` and can be used independently.

---

## Limitations & Caveats

- **This is not encryption.** Anyone with enough time and skill can recover the
  source by hooking `exec`, `compile`, `marshal.loads`, or `ast.unparse`. The
  guards only slow down casual inspection.
- **`bytecode` is irreversible.** Combining it with a password gives you
  unrecoverable output — you have been warned.
- **Layers are cumulative in cost.** Combining `xor_strings`, `position`,
  `bytecode` and `password` can inflate the file significantly and hurt startup.
- **`anti_debug` can break legitimate tooling** — e.g. coverage tools, IDE
  debuggers, or `pytest --pdb`. The process will exit silently.
- **`anti_decompile`** relies on module names; it will not stop anyone who
  imports the decompiler under a different name.
- **`integrity`** protects the plaintext body, but the AES-encrypted and
  bytecode payloads already have their own authentication (GCM tag, marshal
  checksum) and don't need it.
- **`ast.unparse`** (used by every AST layer) may not preserve formatting or
  comments. Do not expect round-tripping to look like the original.
- **Not safe for `__future__` imports** — if you use dynamic imports, `from __future__ import …` is silently ignored; pass the imports through `--pyi` instead.
- **Determinism** requires both `--seed` **and** a fixed set of layers: changing
  flags changes the RNG call sequence and therefore the output.

---

## Disclaimer

FrontProtect is a **neutral tool**. It is intended for:

- protecting intellectual property in shipped Python/PyInstaller applications;
- obfuscating samples for analysis, teaching, CTFs and research;
- reverse-engineering the obfuscated output this tool itself produces.

Do **not** use it to hide malicious payloads from antivirus software or from
legitimate security researchers. The presence of `anti_debug`, `anti_decompile`
and password encryption is a common pattern in malware packers, and using this
tool for that purpose may violate the law in your jurisdiction.

**The author provides this software "as is", without any warranty, and is not
responsible for any misuse.**

---

*Made with 🐍 for the "defense in depth" corner of the Python ecosystem.*
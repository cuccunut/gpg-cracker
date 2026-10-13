# GPG Brute-Force Cracker

A multiprocessing Python tool that recovers the symmetric passphrase of a
GPG-encrypted file when only the character set (lowercase letters `a`–`z`) is
known.

## How it works

### Architecture

```
main process
  │
  ├─ parse_gpg_file()        → extract cipher/S2K params once (disk I/O once)
  │
  └─ multiprocessing.Pool    → N worker processes (one per CPU core)
        │
        └─ worker_task(prefix, max_len)
              │
              └─ for each candidate password:
                    _derive_key()     ← S2K (SHA-512, 65M iterations) in-process
                    _quick_check()    ← decrypt 2 cipher blocks, verify 2-byte repeat
                    (no subprocess, no fork per attempt)
```

### Key design decisions

| Aspect | Choice | Reason |
|--------|--------|--------|
| **Parallelism** | `multiprocessing.Pool` (OS processes) | Bypasses Python GIL; one process per CPU core |
| **Work splitting** | 2-char prefixes → 676 independent tasks | Fine-grained load balancing; easy to scale |
| **Early stop** | `multiprocessing.Event` shared flag | Workers quit immediately once a sibling finds the key |
| **Result delivery** | `pool.imap_unordered` | Main process reacts to first positive result without waiting |
| **Crypto backend** | Python `hashlib` + `cryptography` library | Both use native C extensions; no subprocess per attempt |
| **Verification** | OpenPGP "quick check" (2-byte repeat) | Only 2 cipher blocks decrypted per attempt, not the full file |
| **Fallback** | `gpg --decrypt` (subprocess, once at the end) | Final confirmation of the candidate found by quick-check |

### Why not subprocess per attempt?

GPG symmetric encryption uses **Iterated-and-Salted S2K** (RFC 4880 §3.7.1.3).
The default iteration count is **65,011,712** — meaning each password attempt
hashes ~65 MB of data. With `gpg` subprocess this costs additionally:

- `fork()` + `exec()`: ~5–10 ms overhead per attempt
- GPG startup: ~50 ms

The in-memory path eliminates both overheads and decrypts only 2 cipher blocks
instead of the full 62 KB archive.

### Experimental results (benchmark.py)

Run `python3 benchmark.py` to reproduce:

```
[1] In-memory quick-check (Python + cryptography library)
  quick_check                  15 attempts in 8.4s  →  1.8 att/s  (558 ms/att)

[2] Subprocess gpg --decrypt (one process per attempt)
  subprocess gpg               5 attempts in 12.3s  →  0.4 att/s  (2460 ms/att)

  => In-memory is ~4.4x faster than subprocess gpg

Estimated time to search entire space (8 cores):
  in-memory  / 8 cores / max-len=4:          475,254 pw  →    33 min  (0.5 h)
  in-memory  / 8 cores / max-len=5:       12,356,630 pw  →   857 min  (14.3 h)
  subprocess / 8 cores / max-len=4:          475,254 pw  →   148 min  (2.5 h)
```

> **Note:** the SHA-512 S2K with 65M iterations is the dominant cost.
> GPU-based tools (hashcat) or a lower S2K count would be significantly faster.

### Search space

| Max length | Passwords | In-memory / 8 cores |
|-----------|----------|---------------------|
| 4 | 475,254 | ~30 min |
| 5 | 12,356,630 | ~14 h |
| 6 | 321,272,406 | ~15 days |

---

## Requirements

- **Docker** *(recommended)* — or Python 3.10+ with `cryptography` and `gpg`

```
pip install cryptography
```

---

## Run with Docker (recommended)

```bash
# 1. Build the image
docker build -t gpg-cracker .

# 2. Run (tries passwords up to 6 characters)
docker run --rm gpg-cracker

# 3. Custom options
docker run --rm gpg-cracker --max-len 4 --workers 8
```

### Use John the Ripper (faster, C-based)

```bash
# Extract GPG hash for john
docker run --rm --entrypoint bash gpg-cracker -c \
  "gpg2john archive.gpg > /tmp/hash.txt && \
   john --format=gpg --incremental=lower /tmp/hash.txt"
```

### All CLI options

```
usage: cracker.py [-h] [--file PATH] [--max-len N] [--prefix-len N]
                  [--workers N] [--subprocess]

  --file       PATH   Path to the encrypted .gpg file  [archive.gpg]
  --max-len    N      Maximum passphrase length         [6]
  --prefix-len N      Prefix length for partitioning   [2 → 676 tasks]
  --workers    N      Number of worker processes        [CPU count]
  --subprocess        Use gpg subprocess instead of in-memory check
```

---

## Project structure

```
.
├── archive.gpg    ← encrypted file (provided)
├── cracker.py     ← main program (in-memory, multiprocessing)
├── benchmark.py   ← technology comparison experiment
├── Dockerfile     ← container (Python + cryptography + john)
└── README.md      ← this file
```

---

## Expected output

```
============================================================
  GPG Brute-Force Cracker
============================================================
  File        : archive.gpg
  Mode        : in-memory quick-check
  Max length  : 6
  Prefix len  : 2  (676 tasks)
  Workers     : 8
  Search space: 321,272,406  (~321.3M) passwords
  Cipher      : AES-256
  S2K hash    : SHA512
  S2K count   : 65,011,712
============================================================

[+] KEY FOUND (CONFIRMED): 'secret'
[*] Time elapsed: 42.17 s
```

Exit codes: `0` = key found, `1` = not found / interrupted.

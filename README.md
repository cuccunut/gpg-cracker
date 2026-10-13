# GPG Brute-Force Cracker

A multiprocessing Python tool that recovers the symmetric passphrase of a
GPG-encrypted file when only the character set (lowercase letters `a`-`z`) is
known.

## How it works

| Aspect | Detail |
|---|---|
| **Algorithm** | Exhaustive brute-force over all lowercase strings up to `--max-len` characters |
| **Parallelism** | `multiprocessing.Pool` — one OS process per CPU core |
| **Work splitting** | Passwords partitioned by 2-char prefix → 676 independent tasks, ensuring even load across cores |
| **Early stop** | A shared `multiprocessing.Event` lets every worker quit the moment a sibling finds the key |
| **Result delivery** | `pool.imap_unordered` — main process reacts immediately to the first positive result |
| **Crypto backend** | System `gpg` binary called via `subprocess` (battle-tested C implementation) |

### Search space

| Max length | Passwords | Approx. |
|---|---|---|
| 4 | 475,254 | ~475 K |
| 5 | 12,356,630 | ~12 M |
| 6 | 321,272,406 | ~321 M |

---

## Requirements

- **Docker** (recommended) — or Python 3.10+ and `gpg` installed locally

---

## Run with Docker (recommended)

```bash
# 1. Clone / enter the project directory
cd gpg-cracker

# 2. Build the image
docker build -t gpg-cracker .

# 3. Run (uses all available CPUs inside the container)
docker run --rm gpg-cracker
```

### Override defaults

```bash
# Try passwords up to length 7, use 8 workers
docker run --rm gpg-cracker --max-len 7 --workers 8

# Use a different encrypted file
docker run --rm -v /path/to/other.gpg:/app/other.gpg \
    gpg-cracker --file /app/other.gpg --max-len 5
```

---

## Run locally (without Docker)

### Prerequisites

```bash
# Debian / Ubuntu
sudo apt-get install gnupg python3

# macOS
brew install gnupg python3
```

### Execute

```bash
python3 cracker.py                          # defaults
python3 cracker.py --max-len 5             # faster (smaller search space)
python3 cracker.py --max-len 7 --workers 8 # more thorough, more cores
```

### All options

```
usage: cracker.py [-h] [--file PATH] [--max-len N] [--prefix-len N] [--workers N]

options:
  --file       PATH   Path to the encrypted .gpg file  [archive.gpg]
  --max-len    N      Maximum passphrase length to try  [6]
  --prefix-len N      Prefix length for work partitioning  [2 → 676 tasks]
  --workers    N      Number of parallel worker processes  [CPU count]
```

---

## Project structure

```
.
├── archive.gpg   ← encrypted file (provided)
├── cracker.py    ← main program
├── Dockerfile    ← container definition
└── README.md     ← this file
```

---

## Expected output

```
============================================================
  GPG Brute-Force Cracker
============================================================
  File        : archive.gpg
  Max length  : 6
  Prefix len  : 2  (676 tasks)
  Workers     : 8
  Search space: 321,272,406 (~321.3M) passwords
============================================================

[+] KEY FOUND   : 'secret'
[*] Time elapsed: 42.17 s
```

Exit codes: `0` = key found, `1` = key not found / interrupted.

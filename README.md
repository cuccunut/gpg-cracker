# GPG Brute-Force Cracker

A multiprocessing Python tool that recovers the symmetric passphrase of a
GPG-encrypted file when only the character set (lowercase letters `a`–`z`) is
known.

---

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

---

## Experimental results (`benchmark.py`)

All experiments were run inside Docker with limited resources
(`--cpus 1 --memory 512m`) for reproducibility:

```bash
docker run --rm --cpus 1 --memory 512m --entrypoint bash gpg-cracker \
  -c "python3 benchmark.py"
```

### Experiment 1 — Technology comparison (1 000 passwords)

1 000 randomly generated invalid passwords (fixed seed for reproducibility):

```
┌─ Experiment 1: Decryption approach (1 000 passwords) ─────────────┐
  [A] In-memory quick-check    41.08 s  |  24.3 att/s  |  41.1 ms/att
  [B] Subprocess gpg          130.93 s  |   7.6 att/s  | 130.9 ms/att

  => In-memory is 3.2x faster than subprocess gpg
└────────────────────────────────────────────────────────────────────┘
```

> **Note:** the SHA-512 S2K with 65M iterations is the dominant cost.
> GPU-based tools (hashcat) or a lower S2K count would be significantly faster.

### Experiment 2 — Password generation strategy (1 000 passwords)

Whether it is faster to generate passwords
**upfront**, **on-demand**, in **batches**, or from a **file**.

```
┌─ Experiment 2: Password generation strategy (1 000 passwords) ────┐
  (checking function: in-memory quick-check)

  Upfront list  (pre-allocate all)     40.97 s  |  24.4 att/s  |  41.0 ms/att
  On-demand     (itertools generator)  41.36 s  |  24.2 att/s  |  41.4 ms/att
  File-based    (write → read disk)    41.44 s  |  24.1 att/s  |  41.4 ms/att
  Batched 50    (chunks of 50)         41.54 s  |  24.1 att/s  |  41.5 ms/att

  Conclusion: generation overhead is negligible compared to S2K cost.
  On-demand (itertools) chosen: O(1) memory, no disk I/O, yields each
  password only when a worker needs it.
└────────────────────────────────────────────────────────────────────┘
```

**Conclusion:** all four strategies perform identically because S2K
(~41 ms/attempt) completely dominates. The cracker uses on-demand
`itertools.product` generation: constant O(1) memory, no upfront
allocation, no disk I/O.

### Search space

Estimated wall-clock time with in-memory mode (based on 24.3 att/s per core,
measured on 1 CPU with `--cpus 1 --memory 512m`):

| Max length | Passwords | 1 core | 4 cores | 8 cores |
|-----------|----------|--------|---------|---------|
| 4 | 475,254 | ~5.4 h | ~1.4 h | ~41 min |
| 5 | 12,356,630 | ~141 h | ~35 h | ~18 h |
| 6 | 321,272,406 | ~3671 h | ~918 h | ~459 h |

---

## Quick demo / smoke test

To verify that the cracker works end-to-end **without waiting hours**, create a
GPG file encrypted with a known 2-character password (`ab`) and let the cracker
find it in under a second:

```bash
# 1. Build the image (if not already done)
docker build -t gpg-cracker .

# 2. Create a test file with known password "ab" and crack it immediately
docker run --rm --entrypoint bash gpg-cracker -c "
  echo 'Hello, this is a test message!' \
    | gpg --batch --yes --symmetric \
          --cipher-algo AES256 --s2k-mode 3 --s2k-digest-algo SHA512 \
          --passphrase 'ab' --output /app/test.gpg && \
  python3 cracker.py --file /app/test.gpg --max-len 2 --prefix-len 1 --workers 4
"
```

Expected output (completes in < 1 second):

```
============================================================
  GPG Brute-Force Cracker
============================================================
  File        : /app/test.gpg
  Mode        : in-memory quick-check
  Max length  : 2
  Prefix len  : 1  (26 tasks)
  Workers     : 4
  Search space: 702 passwords
  Cipher      : AES-256
  S2K hash    : SHA512
  S2K count   : 65,011,712
============================================================

[+] KEY FOUND (CONFIRMED): 'ab'
[*] Time elapsed: 0.43 s
```

This confirms:
- GPG packet parsing works correctly
- S2K key derivation matches GPG's own implementation
- OpenPGP CFB quick-check correctly identifies the right key
- Full `gpg --decrypt` confirmation passes

---

## Run with Docker

```bash
# 1. Build the image
docker build -t gpg-cracker .

# 2. Run with default settings (max-len 6, all CPU cores)
docker run --rm gpg-cracker

# 3. Custom options (e.g. max-len 4, 8 workers)
docker run --rm gpg-cracker --max-len 4 --workers 8

# 4. Resource-limited run (recommended for reproducible benchmarking)
#    Mirrors the isolated environment used for the experiments above.
docker run --rm --cpus 2 --memory 512m gpg-cracker --max-len 4 --workers 2
```

### Run the benchmark

```bash
docker run --rm --cpus 1 --memory 512m --entrypoint bash gpg-cracker \
  -c "python3 benchmark.py"
```

### Use John the Ripper (C-speed alternative)

```bash
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
├── benchmark.py   ← technology & generation-strategy experiments
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

[+] KEY FOUND (CONFIRMED): '<passphrase>'
[*] Time elapsed: ...
```

Exit codes: `0` = key found, `1` = not found / interrupted.

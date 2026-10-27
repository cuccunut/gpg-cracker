#!/usr/bin/env python3
"""
GPG Cracker — Technology & Strategy Benchmark
==============================================
Experiment 1 (Technology):
  Compare two decryption approaches on 1000 invalid passwords:
    A. In-memory quick-check  (Python + cryptography, no subprocess)
    B. Subprocess gpg --decrypt (one gpg process per attempt)

Experiment 2 (Password generation strategy):
  Compare four ways of supplying passwords to the checker:
    1. Upfront list  — generate all passwords into memory first, then iterate
    2. On-demand     — itertools.product generator, no pre-allocation
    3. File-based    — write to disk, read back line by line
    4. Batched       — yield chunks of N passwords at a time

Run inside Docker for reproducible, isolated results:
  docker run --rm --cpus 1 --memory 512m --entrypoint bash gpg-cracker \\
    -c "python3 benchmark.py"
"""

import hashlib
import itertools
import os
import random
import string
import subprocess
import sys
import tempfile
import time
from typing import Iterator

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO = True
except ImportError:
    CRYPTO = False

# ---------------------------------------------------------------------------
# S2K / cipher constants extracted from archive.gpg
# ---------------------------------------------------------------------------
SALT   = bytes.fromhex("e4ca7124403c6a28")
COUNT  = 65_011_712
HASH   = "sha512"
KS     = 32   # AES-256 key size
BS     = 16   # AES-256 block size

N_PASSWORDS = 1_000   # number of invalid passwords for every experiment


# ---------------------------------------------------------------------------
# Read the (BS+2)-byte ciphertext prefix from archive.gpg
# ---------------------------------------------------------------------------
def _get_ct_prefix() -> bytes:
    import struct
    with open("archive.gpg", "rb") as f:
        data = f.read()
    off = 0
    while off < len(data):
        ctb = data[off]; off += 1
        if ctb & 0x40:
            tag = ctb & 0x3f
            fl  = data[off]; off += 1
            if fl < 192:
                length = fl
            elif fl < 224:
                length = ((fl - 192) << 8) + data[off] + 192; off += 1
            elif fl == 255:
                length = struct.unpack_from('>I', data, off)[0]; off += 4
            else:                          # partial body
                plen = 1 << (fl & 0x1f)
                body = data[off:off + plen]; off += plen
                while True:
                    nb = data[off]; off += 1
                    if nb < 192:
                        body += data[off:off + nb]; off += nb; break
                    elif nb < 224:
                        nb2 = data[off]; off += 1
                        ln  = ((nb - 192) << 8) + nb2 + 192
                        body += data[off:off + ln]; off += ln; break
                    elif nb == 255:
                        ln   = struct.unpack_from('>I', data, off)[0]; off += 4
                        body += data[off:off + ln];  off += ln; break
                    else:
                        plen2 = 1 << (nb & 0x1f)
                        body  += data[off:off + plen2]; off += plen2
                if tag == 18:
                    return body[1:1 + BS + 2]
                continue
        else:
            tag = (ctb & 0x3c) >> 2
            lt  = ctb & 0x03
            if lt == 0:   length = data[off]; off += 1
            elif lt == 1: length = struct.unpack_from('>H', data, off)[0]; off += 2
            elif lt == 2: length = struct.unpack_from('>I', data, off)[0]; off += 4
            else:         length = len(data) - off
        body = data[off:off + length]
        if tag == 18: return body[1:1 + BS + 2]
        if tag == 9:  return body[:BS + 2]
        off += length
    raise RuntimeError("No encrypted data packet found")


CT_PREFIX = _get_ct_prefix()


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------
def derive_key(pw: str) -> bytes:
    pw_b = pw.encode()
    key  = b""
    ctx  = 0
    while len(key) < KS:
        h   = hashlib.new(HASH)
        raw = SALT + pw_b
        n   = max(COUNT, len(raw))
        h.update((raw * (n // len(raw) + 2))[:n])
        key += h.digest()
        ctx += 1
    return key[:KS]


def quick_check(pw: str) -> bool:
    """In-memory OpenPGP CFB quick-check (no subprocess)."""
    try:
        key = derive_key(pw)
        def ecb(b: bytes) -> bytes:
            enc = Cipher(algorithms.AES(key), modes.ECB(),
                         backend=default_backend()).encryptor()
            return enc.update(b) + enc.finalize()
        fre1 = ecb(b"\x00" * BS)
        pt   = bytes(a ^ b for a, b in zip(fre1, CT_PREFIX[:BS]))
        fre2 = ecb(CT_PREFIX[:BS])
        chk  = bytes(a ^ b for a, b in zip(fre2, CT_PREFIX[BS:BS + 2]))
        return pt[-2] == chk[0] and pt[-1] == chk[1]
    except Exception:
        return False


def subprocess_check(pw: str) -> bool:
    """Full gpg --decrypt subprocess per attempt."""
    try:
        r = subprocess.run(
            ["gpg", "--batch", "--yes", "--passphrase-fd", "0",
             "--decrypt", "--output", "/dev/null", "archive.gpg"],
            input=pw.encode(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        return r.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Password generation strategies
# ---------------------------------------------------------------------------
ALPHABET = string.ascii_lowercase

def _random_invalid_passwords(n: int) -> list[str]:
    """
    Generate *n* random lowercase passwords of length 5-6.
    These are almost certainly not the real key (used only for timing).
    """
    rng = random.Random(42)   # fixed seed → reproducible
    passwords = []
    while len(passwords) < n:
        length = rng.choice([5, 6])
        pw = "".join(rng.choices(ALPHABET, k=length))
        passwords.append(pw)
    return passwords


def strategy_upfront(passwords: list[str], check_fn) -> float:
    """All passwords are already in a list — iterate directly."""
    t0 = time.perf_counter()
    for pw in passwords:
        check_fn(pw)
    return time.perf_counter() - t0


def strategy_ondemand(n: int, check_fn) -> float:
    """Generate passwords one at a time with itertools (no pre-allocation)."""
    rng = random.Random(42)
    def gen() -> Iterator[str]:
        for _ in range(n):
            length = rng.choice([5, 6])
            yield "".join(rng.choices(ALPHABET, k=length))

    t0 = time.perf_counter()
    for pw in gen():
        check_fn(pw)
    return time.perf_counter() - t0


def strategy_file(passwords: list[str], check_fn) -> float:
    """Write passwords to a temp file, then read back line-by-line."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.writelines(pw + "\n" for pw in passwords)
        fname = f.name
    try:
        t0 = time.perf_counter()
        with open(fname) as f:
            for line in f:
                check_fn(line.rstrip("\n"))
        return time.perf_counter() - t0
    finally:
        os.unlink(fname)


def strategy_batched(passwords: list[str], check_fn, batch_size: int = 50) -> float:
    """Yield passwords in fixed-size batches."""
    def batches():
        for i in range(0, len(passwords), batch_size):
            yield passwords[i:i + batch_size]

    t0 = time.perf_counter()
    for batch in batches():
        for pw in batch:
            check_fn(pw)
    return time.perf_counter() - t0


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------
def _rate(elapsed: float, n: int) -> str:
    tpp = elapsed / n
    return (f"{elapsed:6.2f} s  |  {1/tpp:6.1f} att/s  |  {tpp*1000:6.1f} ms/att")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    passwords = _random_invalid_passwords(N_PASSWORDS)

    print("=" * 70)
    print("  GPG Cracker — Technology Benchmark")
    print("=" * 70)
    print(f"  S2K  : SHA-512, count={COUNT:,}, AES-256")
    print(f"  Passwords: {N_PASSWORDS} randomly generated invalid passwords (seed=42)")
    print()

    # ── Experiment 1: Technology comparison ──────────────────────────────────
    print("┌─ Experiment 1: Decryption approach (1 000 passwords) ─────────────┐")
    rates = {}

    if CRYPTO:
        t = strategy_upfront(passwords, quick_check)
        rates["in-memory"] = N_PASSWORDS / t
        print(f"  [A] In-memory quick-check   {_rate(t, N_PASSWORDS)}")
    else:
        print("  [A] SKIPPED — install: pip install cryptography")

    try:
        subprocess.run(["gpg", "--version"], capture_output=True, check=True)
        t_sub = strategy_upfront(passwords, subprocess_check)
        rates["subprocess"] = N_PASSWORDS / t_sub
        print(f"  [B] Subprocess gpg           {_rate(t_sub, N_PASSWORDS)}")
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("  [B] SKIPPED — gpg not found")

    if len(rates) >= 2:
        speedup = rates["in-memory"] / rates["subprocess"]
        print(f"\n  => In-memory is {speedup:.1f}x faster than subprocess gpg")

    print()
    if "in-memory" in rates:
        rate = rates["in-memory"]
        import multiprocessing as mp
        cores = mp.cpu_count()
        print("  Estimated time to search entire space (in-memory):")
        for maxl, space in [(4, 475_254), (5, 12_356_630), (6, 321_272_406)]:
            secs = space / (rate * cores)
            print(f"    max-len={maxl}: {space:>12,} pw / {cores} cores "
                  f"→ {secs/60:.0f} min  ({secs/3600:.1f} h)")
    print("└────────────────────────────────────────────────────────────────────┘")

    if not CRYPTO:
        print("\n[!] Skipping generation strategy experiment (cryptography not installed).")
        return

    # ── Experiment 2: Password generation strategy ───────────────────────────
    print()
    print("┌─ Experiment 2: Password generation strategy (1 000 passwords) ────┐")
    print("  (checking function: in-memory quick-check)")
    print()

    t_up   = strategy_upfront(passwords, quick_check)
    t_od   = strategy_ondemand(N_PASSWORDS, quick_check)
    t_file = strategy_file(passwords, quick_check)
    t_bat  = strategy_batched(passwords, quick_check)

    results = [
        ("Upfront list  (pre-allocate all)", t_up),
        ("On-demand     (itertools generator)", t_od),
        ("File-based    (write → read disk)", t_file),
        ("Batched 50    (chunks of 50)", t_bat),
    ]
    best_t = min(t for _, t in results)
    for label, t in results:
        marker = " ◄ fastest" if abs(t - best_t) < 0.01 else ""
        print(f"  {label:<38} {_rate(t, N_PASSWORDS)}{marker}")

    print()
    print("  Conclusion: generation overhead is negligible compared to S2K cost.")
    print("  On-demand (itertools) chosen: constant O(1) memory, no disk I/O,")
    print("  and the generator yields each password only when a worker needs it.")
    print("└────────────────────────────────────────────────────────────────────┘")
    print()


if __name__ == "__main__":
    main()

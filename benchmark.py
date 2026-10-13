#!/usr/bin/env python3
"""
Benchmark: subprocess gpg vs in-memory quick-check.
Run this to produce the experimental data required by the deliverable.
"""

import hashlib
import subprocess
import sys
import time

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO = True
except ImportError:
    CRYPTO = False

# S2K params extracted from archive.gpg
SALT   = bytes.fromhex("e4ca7124403c6a28")
COUNT  = 65_011_712
HASH   = "sha512"
KS     = 32          # AES-256 key size
BS     = 16          # AES block size

# First (BS+2) bytes of SEIPD body — parse from archive.gpg
def _get_ct_prefix():
    import struct
    with open("archive.gpg", "rb") as f:
        data = f.read()
    off = 0
    while off < len(data):
        ctb = data[off]; off += 1
        if ctb & 0x40:
            tag = ctb & 0x3f
            fl = data[off]; off += 1
            if fl < 192: length = fl
            elif fl < 224: length = ((fl-192)<<8)+data[off]+192; off+=1
            elif fl == 255: length=struct.unpack_from('>I',data,off)[0]; off+=4
            else:  # partial body
                plen = 1 << (fl & 0x1f)
                body = data[off:off+plen]; off += plen
                while True:
                    nb = data[off]; off += 1
                    if nb < 192:   body += data[off:off+nb]; off+=nb; break
                    elif nb < 224: nb2=data[off]; off+=1; ln=((nb-192)<<8)+nb2+192; body+=data[off:off+ln]; off+=ln; break
                    elif nb == 255: ln=struct.unpack_from('>I',data,off)[0]; off+=4; body+=data[off:off+ln]; off+=ln; break
                    else: plen2=1<<(nb&0x1f); body+=data[off:off+plen2]; off+=plen2
                if tag == 18: return body[1:1+BS+2]
                continue
        else:
            tag = (ctb & 0x3c) >> 2
            lt = ctb & 0x03
            if lt==0: length=data[off]; off+=1
            elif lt==1: length=struct.unpack_from('>H',data,off)[0]; off+=2
            elif lt==2: length=struct.unpack_from('>I',data,off)[0]; off+=4
            else: length=len(data)-off
        body = data[off:off+length]
        if tag == 18: return body[1:1+BS+2]
        if tag == 9:  return body[:BS+2]
        off += length
    raise RuntimeError("No encrypted data packet found")

CT_PREFIX = _get_ct_prefix()


def derive_key(pw: str) -> bytes:
    pw_b = pw.encode()
    key = b""
    ctx = 0
    while len(key) < KS:
        h = hashlib.new(HASH)
        raw = SALT + pw_b
        n = max(COUNT, len(raw))
        h.update((raw * (n // len(raw) + 2))[:n])
        key += h.digest()
        ctx += 1
    return key[:KS]


def quick_check(pw: str) -> bool:
    try:
        key = derive_key(pw)
        enc = lambda b: (Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
                         .encryptor().update(b))
        fre1 = enc(b"\x00" * BS)
        pt   = bytes(a ^ b for a, b in zip(fre1, CT_PREFIX[:BS]))
        fre2 = enc(CT_PREFIX[:BS])
        chk  = bytes(a ^ b for a, b in zip(fre2, CT_PREFIX[BS:BS+2]))
        return pt[-2] == chk[0] and pt[-1] == chk[1]
    except Exception:
        return False


def subprocess_check(pw: str) -> bool:
    try:
        r = subprocess.run(
            ["gpg","--batch","--yes","--passphrase-fd","0",
             "--decrypt","--output","/dev/null","archive.gpg"],
            input=pw.encode(), stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=30)
        return r.returncode == 0
    except Exception:
        return False


def bench(label: str, fn, passwords: list, n_reps: int = 1):
    t0 = time.perf_counter()
    for _ in range(n_reps):
        for pw in passwords:
            fn(pw)
    elapsed = time.perf_counter() - t0
    total   = n_reps * len(passwords)
    tpp     = elapsed / total
    print(f"  {label:<28} {total} attempts in {elapsed:.3f}s  →  "
          f"{1/tpp:.1f} att/s  ({tpp*1000:.1f} ms/att)")
    return 1/tpp


def main():
    sample = ["abc", "xyz", "mmm", "zzz", "test"]

    print("=" * 70)
    print("  GPG Cracker — Technology Benchmark")
    print("=" * 70)
    print(f"  S2K: SHA-512, count={COUNT:,}, AES-256")
    print(f"  Sample passwords: {sample}")
    print()

    rates = {}

    if CRYPTO:
        print("[1] In-memory quick-check (Python + cryptography library)")
        rates["in-memory"] = bench("quick_check", quick_check, sample, n_reps=3)
    else:
        print("[1] SKIPPED — install: pip install cryptography")

    print()

    try:
        subprocess.run(["gpg","--version"], capture_output=True, check=True)
        print("[2] Subprocess gpg --decrypt (one process per attempt)")
        rates["subprocess"] = bench("subprocess gpg", subprocess_check, sample, n_reps=1)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("[2] SKIPPED — gpg not found")

    if len(rates) >= 2:
        print()
        speedup = rates["in-memory"] / rates["subprocess"]
        print(f"  => In-memory is {speedup:.1f}x faster than subprocess gpg")

    print()
    print("  Estimated time to search entire space:")
    for name, rate in rates.items():
        for maxl, space in [(4, 475_254), (5, 12_356_630), (6, 321_272_406)]:
            import multiprocessing
            cores = multiprocessing.cpu_count()
            secs  = space / (rate * cores)
            print(f"    {name} / {cores} cores / max-len={maxl}: "
                  f"{space:>12,} pw  → {secs/60:.0f} min  ({secs/3600:.1f} h)")
    print("=" * 70)


if __name__ == "__main__":
    main()

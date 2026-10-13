#!/usr/bin/env python3
"""
GPG Brute-Force Password Cracker — In-Memory Edition
======================================================
Instead of spawning a `gpg` subprocess per attempt (expensive), this program:

  1. Parses the GPG packet once to extract cipher/S2K parameters.
  2. Re-implements OpenPGP S2K key derivation in Python (hashlib = C speed).
  3. Decrypts only the first (block_size + 2) ciphertext bytes per attempt
     and applies the OpenPGP "quick check" (2-byte repeat) to confirm.
  4. Falls back to a full `gpg --decrypt` call only for final confirmation.
  5. Parallelises across all CPU cores with `multiprocessing`.

Performance vs subprocess approach
-----------------------------------
  subprocess gpg : ~0.5–2 s per attempt (fork + exec + gpg S2K + disk I/O)
  in-memory      : ~0.05–0.2 s per attempt (S2K is the only bottleneck,
                   no fork, no exec, only 2 cipher blocks decrypted)

Usage
-----
    python3 cracker.py [--file PATH] [--max-len N] [--prefix-len N] [--workers N]

Defaults
--------
    --file       archive.gpg
    --max-len    6
    --prefix-len 2   → 676 tasks balanced across workers
    --workers    CPU count
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import multiprocessing
import string
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend as _backend
    _CRYPTO = True
except ImportError:
    _CRYPTO = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ALPHABET = string.ascii_lowercase

# OpenPGP cipher algo ID → (name, block_size, key_size)
CIPHER_INFO: dict[int, tuple[str, int, int]] = {
    2:  ("3DES",   8,  24),
    3:  ("CAST5",  8,  16),
    7:  ("AES",   16,  16),
    8:  ("AES",   16,  24),
    9:  ("AES",   16,  32),
    10: ("Twofish",16, 32),
}

# OpenPGP hash algo ID → hashlib name
HASH_INFO: dict[int, str] = {
    1:  "md5",
    2:  "sha1",
    3:  "ripemd160",
    8:  "sha256",
    9:  "sha384",
    10: "sha512",
    11: "sha224",
}


# ---------------------------------------------------------------------------
# GPG packet parser
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class GPGParams:
    cipher_algo: int
    s2k_type: int
    hash_algo: int
    salt: bytes
    count: int
    ct_prefix: bytes   # first (block_size + 2) bytes from SEIPD / SED body


def _read_one_packet(data: bytes, off: int) -> tuple[int, bytes, int]:
    """Return (tag, body, next_offset) for the packet starting at *off*."""
    ctb = data[off]; off += 1

    if ctb & 0x40:                        # new-format packet
        tag = ctb & 0x3f
        fl = data[off]; off += 1
        if fl < 192:
            length = fl
        elif fl < 224:
            length = ((fl - 192) << 8) + data[off] + 192; off += 1
        elif fl == 255:
            length = struct.unpack_from(">I", data, off)[0]; off += 4
        else:                             # partial body — accumulate
            parts: list[bytes] = []
            plen = 1 << (fl & 0x1f)
            parts.append(data[off:off + plen]); off += plen
            while True:
                nb = data[off]; off += 1
                if nb < 192:
                    parts.append(data[off:off + nb]); off += nb; break
                elif nb < 224:
                    nb2 = data[off]; off += 1
                    ln = ((nb - 192) << 8) + nb2 + 192
                    parts.append(data[off:off + ln]); off += ln; break
                elif nb == 255:
                    ln = struct.unpack_from(">I", data, off)[0]; off += 4
                    parts.append(data[off:off + ln]); off += ln; break
                else:
                    plen2 = 1 << (nb & 0x1f)
                    parts.append(data[off:off + plen2]); off += plen2
            return tag, b"".join(parts), off
    else:                                 # old-format packet
        tag = (ctb & 0x3c) >> 2
        lt = ctb & 0x03
        if lt == 0:
            length = data[off]; off += 1
        elif lt == 1:
            length = struct.unpack_from(">H", data, off)[0]; off += 2
        elif lt == 2:
            length = struct.unpack_from(">I", data, off)[0]; off += 4
        else:
            length = len(data) - off

    return tag, data[off:off + length], off + length


def parse_gpg_file(path: str) -> GPGParams:
    """
    Read a symmetric GPG file and extract everything needed for in-memory
    brute-force: S2K parameters + first encrypted block(s) for quick-check.
    """
    with open(path, "rb") as f:
        raw = f.read()

    cipher_algo = s2k_type = hash_algo = None
    salt = b""; count = 0
    ct_prefix: bytes | None = None

    off = 0
    while off < len(raw):
        tag, body, off = _read_one_packet(raw, off)

        if tag == 3:                      # Symmetric-Key Encrypted Session Key
            i = 1                        # skip version byte
            cipher_algo = body[i]; i += 1
            s2k_type    = body[i]; i += 1
            hash_algo   = body[i]; i += 1
            if s2k_type in (1, 3):
                salt = body[i:i + 8]; i += 8
            if s2k_type == 3:
                c = body[i]; i += 1
                count = (16 + (c & 15)) << ((c >> 4) + 6)
            # If body has more bytes after S2K, it's an encrypted session key.
            # For simplicity we only support the no-ESK case (most common with
            # `gpg --symmetric`). The derived key IS the session key.
            if i < len(body):
                raise NotImplementedError(
                    "This file uses an Encrypted Session Key (ESK) — "
                    "not yet supported by the in-memory path. "
                    "Use --subprocess mode or upgrade the tool."
                )

        elif tag in (9, 18):              # Encrypted Data (SEIPD or SED)
            start = 1 if tag == 18 else 0  # SEIPD has a 1-byte version prefix
            bs = CIPHER_INFO.get(cipher_algo, (None, 16, None))[1]
            ct_prefix = body[start:start + bs + 2]
            break

    if cipher_algo is None or ct_prefix is None:
        raise ValueError(
            f"Could not parse symmetric GPG parameters from '{path}'. "
            "Is it a symmetric-encrypted file?"
        )

    return GPGParams(cipher_algo, s2k_type, hash_algo, salt, count, ct_prefix)


# ---------------------------------------------------------------------------
# S2K key derivation  (RFC 4880 §3.7)
# ---------------------------------------------------------------------------
def _derive_key(pw: str, params: GPGParams, key_size: int) -> bytes:
    """Derive a symmetric key from *pw* using OpenPGP S2K."""
    hash_name = HASH_INFO[params.hash_algo]
    pw_b = pw.encode()
    key = b""
    ctx = 0
    while len(key) < key_size:
        h = hashlib.new(hash_name)
        prefix = b"\x00" * ctx
        if params.s2k_type == 0:          # Simple
            h.update(prefix + pw_b)
        elif params.s2k_type == 1:        # Salted
            h.update(prefix + params.salt + pw_b)
        elif params.s2k_type == 3:        # Iterated-and-Salted
            h.update(prefix)
            raw = params.salt + pw_b
            n = max(params.count, len(raw))
            reps = n // len(raw) + 2
            h.update((raw * reps)[:n])
        key += h.digest()
        ctx += 1
    return key[:key_size]


# ---------------------------------------------------------------------------
# Cipher helpers
# ---------------------------------------------------------------------------
def _ecb_encrypt_block(cipher_algo: int, key: bytes, block: bytes) -> bytes:
    """Encrypt a single block with the given cipher in ECB mode."""
    if not _CRYPTO:
        raise RuntimeError("Install the 'cryptography' package: pip install cryptography")
    name = CIPHER_INFO[cipher_algo][0]
    if name == "AES":
        algo = algorithms.AES(key)
    elif name == "CAST5":
        algo = algorithms.CAST5(key)
    elif name == "3DES":
        algo = algorithms.TripleDES(key)
    else:
        raise ValueError(f"Unsupported cipher: {name}")
    enc = Cipher(algo, modes.ECB(), backend=_backend()).encryptor()
    return enc.update(block) + enc.finalize()


# ---------------------------------------------------------------------------
# Quick-check  (OpenPGP CFB prefix verification, RFC 4880 §5.13)
# ---------------------------------------------------------------------------
def _quick_check(pw: str, params: GPGParams) -> bool:
    """
    Derive the key for *pw*, decrypt the first (bs + 2) ciphertext bytes
    using OpenPGP CFB and verify the 2-byte repeat.

    This avoids decrypting the full archive and needs no subprocess.
    """
    try:
        _, bs, key_size = CIPHER_INFO[params.cipher_algo]
        key = _derive_key(pw, params, key_size)
        ct = params.ct_prefix

        # FRE₁ = E(key, 0ˢ)
        fre1 = _ecb_encrypt_block(params.cipher_algo, key, b"\x00" * bs)
        # plaintext prefix[0:bs] = FRE₁ ⊕ ct[0:bs]
        pt = bytes(a ^ b for a, b in zip(fre1, ct[:bs]))
        # FRE₂ = E(key, ct[0:bs])
        fre2 = _ecb_encrypt_block(params.cipher_algo, key, ct[:bs])
        # check[0:2] = FRE₂[0:2] ⊕ ct[bs:bs+2]
        check = bytes(a ^ b for a, b in zip(fre2, ct[bs:bs + 2]))

        return pt[-2] == check[0] and pt[-1] == check[1]
    except Exception:
        return False


def _gpg_verify(pw: str, path: str) -> bool:
    """Full verification via gpg subprocess (used only for the final candidate)."""
    try:
        r = subprocess.run(
            ["gpg", "--batch", "--yes", "--passphrase-fd", "0",
             "--decrypt", "--output", "/dev/null", path],
            input=pw.encode(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        return r.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Worker process
# ---------------------------------------------------------------------------
_params: GPGParams | None = None
_stop: multiprocessing.Event | None = None
_gpg_path: str | None = None
_use_quick: bool = True


def _init(params: GPGParams, stop: multiprocessing.Event,
          gpg_path: str, use_quick: bool) -> None:
    global _params, _stop, _gpg_path, _use_quick
    _params = params
    _stop = stop
    _gpg_path = gpg_path
    _use_quick = use_quick


def worker_task(args_tuple: tuple) -> Optional[str]:
    """
    Test all lowercase passwords starting with *prefix*, length in
    [len(prefix), max_length].  Returns the matching password or None.
    """
    prefix, max_length = args_tuple
    prefix_len = len(prefix)

    for length in range(prefix_len, max_length + 1):
        remaining = length - prefix_len
        for suffix in itertools.product(ALPHABET, repeat=remaining):
            if _stop.is_set():
                return None

            candidate = prefix + "".join(suffix)

            if _use_quick:
                # Quick-check has ~1/65536 false-positive rate.
                # Confirm with gpg before declaring victory and stopping all workers.
                if _quick_check(candidate, _params) and _gpg_verify(candidate, _gpg_path):
                    _stop.set()
                    return candidate
            else:
                if _gpg_verify(candidate, _gpg_path):
                    _stop.set()
                    return candidate

    return None


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------
def _build_prefixes(n: int) -> list[str]:
    return ["".join(t) for t in itertools.product(ALPHABET, repeat=n)]


def _space_str(max_len: int) -> str:
    total = sum(26**l for l in range(1, max_len + 1))
    s = f"{total:,}"
    if total >= 1_000_000:
        s += f"  (~{total/1_000_000:.1f}M)"
    return s


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Brute-force a symmetric GPG passphrase (lowercase only)."
    )
    p.add_argument("--file", default="archive.gpg", metavar="PATH")
    p.add_argument("--max-len", type=int, default=6, metavar="N",
                   help="Maximum passphrase length  [6]")
    p.add_argument("--prefix-len", type=int, default=2, metavar="N",
                   help="Prefix length for work partitioning  [2 → 676 tasks]")
    p.add_argument("--workers", type=int, default=None, metavar="N",
                   help="Worker processes  [CPU count]")
    p.add_argument("--subprocess", action="store_true",
                   help="Use gpg subprocess per attempt instead of in-memory check")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    args = parse_args()
    use_quick = not args.subprocess

    if use_quick and not _CRYPTO:
        print("[!] 'cryptography' package not found. Falling back to subprocess mode.")
        print("    Install with: pip install cryptography")
        use_quick = False

    # Parse GPG file once
    try:
        params = parse_gpg_file(args.file)
    except NotImplementedError as e:
        print(f"[!] {e}")
        print("    Switching to subprocess mode.")
        use_quick = False
        params = None  # not needed in subprocess mode
    except Exception as e:
        print(f"[!] Could not parse '{args.file}': {e}")
        sys.exit(1)

    n_workers = args.workers or multiprocessing.cpu_count()
    prefixes  = _build_prefixes(args.prefix_len)
    tasks     = [(p, args.max_len) for p in prefixes]
    mode_str  = "in-memory quick-check" if use_quick else "subprocess gpg"

    print("=" * 60)
    print("  GPG Brute-Force Cracker")
    print("=" * 60)
    print(f"  File        : {args.file}")
    print(f"  Mode        : {mode_str}")
    print(f"  Max length  : {args.max_len}")
    print(f"  Prefix len  : {args.prefix_len}  ({len(prefixes)} tasks)")
    print(f"  Workers     : {n_workers}")
    print(f"  Search space: {_space_str(args.max_len)} passwords")
    if use_quick and params:
        c_name = {"AES": "AES", "CAST5": "CAST5", "3DES": "3DES"}.get(
            CIPHER_INFO[params.cipher_algo][0], "?"
        )
        print(f"  Cipher      : {c_name}-{CIPHER_INFO[params.cipher_algo][2]*8}")
        print(f"  S2K hash    : {HASH_INFO[params.hash_algo].upper()}")
        print(f"  S2K count   : {params.count:,}")
    print("=" * 60)
    print()

    stop  = multiprocessing.Event()
    found: Optional[str] = None
    start = time.perf_counter()

    with multiprocessing.Pool(
        processes=n_workers,
        initializer=_init,
        initargs=(params, stop, args.file, use_quick),
    ) as pool:
        try:
            for result in pool.imap_unordered(worker_task, tasks, chunksize=1):
                if result is not None:
                    found = result
                    pool.terminate()
                    break
        except KeyboardInterrupt:
            pool.terminate()
            print("\n[!] Interrupted by user.")
            sys.exit(1)

    elapsed = time.perf_counter() - start

    print()
    if found:
        print(f"[+] KEY FOUND (CONFIRMED): '{found}'")
    else:
        print("[-] Key NOT found in the specified search space.")

    print(f"[*] Time elapsed: {elapsed:.2f} s")
    print()
    sys.exit(0 if found else 1)


if __name__ == "__main__":
    main()

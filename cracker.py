#!/usr/bin/env python3
"""
GPG Brute-Force Password Cracker
=================================
Searches for a symmetric GPG passphrase that consists solely of lowercase
ASCII letters ('a'-'z'), up to a configurable maximum length.

Strategy
--------
* Work is partitioned by 2-character prefixes (26^2 = 676 independent tasks),
  giving fine-grained load balancing across any number of CPU cores.
* Each worker calls `gpg --decrypt` in a subprocess (zero-copy: GPG reads
  the file from disk itself; only the passphrase crosses the process boundary).
* A multiprocessing.Event flag lets every worker stop as soon as one of
  them finds the correct passphrase (early termination).
* The pool uses imap_unordered so the main process reacts the moment any
  worker returns a positive result, without waiting for slower workers.

Usage
-----
    python3 cracker.py [--file PATH] [--max-len N] [--prefix-len N] [--workers N]

Defaults
--------
    --file       archive.gpg
    --max-len    6
    --prefix-len 2  (676 tasks spread across the pool)
    --workers    number of logical CPUs
"""

import argparse
import itertools
import multiprocessing
import string
import subprocess
import sys
import time
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ALPHABET: str = string.ascii_lowercase  # 'a'-'z'

GPG_DECRYPT_CMD: list[str] = [
    "gpg",
    "--batch",
    "--yes",
    "--passphrase-fd", "0",   # passphrase via stdin
    "--decrypt",
    "--output", "/dev/null",  # discard plaintext
]

# ---------------------------------------------------------------------------
# Module-level globals populated once per worker via pool initializer.
# This avoids serialising large state through pickle for every single task.
# ---------------------------------------------------------------------------
_stop_event: Optional[multiprocessing.Event] = None
_gpg_file_path: Optional[str] = None


def _pool_initializer(stop_event: multiprocessing.Event, gpg_file_path: str) -> None:
    """Called once in each worker process to set up shared globals."""
    global _stop_event, _gpg_file_path
    _stop_event = stop_event
    _gpg_file_path = gpg_file_path


# ---------------------------------------------------------------------------
# Core verification
# ---------------------------------------------------------------------------
def _try_password(password: str) -> bool:
    """Return True iff *password* successfully decrypts the GPG archive."""
    try:
        result = subprocess.run(
            GPG_DECRYPT_CMD + [_gpg_file_path],
            input=password.encode(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


# ---------------------------------------------------------------------------
# Worker task
# ---------------------------------------------------------------------------
def worker_task(args_tuple: tuple) -> Optional[str]:
    """
    Test every lowercase-only password that starts with *prefix* and has
    total length in [len(prefix), max_length].  Returns the matching password
    string on success, or None if not found in this partition.
    """
    prefix, max_length = args_tuple

    if _stop_event is None:
        return None

    prefix_len = len(prefix)

    for length in range(prefix_len, max_length + 1):
        remaining = length - prefix_len
        for suffix_tuple in itertools.product(ALPHABET, repeat=remaining):
            if _stop_event.is_set():
                return None  # Another worker already found the key

            candidate = prefix + "".join(suffix_tuple)
            if _try_password(candidate):
                _stop_event.set()  # Signal all other workers to stop
                return candidate

    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _build_prefixes(prefix_len: int) -> list[str]:
    return ["".join(t) for t in itertools.product(ALPHABET, repeat=prefix_len)]


def _search_space_str(max_len: int) -> str:
    total = sum(26**l for l in range(1, max_len + 1))
    suffix = f" (~{total / 1_000_000:.1f}M)" if total >= 1_000_000 else ""
    return f"{total:,}{suffix}"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Brute-force a symmetric GPG passphrase (lowercase letters only)."
    )
    p.add_argument("--file", default="archive.gpg", metavar="PATH",
                   help="Path to the encrypted .gpg file  [archive.gpg]")
    p.add_argument("--max-len", type=int, default=6, metavar="N",
                   help="Maximum passphrase length to try  [6]")
    p.add_argument("--prefix-len", type=int, default=2, metavar="N",
                   help="Prefix length for work partitioning  [2 → 676 tasks]")
    p.add_argument("--workers", type=int, default=None, metavar="N",
                   help="Number of parallel worker processes  [CPU count]")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    args = parse_args()

    n_workers: int = args.workers or multiprocessing.cpu_count()
    prefixes: list[str] = _build_prefixes(args.prefix_len)
    tasks: list[tuple] = [(p, args.max_len) for p in prefixes]

    print("=" * 60)
    print("  GPG Brute-Force Cracker")
    print("=" * 60)
    print(f"  File        : {args.file}")
    print(f"  Max length  : {args.max_len}")
    print(f"  Prefix len  : {args.prefix_len}  ({len(prefixes)} tasks)")
    print(f"  Workers     : {n_workers}")
    print(f"  Search space: {_search_space_str(args.max_len)} passwords")
    print("=" * 60)
    print()

    stop_event = multiprocessing.Event()
    found_key: Optional[str] = None
    start = time.perf_counter()

    with multiprocessing.Pool(
        processes=n_workers,
        initializer=_pool_initializer,
        initargs=(stop_event, args.file),
    ) as pool:
        try:
            for result in pool.imap_unordered(worker_task, tasks, chunksize=1):
                if result is not None:
                    found_key = result
                    pool.terminate()
                    break
        except KeyboardInterrupt:
            pool.terminate()
            print("\n[!] Interrupted by user.")
            sys.exit(1)

    elapsed = time.perf_counter() - start

    print()
    if found_key:
        print(f"[+] KEY FOUND   : '{found_key}'")
    else:
        print("[-] Key NOT found in the specified search space.")
    print(f"[*] Time elapsed: {elapsed:.2f} s")
    print()

    sys.exit(0 if found_key else 1)


if __name__ == "__main__":
    main()

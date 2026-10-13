# ─────────────────────────────────────────────────────────────────────────────
#  GPG Brute-Force Cracker — Docker image
#  Base: debian:bookworm-slim
#
#  Contains:
#    - python3 + cryptography  → cracker.py (in-memory, fast)
#    - john the ripper         → john/gpg2john (C-speed, for experiments)
# ─────────────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

LABEL description="GPG symmetric passphrase brute-force cracker"

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gnupg \
        python3 \
        python3-pip \
        python3-cryptography \
        john \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ─────────────────────────────────────────────────────────
WORKDIR /app

# ── Copy source + encrypted archive ──────────────────────────────────────────
COPY cracker.py   ./cracker.py
COPY archive.gpg  ./archive.gpg

# ── Default command: Python in-memory cracker ─────────────────────────────────
#   Override at runtime, e.g.:
#     docker run --rm gpg-cracker --max-len 5 --workers 8
#     docker run --rm --entrypoint john gpg-cracker --format=gpg --wordlist=/usr/share/john/password.lst /tmp/hash.txt
ENTRYPOINT ["python3", "cracker.py"]
CMD ["--file", "archive.gpg", "--max-len", "6", "--prefix-len", "2"]

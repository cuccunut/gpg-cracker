# ─────────────────────────────────────────────────────────────────────────────
#  GPG Brute-Force Cracker — Docker image
#  Base: debian:bookworm-slim  (small, glibc-based, ships with gpg)
# ─────────────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

LABEL maintainer="andrea"
LABEL description="GPG symmetric passphrase brute-force cracker"

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gnupg \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ─────────────────────────────────────────────────────────
WORKDIR /app

# ── Copy source + encrypted archive ──────────────────────────────────────────
COPY cracker.py   ./cracker.py
COPY archive.gpg  ./archive.gpg

# ── Default command ───────────────────────────────────────────────────────────
#   All CLI flags can be overridden at `docker run` time, e.g.:
#     docker run --rm gpg-cracker --max-len 7 --workers 8
ENTRYPOINT ["python3", "cracker.py"]
CMD ["--file", "archive.gpg", "--max-len", "6", "--prefix-len", "2"]

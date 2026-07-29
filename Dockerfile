# Decko v2.0 — Dockerfile
# Used for the mini sandbox (dynamic analysis) — NOT for the desktop GUI.
# The GUI runs natively on Windows/Linux with PyQt6.

FROM python:3.11-slim

# Security: run as non-root
RUN useradd -m -u 1000 sandbox
WORKDIR /sandbox

# Install system tools for analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    file \
    strings \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# Copy only what the sandbox needs
COPY requirements.txt .
RUN pip install --no-cache-dir requests psutil PyYAML

# Drop privileges
USER sandbox

# Default: run the headless check script
# Override CMD when doing dynamic analysis
CMD ["python", "-c", "print('Decko Sandbox Ready')"]

# ── Usage Notes ─────────────────────────────────────────────────────────────
# Build:   docker build -t decko-sandbox .
# Run:     docker run --rm --network none -v /path/to/sample:/sandbox/sample \
#                     decko-sandbox python analyze.py /sandbox/sample/file.exe
#
# --network none  →  Air-gapped: zero outbound connections possible
# --rm            →  Container deleted after run (no persistence)

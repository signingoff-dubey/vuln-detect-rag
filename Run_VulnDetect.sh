#!/usr/bin/env bash
# VulnDetectRAG v4.5 launcher (Linux / macOS)
#
# Starts the FastAPI backend on 127.0.0.1:8000 and the Vite dev server on
# :5173. Vite proxies /api to the backend, so the browser only ever talks to
# 5173 and no CORS configuration is required for local use.

set -uo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"

BACKEND_HOST="127.0.0.1"
BACKEND_PORT="8000"
FRONTEND_PORT="5173"
VENV_PY="${ROOT}/backend/venv/bin/python"

echo "==================================================="
echo "   VulnDetectRAG v4.5 - Vulnerability Intelligence Platform"
echo
echo "   Network      : Nmap, Nuclei, OpenVAS"
echo "   Web          : OWASP ZAP, Nikto, testssl/sslyze, WhatWeb"
echo "   Supply chain : Trivy, OSV-Scanner, Grype"
echo "   Commercial   : Burp (licence), Nessus (simulated)"
echo
echo "   AI: Groq / Gemini / OpenRouter / NVIDIA, Ollama offline"
echo "==================================================="
echo

# ---------------------------------------------------------------
# 1. Prerequisites
# ---------------------------------------------------------------
need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "[ERROR] $1 is required but not installed."
        echo "        $2"
        exit 1
    }
}
need python3 "Install Python 3.10+ from https://www.python.org/downloads/"
need npm     "Install Node.js 20.19+ from https://nodejs.org/"

echo "[*] Checking optional scanners (missing ones are simply unavailable)..."
for tool in nmap nuclei nikto whatweb trivy osv-scanner grype sslyze testssl.sh zap.sh; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "    [OK] $tool"
    else
        echo "    [--] $tool not found"
    fi
done

# ---------------------------------------------------------------
# 2. AI provider configuration
# ---------------------------------------------------------------
echo
if [ -f backend/.env ]; then
    echo "    [OK] backend/.env present"
else
    echo "[WARNING] backend/.env not found."
    echo "          Copy backend/.env.example to backend/.env and add at least"
    echo "          one free API key, or install Ollama to run fully offline."
fi

if command -v ollama >/dev/null 2>&1; then
    echo "    [OK] Ollama installed (offline fallback available)"
else
    echo "    [--] Ollama not installed (cloud providers will be used)"
fi

cat <<'PRIVACY'

[PRIVACY] Cloud providers are enabled by default and receive your scan
          findings and questions. To keep everything on this machine, set
          LLM_PROVIDER=ollama in backend/.env, or disable each cloud provider
          from the Settings page in the UI.

PRIVACY

# ---------------------------------------------------------------
# 3. Sanity-check the layout
# ---------------------------------------------------------------
for dir in backend frontend; do
    [ -d "$dir" ] || { echo "[ERROR] $dir/ not found. Run this from the project root."; exit 1; }
done

# ---------------------------------------------------------------
# 4. Backend dependencies
# ---------------------------------------------------------------
echo "[1/4] Preparing FastAPI backend..."
# A venv directory can exist yet be unusable: if the system Python was upgraded
# or moved, the venv's interpreter still points at the old install and every
# command fails. Existence is not a good enough test - it has to actually run.
if ! "$VENV_PY" -c "import sys" >/dev/null 2>&1; then
    if [ -d backend/venv ]; then
        echo "[WARNING] Existing virtual environment is broken, rebuilding it..."
        rm -rf backend/venv
    else
        echo "[*] Creating Python virtual environment..."
    fi
    python3 -m venv backend/venv || { echo "[ERROR] venv creation failed."; exit 1; }
fi

# Even with nothing to do, "pip install -q" still re-resolves every pinned
# version on every launch, which is seconds wasted on every single start.
# Skipped once a hash of requirements.txt matches what was last installed
# into this venv; living inside backend/venv ties the stamp's lifetime to
# the venv's, so a rebuilt venv (above) always reinstalls.
REQ_STAMP="backend/venv/.requirements.sha256"
REQ_HASH="$(sha256sum requirements.txt 2>/dev/null | cut -d' ' -f1)"
if [ -n "$REQ_HASH" ] && [ "$(cat "$REQ_STAMP" 2>/dev/null)" = "$REQ_HASH" ]; then
    echo "[*] Python dependencies already up to date, skipping install."
else
    echo "[*] Installing Python dependencies..."
    # requirements.txt lives at the repository root, not in backend/.
    "$VENV_PY" -m pip install -r requirements.txt -q || {
        echo "[ERROR] Dependency installation failed."
        exit 1
    }
    [ -n "$REQ_HASH" ] && echo "$REQ_HASH" > "$REQ_STAMP"
fi

# ---------------------------------------------------------------
# 5. Seed the knowledge base BEFORE the backend starts
# ---------------------------------------------------------------
# Ordering matters: the assistant reports an empty corpus if it starts against
# an unseeded store. Seeding upserts, so running it every launch is safe.
echo "[2/4] Seeding the CVE knowledge base (idempotent)..."
if [ -f scripts/seed_cve_data.py ]; then
    "$VENV_PY" scripts/seed_cve_data.py || \
        echo "[WARNING] Seeding failed; the assistant will have no corpus to retrieve from."
else
    echo "[INFO] scripts/seed_cve_data.py not found, skipping."
fi

# ---------------------------------------------------------------
# 6. Start services
# ---------------------------------------------------------------
PIDS=()
cleanup() {
    echo
    echo "[*] Shutting down..."
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    exit 0
}
# Ctrl+C stops both services rather than orphaning the backend.
trap cleanup INT TERM

echo "[3/4] Starting backend on http://${BACKEND_HOST}:${BACKEND_PORT} ..."
# Started from backend/ because main.py resolves "main:app" relative to it.
( cd backend && exec "$VENV_PY" main.py ) &
PIDS+=($!)

echo "[4/4] Starting frontend on http://localhost:${FRONTEND_PORT} ..."
if [ ! -d frontend/node_modules ]; then
    echo "[*] Installing NPM dependencies (first run only)..."
    ( cd frontend && npm install )
fi
( cd frontend && exec npm run dev ) &
PIDS+=($!)

# ---------------------------------------------------------------
# 7. Open the UI
# ---------------------------------------------------------------
# Poll instead of a flat 10s sleep: the backend is usually ready in 1-3s
# once dependencies are already installed, and the browser should open the
# moment it actually can, not after a fixed wait sized for the slowest case.
# Still capped, so a genuinely slow machine does not hang here.
echo "[*] Waiting for the backend to become ready..."
if command -v curl >/dev/null 2>&1; then
    for _ in $(seq 1 30); do
        if curl -fsS "http://${BACKEND_HOST}:${BACKEND_PORT}/api/health" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
else
    sleep 10
fi
URL="http://localhost:${FRONTEND_PORT}"
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$URL" >/dev/null 2>&1 &
elif command -v open >/dev/null 2>&1; then
    open "$URL" >/dev/null 2>&1 &
else
    echo "[INFO] Open $URL in your browser."
fi

cat <<EOF

===================================================
   VulnDetectRAG v4.5 is running.

   Frontend : http://localhost:${FRONTEND_PORT}
   Backend  : http://${BACKEND_HOST}:${BACKEND_PORT}
   API docs : http://${BACKEND_HOST}:${BACKEND_PORT}/docs
   Health   : http://${BACKEND_HOST}:${BACKEND_PORT}/api/health

   Press Ctrl+C to stop both services.
===================================================
EOF

# Wait on the service processes so Ctrl+C reaches the trap.
wait

@echo off
setlocal enabledelayedexpansion
title VulnDetectRAG v4.5 Startup
color 0b

:: Always operate from the repository root, whatever directory the user
:: launched this from.
cd /d "%~dp0"

set "BACKEND_HOST=127.0.0.1"
set "BACKEND_PORT=8000"
set "FRONTEND_PORT=5173"
set "VENV_PY=%~dp0backend\venv\Scripts\python.exe"

echo ===================================================
echo    VulnDetectRAG v4.5 - Vulnerability Intelligence Platform
echo.
echo    Network      : Nmap, Nuclei, OpenVAS
echo    Web          : OWASP ZAP, Nikto, testssl/sslyze, WhatWeb
echo    Supply chain : Trivy, OSV-Scanner, Grype
echo    Commercial   : Burp (licence), Nessus (simulated)
echo.
echo    AI: Groq / Gemini / OpenRouter / NVIDIA, Ollama offline
echo ===================================================
echo.

:: ---------------------------------------------------------------
:: 1. Prerequisites
:: ---------------------------------------------------------------
echo [*] Checking for Python...
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python is not installed or not in PATH. Please install Python 3.10+
    echo         Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [*] Checking for Node.js (npm)...
where npm >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Node.js is not installed or not in PATH. Please install Node.js 20.19+
    echo         Download from: https://nodejs.org/
    pause
    exit /b 1
)

:: Scanners are all optional. A missing tool reports that it did not run;
:: it never fabricates findings.
echo.
echo [*] Checking optional scanners (missing ones are simply unavailable)...
for %%T in (nmap nuclei nikto whatweb trivy osv-scanner grype sslyze) do (
    where %%T >nul 2>nul
    if !ERRORLEVEL! neq 0 (
        echo     [--] %%T not found
    ) else (
        echo     [OK] %%T
    )
)

:: ---------------------------------------------------------------
:: 2. AI provider configuration
:: ---------------------------------------------------------------
echo.
echo [*] Checking AI provider configuration...
if not exist "backend\.env" (
    echo [WARNING] backend\.env not found.
    echo           Copy backend\.env.example to backend\.env and add at least
    echo           one free API key, or install Ollama to run fully offline.
) else (
    echo     [OK] backend\.env present
)

:: Ollama is the offline fallback, not the default. It is only pulled when
:: it is actually installed - this must never block startup.
where ollama >nul 2>nul
if !ERRORLEVEL! neq 0 (
    echo     [--] Ollama not installed ^(cloud providers will be used^)
) else (
    echo     [OK] Ollama installed ^(offline fallback available^)
)

echo.
echo [PRIVACY] Cloud providers are enabled by default and receive your scan
echo           findings and questions. To keep everything on this machine,
echo           set LLM_PROVIDER=ollama in backend\.env, or disable each cloud
echo           provider from the Settings page in the UI.
echo.

:: ---------------------------------------------------------------
:: 3. Sanity-check the layout
:: ---------------------------------------------------------------
if not exist "backend\" (
    echo [ERROR] backend\ directory not found. Run this from the project root.
    pause
    exit /b 1
)
if not exist "frontend\" (
    echo [ERROR] frontend\ directory not found. Run this from the project root.
    pause
    exit /b 1
)

:: ---------------------------------------------------------------
:: 4. Backend
:: ---------------------------------------------------------------
echo [1/4] Preparing FastAPI backend...

:: A venv directory can exist yet be unusable - if the machine's Python was
:: upgraded or moved, the venv's python.exe still points at the old install and
:: every command fails with "did not find executable". Existence is therefore
:: not a good enough test; the interpreter has to actually run.
set "VENV_OK="
if exist "%VENV_PY%" (
    "%VENV_PY%" -c "import sys" >nul 2>nul
    if !ERRORLEVEL! equ 0 set "VENV_OK=1"
)

if not defined VENV_OK (
    if exist "backend\venv\" (
        echo [WARNING] Existing virtual environment is broken, rebuilding it...
        rmdir /s /q "backend\venv"
    ) else (
        echo [*] Creating Python virtual environment...
    )
    python -m venv backend\venv
    if !ERRORLEVEL! neq 0 (
        echo [ERROR] Failed to create the virtual environment.
        pause
        exit /b 1
    )
)

:: Even with nothing to do, "pip install -q" still re-resolves every pinned
:: version on every launch, which is seconds wasted on every single start.
:: Skipped once a hash of requirements.txt matches what was last installed
:: into this venv; living inside backend\venv ties the stamp's lifetime to
:: the venv's, so a rebuilt venv (above) always reinstalls.
set "REQ_STAMP=backend\venv\.requirements.sha256"
set "REQ_HASH="
for /f "usebackq delims=" %%H in (`powershell -NoProfile -Command "(Get-FileHash requirements.txt -Algorithm SHA256).Hash" 2^>nul`) do set "REQ_HASH=%%H"
set "REQ_MATCH="
if defined REQ_HASH if exist "%REQ_STAMP%" (
    set /p REQ_PREV=<"%REQ_STAMP%"
    if "!REQ_PREV!"=="!REQ_HASH!" set "REQ_MATCH=1"
)

if defined REQ_MATCH (
    echo [*] Python dependencies already up to date, skipping install.
) else (
    echo [*] Installing Python dependencies...
    :: requirements.txt lives at the repository root, not in backend\.
    "%VENV_PY%" -m pip install -r requirements.txt -q
    if !ERRORLEVEL! neq 0 (
        echo [ERROR] Dependency installation failed. See the messages above.
        pause
        exit /b 1
    )
    if defined REQ_HASH (>"%REQ_STAMP%" echo !REQ_HASH!)
)

:: ---------------------------------------------------------------
:: 4b. Scanner tools: install whatever is missing, once, then put them on PATH
:: ---------------------------------------------------------------
echo [*] Checking scanner tools ^(installs anything missing, skips what is present^)...
powershell -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0scripts\install_tools.ps1"
set "PATH=%~dp0toolsin;%PATH%"

:: ---------------------------------------------------------------
:: 5. Seed the knowledge base BEFORE the backend starts
:: ---------------------------------------------------------------
:: Ordering matters: the RAG assistant reports an empty corpus if it starts
:: against an unseeded store, and seeding is idempotent (upsert), so running
:: it every launch is safe.
echo [2/4] Seeding the CVE knowledge base ^(idempotent^)...
if exist "scripts\seed_cve_data.py" (
    "%VENV_PY%" scripts\seed_cve_data.py
    if !ERRORLEVEL! neq 0 (
        echo [WARNING] Seeding failed. The app will still start, but the
        echo           assistant will have no CVE corpus to retrieve from.
    )
) else (
    echo [INFO] scripts\seed_cve_data.py not found, skipping.
)

echo [3/4] Starting backend on http://%BACKEND_HOST%:%BACKEND_PORT% ...
:: Bound to 127.0.0.1 by main.py. Started from backend\ because main.py
:: resolves "main:app" relative to its own directory.
start "VulnDetectRAG Backend (Do not close)" cmd /k "cd /d "%~dp0backend" && "%VENV_PY%" main.py"

:: ---------------------------------------------------------------
:: 6. Frontend
:: ---------------------------------------------------------------
echo [4/4] Starting frontend on http://localhost:%FRONTEND_PORT% ...
if not exist "frontend\node_modules\" (
    echo [*] Installing NPM dependencies ^(first run only^)...
    pushd frontend
    call npm install
    popd
)
:: Vite proxies /api to the backend, so the browser only ever talks to 5173.
start "VulnDetectRAG Frontend (Do not close)" cmd /k "cd /d "%~dp0frontend" && npm run dev"

:: ---------------------------------------------------------------
:: 7. Open the UI
:: ---------------------------------------------------------------
echo.
echo [*] Waiting for the backend to become ready...
:: Poll instead of a flat 10s wait: the backend is usually ready in 1-3s once
:: dependencies are already installed, so most launches no longer pay a full
:: 10 second tax here. One PowerShell process does all 30 polls internally
:: rather than being relaunched per attempt, which would cost far more than
:: it saves. Still capped, so a genuinely slow machine does not hang here.
powershell -NoProfile -Command ^
    "$u = 'http://%BACKEND_HOST%:%BACKEND_PORT%/api/health'; for ($i = 0; $i -lt 30; $i++) { try { Invoke-WebRequest -UseBasicParsing -Uri $u -TimeoutSec 2 | Out-Null; exit 0 } catch { Start-Sleep -Seconds 1 } }; exit 1"
start http://localhost:%FRONTEND_PORT%

echo.
echo ===================================================
echo    VulnDetectRAG v4.5 is running.
echo.
echo    Frontend : http://localhost:%FRONTEND_PORT%
echo    Backend  : http://%BACKEND_HOST%:%BACKEND_PORT%
echo    API docs : http://%BACKEND_HOST%:%BACKEND_PORT%/docs
echo    Health   : http://%BACKEND_HOST%:%BACKEND_PORT%/api/health
echo.
echo    Leave both terminal windows open.
echo    To stop: close them, or press Ctrl+C in each.
echo ===================================================
pause

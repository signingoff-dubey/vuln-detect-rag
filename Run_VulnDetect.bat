@echo off
setlocal enabledelayedexpansion
title VulnDetectRAG Startup
color 0b

echo ===================================================
echo    Starting VulnDetectRAG Platform
echo ===================================================
echo.

:: 1. Check Prerequisites
echo [*] Checking for Python...
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Python is not installed or not in PATH. Please install Python 3.10+
)

echo [*] Checking for Node.js (npm)...
where npm >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Node.js is not installed or not in PATH. Please install Node.js 18+
)

echo [*] Checking for Ollama...
where ollama >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Ollama is not installed. AI features will be disabled.
    echo Please install Ollama from https://ollama.com/
    echo.
) else (
    echo [*] Ensuring Ollama model qwen2.5-coder:7b is downloaded...
    echo Note: This may take a while if downloading for the first time.
    call ollama run qwen2.5-coder:7b "/bye" >nul 2>nul
)

echo.
:: 2. Backend Setup
echo [1/3] Starting FastApi Backend...
cd backend
if not exist "venv\" (
    echo [*] Creating Python virtual environment...
    python -m venv venv
)
start "VulnDetectRAG Backend (Do not close)" cmd /k "call venv\Scripts\activate.bat && pip install -r requirements.txt && python main.py"
cd ..

echo.
:: 3. Frontend Setup
echo [2/3] Starting React Frontend...
cd frontend
if not exist "node_modules\" (
    echo [*] Installing NPM dependencies...
    start /wait "Installing Node Modules" cmd /c "npm install"
)
start "VulnDetectRAG Frontend (Do not close)" cmd /k "npm run dev"
cd ..

echo.
:: 4. Launch UI
echo [3/3] Waiting for services to initialize (5 seconds)...
timeout /t 5 /nobreak >nul

echo [*] Opening browser to application...
start http://localhost:5173

echo.
echo ===================================================
echo    Platform is now running!
echo    Please leave the two black terminal windows 
echo    open. To stop the servers, simply close them.
echo ===================================================
pause

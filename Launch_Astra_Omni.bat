@echo off
title ASTRA OMNI // Gemini 2.0 + ChatGPT-6 + Project Astra AI
cls
echo =========================================================================
echo    ASTRA OMNI // GEMINI 2.0 + CHATGPT-6 + PROJECT ASTRA UNIFIED AI
echo    Free, Safe & Cryptographically Secure (AES-GCM Web Crypto Vault)
echo =========================================================================
echo.
echo [*] Starting Local Web Engine on http://localhost:8090 ...
echo [*] Launching application in default browser...
echo.

cd /d "%~dp0\astra_omni_ai"

start "" "http://localhost:8090"
python -m http.server 8090

pause

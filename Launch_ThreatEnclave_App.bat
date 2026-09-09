@echo off
title CYBERSHIELD // Enterprise Security Operations & Threat Enclave
echo ===============================================================================
echo  CYBERSHIELD // UNIDIRECTIONAL THREAT DETECTION ENCLAVE & SOC PLATFORM
echo  Mode: Hardened Enterprise Desktop Application
echo  Architecture: 16-Shard Hash Partitioned Passive Sensor
echo ===============================================================================
echo.
echo Starting Cyber Threat Enclave and spawning native desktop application...
echo.

cd /d "%~dp0"
python app_desktop.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Python returned an error code. Checking environment...
    pause
)

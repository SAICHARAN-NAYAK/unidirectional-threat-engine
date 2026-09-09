@echo off
title Open CYBERSHIELD in Android Studio
echo ===============================================================================
echo  CYBERSHIELD // Opening Android Studio Project
echo  Project Path: %~dp0android_studio_app
echo ===============================================================================
echo.

set STUDIO_EXE=C:\Program Files\Android\Android Studio\bin\studio64.exe

if exist "%STUDIO_EXE%" (
    echo [OK] Found Android Studio at: "%STUDIO_EXE%"
    echo [OK] Launching Android Studio with CYBERSHIELD HTML Project...
    start "" "%STUDIO_EXE%" "%~dp0android_studio_app"
    echo.
    echo Android Studio is starting up.
    echo Select your device or emulator and click 'Run' (Shift+F10).
) else (
    echo [!] Could not locate Android Studio at "%STUDIO_EXE%".
    echo Please open Android Studio manually and select:
    echo "%~dp0android_studio_app"
    pause
)

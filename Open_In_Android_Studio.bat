@echo off
setlocal enabledelayedexpansion
title Open CYBERSHIELD in Android Studio

set "PROJECT_DIR=%~dp0android_studio_app"

echo ===============================================================================
echo  CYBERSHIELD // Opening Android Studio Project
echo  Project Path: %PROJECT_DIR%
echo ===============================================================================
echo.

if not exist "%PROJECT_DIR%" (
    echo [!] Warning: Project folder does not exist:
    echo     "%PROJECT_DIR%"
    echo.
    pause
    exit /b 1
)

:: Check installation paths (Android Studio1 first, then Android Studio, then LocalAppData)
set "STUDIO_EXE="
if exist "C:\Program Files\Android\Android Studio1\bin\studio64.exe" (
    set "STUDIO_EXE=C:\Program Files\Android\Android Studio1\bin\studio64.exe"
) else if exist "C:\Program Files\Android\Android Studio\bin\studio64.exe" (
    set "STUDIO_EXE=C:\Program Files\Android\Android Studio\bin\studio64.exe"
) else if exist "%LOCALAPPDATA%\Programs\Android Studio\bin\studio64.exe" (
    set "STUDIO_EXE=%LOCALAPPDATA%\Programs\Android Studio\bin\studio64.exe"
) else (
    for /f "delims=" %%I in ('dir /b /s "%LOCALAPPDATA%\JetBrains\Toolbox\apps\AndroidStudio\bin\studio64.exe" 2^>nul') do (
        set "STUDIO_EXE=%%I"
    )
)

if defined STUDIO_EXE (
    echo [OK] Located Android Studio: "!STUDIO_EXE!"
    echo [OK] Spawning Android Studio IDE...
    echo.
    echo Launching Android Studio. Please wait 10-15 seconds for the splash screen...
    start "" "!STUDIO_EXE!" "%PROJECT_DIR%"
    echo.
    echo [SUCCESS] Android Studio process started.
    echo Once the IDE finishes loading:
    echo   1. Wait for Gradle sync to complete.
    echo   2. Select your device or emulator.
    echo   3. Click Run [Shift+F10].
    echo.
    pause
) else (
    echo [!] Could not locate Android Studio automatically.
    echo Opening project folder in File Explorer...
    explorer "%PROJECT_DIR%"
    echo.
    echo Please open Android Studio manually, select File -^> Open, and choose:
    echo "%PROJECT_DIR%"
    echo.
    pause
)

endlocal

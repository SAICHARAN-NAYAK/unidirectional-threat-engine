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

:: Check common installation paths
set "STUDIO_EXE="
if exist "C:\Program Files\Android\Android Studio\bin\studio64.exe" (
    set "STUDIO_EXE=C:\Program Files\Android\Android Studio\bin\studio64.exe"
) else if exist "%LOCALAPPDATA%\Programs\Android Studio\bin\studio64.exe" (
    set "STUDIO_EXE=%LOCALAPPDATA%\Programs\Android Studio\bin\studio64.exe"
) else (
    :: Check JetBrains Toolbox install location
    for /f "delims=" %%I in ('dir /b /s "%LOCALAPPDATA%\JetBrains\Toolbox\apps\AndroidStudio\bin\studio64.exe" 2^>nul') do (
        set "STUDIO_EXE=%%I"
    )
)

if defined STUDIO_EXE (
    echo [OK] Located Android Studio: "!STUDIO_EXE!"
    echo [OK] Spawning Android Studio IDE...
    start "" "!STUDIO_EXE!" "%PROJECT_DIR%"
    echo.
    echo Android Studio is launching.
    echo Once open, select your device or emulator and click Run [Shift+F10].
) else (
    echo [!] Could not locate Android Studio automatically.
    echo Opening project folder in File Explorer...
    explorer "%PROJECT_DIR%"
    echo.
    echo Please open Android Studio manually, select File -^> Open, and choose:
    echo "%PROJECT_DIR%"
    pause
)

endlocal

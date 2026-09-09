@echo off
setlocal
title Open CYBERSHIELD in Android Studio

set "PROJECT_DIR=%~dp0android_studio_app"
set "STUDIO_EXE=C:\Program Files\Android\Android Studio\bin\studio64.exe"

echo ===============================================================================
echo  CYBERSHIELD // Opening Android Studio Project
echo  Project Path: %PROJECT_DIR%
echo ===============================================================================
echo.

if exist "%STUDIO_EXE%" goto :launch_studio
goto :studio_not_found

:launch_studio
echo [OK] Located Android Studio: "%STUDIO_EXE%"
echo [OK] Spawning Android Studio IDE...
start "" "%STUDIO_EXE%" "%PROJECT_DIR%"
echo.
echo Android Studio is launching.
echo Once open, select your device or emulator and click Run [Shift+F10].
goto :end

:studio_not_found
echo [!] Could not locate Android Studio at default path.
echo Please open Android Studio manually, select 'File' -^> 'Open' and choose:
echo "%PROJECT_DIR%"
pause

:end
endlocal

@echo off
setlocal
cd /d "%~dp0"

:: Launch RedEye silently near the Windows system clock using pythonw
where pythonw >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    start "" pythonw "%~dp0redeye_app.py" --test
    echo [RedEye] Started silently near the system clock (with a 5-second test alert).
    exit /b 0
)

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    start "" /B python "%~dp0redeye_app.py" --test
    echo [RedEye] Started near the system clock.
    exit /b 0
)

echo [Error] Python was not found in PATH. Please install Python 3.10+ and run: pip install -r requirements.txt
pause

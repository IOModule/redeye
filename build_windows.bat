@echo off
setlocal
cd /d "%~dp0"
echo ========================================================
echo   Building RedEye Standalone Windows Executable (.exe)
echo ========================================================

pip install pyinstaller -r requirements.txt
python -c "import redeye_app; app_pix = redeye_app.create_red_eye_Pixmap(128); app_pix.save('redeye.ico', 'ICO')"

pyinstaller --noconfirm --onefile --windowed ^
    --name "RedEye" ^
    --icon "redeye.ico" ^
    --distpath "windows-build" ^
    redeye_app.py

echo.
echo [SUCCESS] Built standalone executable at: %~dp0windows-build\RedEye.exe
pause

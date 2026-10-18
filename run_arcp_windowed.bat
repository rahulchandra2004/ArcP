@echo off
title ArcP Launcher (Windowed Mode)
cd /d "%~dp0"
echo ===================================================
echo Starting ArcP in Standard Windowed Desktop Mode
echo ===================================================
python main.py --windowed %*
if errorlevel 1 (
    echo.
    echo ArcP exited with an error.
    pause
)

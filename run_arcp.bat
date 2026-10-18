@echo off
title ArcP Launcher
cd /d "%~dp0"
echo ===================================================
echo Starting ArcP (Autonomous Radial Context Pipeline)
echo ===================================================
python main.py %*
if errorlevel 1 (
    echo.
    echo ArcP exited with an error.
    pause
)

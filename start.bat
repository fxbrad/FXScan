@echo off
title FXScan
cd /d "%~dp0"

echo ============================================
echo    FXScan - FiveM resource scanner
echo ============================================
echo.

set "PYTHON=python"
python --version >nul 2>&1
if errorlevel 1 (
    py -3 --version >nul 2>&1
    if errorlevel 1 (
        echo [X] Python was not found.
        echo.
        echo     Install it from https://python.org
        echo     During setup, tick "Add Python to PATH".
        echo.
        pause
        exit /b 1
    )
    set "PYTHON=py -3"
)

echo [1/3] Python found.

%PYTHON% -c "import flask, yaml" >nul 2>&1
if errorlevel 1 (
    echo [2/3] Installing dependencies ^(first run only^)...
    %PYTHON% -m pip install -r requirements.txt
    if errorlevel 1 (
        echo.
        echo [X] Failed to install dependencies. Check your internet connection.
        echo.
        pause
        exit /b 1
    )
) else (
    echo [2/3] Dependencies already installed.
)

echo [3/3] Starting the scanner...
echo.
echo     Your browser will open at http://127.0.0.1:5000
echo     Keep this window open while you use the scanner.
echo     Close this window to stop it.
echo.

start "" /b powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 3; Start-Process 'http://127.0.0.1:5000'"
%PYTHON% web\app.py

echo.
echo Scanner stopped.
pause

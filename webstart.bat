@echo off
title WiFi Guard
cd /d "%~dp0"

REM --- Live packet capture needs admin. Re-launch elevated if needed. ---
net session >nul 2>&1
if errorlevel 1 (
  echo Requesting administrator permission...
  powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

REM --- Check Python ---
set "PY=py"
py --version >nul 2>&1
if not errorlevel 1 goto haspy
set "PY=python"
python --version >nul 2>&1
if not errorlevel 1 goto haspy
echo.
echo [ERROR] Python is not installed.
echo   Download it from https://www.python.org/downloads/
echo   On the first setup screen, check "Add python.exe to PATH".
echo.
pause
exit /b
:haspy

REM --- First run: create virtual env and install packages (needs internet) ---
REM A .venv copied from another PC points to that PC's Python and does not run here.
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -c "import flask, flask_socketio, scapy" >nul 2>&1
  if not errorlevel 1 goto run
  echo Existing .venv does not work on this PC. Rebuilding it...
  rmdir /s /q .venv
)
echo.
echo First run: installing components. This may take a few minutes...
echo.
%PY% -m venv .venv
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
  echo.
  echo [ERROR] Install failed. Check your internet connection and run again.
  echo.
  pause
  exit /b
)
:run

REM --- Open the browser shortly after the server starts ---
start "" cmd /c "timeout /t 4 >nul & start http://127.0.0.1:5000"

echo.
echo ============================================================
echo   WiFi Guard is running.
echo   Browser opens automatically:  http://127.0.0.1:5000
echo.
echo   To stop: close this black window.
echo ============================================================
echo.

REM --- Start live monitoring (default = real packet capture) ---
".venv\Scripts\python.exe" run_server.py

pause

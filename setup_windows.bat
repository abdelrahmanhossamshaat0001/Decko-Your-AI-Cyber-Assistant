@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install Python 3.11 or 3.12 from python.org first.
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo Creating the virtual environment...
  py -3 -m venv .venv || goto :fail
)

echo Installing Decko requirements...
".venv\Scripts\python.exe" -m pip install --upgrade pip || goto :fail
".venv\Scripts\python.exe" -m pip install -r requirements.txt || goto :fail

echo Checking the installation...
".venv\Scripts\python.exe" verify_installation.py --test-tools || goto :fail

echo Starting Decko...
".venv\Scripts\python.exe" decko.py
exit /b %errorlevel%

:fail
echo.
echo Setup did not finish. Read the error above, then run this file again.
pause
exit /b 1

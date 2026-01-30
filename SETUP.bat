@echo off
REM Permanent Dependency Installer for Phishing Detector
REM Run this once to ensure all dependencies are always installed

echo ========================================
echo   PHISHING DETECTOR - SETUP WIZARD
echo ========================================
echo.

setlocal enabledelayedexpansion

set "BACKEND_PATH=C:\xampp\htdocs\phishing\backend"
set "VENV_PATH=C:\xampp\htdocs\phishing\.venv\Scripts\python.exe"
set "PROJECT_ROOT=C:\xampp\htdocs\phishing"

echo [*] Checking environment...

REM Check if venv exists
if not exist "%VENV_PATH%" (
    echo [!] Virtual environment not found. Creating...
    cd /d "%PROJECT_ROOT%"
    python -m venv .venv
    echo [+] Virtual environment created
    echo.
)

echo [*] Installing/Updating all dependencies...
echo     This may take a few minutes...
echo.

cd /d "%BACKEND_PATH%"

REM Upgrade pip first
echo [*] Upgrading pip...
"%VENV_PATH%" -m pip install --upgrade pip setuptools wheel -q

REM Install all dependencies from requirements.txt
echo [*] Installing dependencies from requirements.txt...
"%VENV_PATH%" -m pip install -r requirements.txt -q

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to install dependencies!
    echo Please check requirements.txt
    pause
    exit /b 1
)

echo.
echo [+] All dependencies installed successfully!
echo.
echo [*] Verifying Flask installation...
"%VENV_PATH%" -c "import flask; print('[+] Flask version: ' + flask.__version__)"

echo [*] Verifying Flask-Limiter installation...
"%VENV_PATH%" -c "import flask_limiter; print('[+] Flask-Limiter installed')"

echo [*] Verifying scikit-learn installation...
"%VENV_PATH%" -c "import sklearn; print('[+] scikit-learn version: ' + sklearn.__version__)"

echo.
echo ========================================
echo   SETUP COMPLETE!
echo ========================================
echo.
echo You can now run:
echo   python secure_api.py
echo.
echo Or for production:
echo   gunicorn --config gunicorn_config.py secure_api:app
echo.
pause

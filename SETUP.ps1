# Permanent Dependency Installer for Phishing Detector
# Run this once to ensure all dependencies are always installed

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PHISHING DETECTOR - SETUP WIZARD" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$BACKEND_PATH = "C:\xampp\htdocs\phishing\backend"
$VENV_PATH = "C:\xampp\htdocs\phishing\.venv\Scripts\python.exe"
$PROJECT_ROOT = "C:\xampp\htdocs\phishing"
$REQUIREMENTS = "$BACKEND_PATH\requirements.txt"

Write-Host "[*] Checking environment..." -ForegroundColor Yellow

# Check if venv exists
if (-not (Test-Path $VENV_PATH)) {
    Write-Host "[!] Virtual environment not found. Creating..." -ForegroundColor Yellow
    Set-Location $PROJECT_ROOT
    python -m venv .venv
    Write-Host "[+] Virtual environment created" -ForegroundColor Green
    Write-Host ""
}

Write-Host "[*] Installing/Updating all dependencies..." -ForegroundColor Yellow
Write-Host "    This may take a few minutes..." -ForegroundColor Yellow
Write-Host ""

Set-Location $BACKEND_PATH

# Upgrade pip first
Write-Host "[*] Upgrading pip..." -ForegroundColor Yellow
& $VENV_PATH -m pip install --upgrade pip setuptools wheel -q

# Install all dependencies from requirements.txt
Write-Host "[*] Installing dependencies from requirements.txt..." -ForegroundColor Yellow
& $VENV_PATH -m pip install -r $REQUIREMENTS -q

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[ERROR] Failed to install dependencies!" -ForegroundColor Red
    Write-Host "Please check requirements.txt" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "[+] All dependencies installed successfully!" -ForegroundColor Green
Write-Host ""

Write-Host "[*] Verifying installations..." -ForegroundColor Yellow

Write-Host "[*] Checking Flask..." -ForegroundColor Yellow
& $VENV_PATH -c "import flask; print('[+] Flask version: ' + flask.__version__)"

Write-Host "[*] Checking Flask-Limiter..." -ForegroundColor Yellow
& $VENV_PATH -c "import flask_limiter; print('[+] Flask-Limiter installed')"

Write-Host "[*] Checking scikit-learn..." -ForegroundColor Yellow
& $VENV_PATH -c "import sklearn; print('[+] scikit-learn version: ' + sklearn.__version__)"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SETUP COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "You can now run:" -ForegroundColor Green
Write-Host "  python secure_api.py" -ForegroundColor White
Write-Host ""
Write-Host "Or for production:" -ForegroundColor Green
Write-Host "  gunicorn --config gunicorn_config.py secure_api:app" -ForegroundColor White
Write-Host ""
Write-Host "Press Enter to close..." -ForegroundColor Yellow
Read-Host

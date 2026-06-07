# grey-hat-security-agent Setup Script (PowerShell)
# Run this script after cloning the repository to set up the development environment.

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "grey-hat-security-agent — Environment Setup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# 1. Check Python version
Write-Host "`n[1/6] Checking Python version..." -ForegroundColor Yellow
$pythonVersion = python --version 2>&1
Write-Host "  Found: $pythonVersion"
if (-not ($pythonVersion -match "3\.1[12]")) {
    Write-Host "  WARNING: Python 3.11+ is recommended. Current: $pythonVersion" -ForegroundColor Red
}

# 2. Create virtual environment
Write-Host "`n[2/6] Creating virtual environment..." -ForegroundColor Yellow
if (-not (Test-Path "venv")) {
    python -m venv venv
    Write-Host "  Virtual environment created."
} else {
    Write-Host "  Virtual environment already exists."
}

# 3. Activate and install dependencies
Write-Host "`n[3/6] Installing dependencies..." -ForegroundColor Yellow
& ".\venv\Scripts\pip.exe" install -r requirements.txt
Write-Host "  Dependencies installed."

# 4. Create data directories
Write-Host "`n[4/6] Creating data directories..." -ForegroundColor Yellow
@("data\cve_mirror", "data\model_cache", "data\reports", "logs", "keys") | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
        Write-Host "  Created: $_"
    } else {
        Write-Host "  Exists: $_"
    }
}

# 5. Copy .env.example to .env if not exists
Write-Host "`n[5/6] Setting up environment configuration..." -ForegroundColor Yellow
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "  Created .env from .env.example — fill in your API keys!" -ForegroundColor Green
} else {
    Write-Host "  .env already exists."
}

# 6. Generate encryption key
Write-Host "`n[6/6] Generating database encryption key..." -ForegroundColor Yellow
& ".\venv\Scripts\python.exe" -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>&1 | ForEach-Object {
    if ($_ -match "^g") {
        Write-Host "  Generated ENCRYPTION_KEY. Add it to your .env file." -ForegroundColor Green
        Write-Host "  Key: $_" -ForegroundColor Cyan
    }
}

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "Setup complete! Next steps:" -ForegroundColor Green
Write-Host "  1. Edit .env and add your API keys" -ForegroundColor White
Write-Host "  2. Install Ollama: https://ollama.ai/download" -ForegroundColor White
Write-Host "  3. Pull model: ollama pull mistral:7b-instruct" -ForegroundColor White
Write-Host "  4. Install nmap: https://nmap.org/download.html" -ForegroundColor White
Write-Host "  5. Run tests: .\venv\Scripts\python.exe -m pytest tests\ -v" -ForegroundColor White
Write-Host "============================================" -ForegroundColor Cyan

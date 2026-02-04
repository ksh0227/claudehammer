# install.ps1 - Install ClaudeHammer for Windows
# Run: powershell -ExecutionPolicy Bypass -File install.ps1

$ErrorActionPreference = "Stop"

Write-Host "ClaudeHammer for Windows - Installer" -ForegroundColor Cyan
Write-Host ""

# Check Python
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    Write-Host "Python not found. Install from https://python.org" -ForegroundColor Red
    exit 1
}

$ver = python --version 2>&1
Write-Host "Found $ver"

# Install dependencies
Write-Host "Installing dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "pip install failed." -ForegroundColor Red
    exit 1
}

# Create data directory
$dataDir = Join-Path $env:USERPROFILE ".claudehammer"
if (-not (Test-Path $dataDir)) {
    New-Item -ItemType Directory -Path $dataDir | Out-Null
}

Write-Host ""
Write-Host "Installed successfully." -ForegroundColor Green
Write-Host ""
Write-Host "Usage:" -ForegroundColor Cyan
Write-Host "  python claudehammer.py"
Write-Host ""
Write-Host "Toggle:  Ctrl+Shift+A"
Write-Host "Config:  $dataDir\config.json"
Write-Host "Log:     $dataDir\audit.log"

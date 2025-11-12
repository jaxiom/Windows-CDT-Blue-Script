# CCDC Windows Hardening - Quick Run Script
# This script downloads and executes the Ansible playbook

param(
    [string]$PlaybookUrl = "https://raw.githubusercontent.com/jaxiom/Windows-CDT-Blue-Script/main/windows_harden.yml",
    [string]$InventoryContent = "localhost ansible_connection=local"
)

Write-Host "=== CCDC Windows Hardening Script ===" -ForegroundColor Cyan
Write-Host "Starting hardening process..." -ForegroundColor Yellow

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    exit 1
}

# Create working directory
$workDir = "C:\CCDC_Hardening"
if (-not (Test-Path $workDir)) {
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
}
Set-Location $workDir

# Check if Ansible is installed
$ansibleInstalled = Get-Command ansible-playbook -ErrorAction SilentlyContinue

if (-not $ansibleInstalled) {
    Write-Host "Ansible not found. Installing Ansible..." -ForegroundColor Yellow
    
    # Install Python if not present
    $pythonInstalled = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonInstalled) {
        Write-Host "ERROR: Python not found. Please install Python 3.8+ first from python.org" -ForegroundColor Red
        Write-Host "Or use: winget install Python.Python.3.11" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "Python found. Installing Ansible and pywinrm..." -ForegroundColor Yellow
    
    # Install Ansible via pip
    python -m pip install --upgrade pip --quiet
    python -m pip install ansible pywinrm --quiet
    
    Write-Host "Ansible installed. Locating ansible-playbook..." -ForegroundColor Yellow
    
    # Refresh PATH in current session
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    
    # Try to find ansible-playbook in common locations
    $pythonScriptsPath = python -c "import os, sys; print(os.path.join(sys.prefix, 'Scripts'))"
    $ansiblePath = Join-Path $pythonScriptsPath "ansible-playbook.exe"
    
    if (Test-Path $ansiblePath) {
        Write-Host "Found ansible-playbook at: $ansiblePath" -ForegroundColor Green
        # Add Python Scripts to PATH for this session
        $env:Path = "$pythonScriptsPath;$env:Path"
    } else {
        Write-Host "ERROR: ansible-playbook not found after installation" -ForegroundColor Red
        Write-Host "Expected location: $ansiblePath" -ForegroundColor Yellow
        Write-Host "Please close this PowerShell window and open a new one, then run the script again." -ForegroundColor Yellow
        exit 1
    }
    
    # Verify it's accessible now
    $ansibleInstalled = Get-Command ansible-playbook -ErrorAction SilentlyContinue
    if (-not $ansibleInstalled) {
        Write-Host "ERROR: Still cannot find ansible-playbook after PATH update" -ForegroundColor Red
        Write-Host "Try running: $ansiblePath directly" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "Ansible is ready!" -ForegroundColor Green
}

# Download the playbook
Write-Host "Downloading playbook from GitHub..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $PlaybookUrl -OutFile "$workDir\windows_harden.yml"
    Write-Host "Playbook downloaded successfully." -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to download playbook from $PlaybookUrl" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# Create inventory file
Write-Host "Creating inventory..." -ForegroundColor Yellow
$InventoryContent | Out-File -FilePath "$workDir\inventory.ini" -Encoding ASCII

# Run the Ansible playbook
Write-Host "`nRunning hardening playbook..." -ForegroundColor Cyan
Write-Host "This may take several minutes...`n" -ForegroundColor Yellow

ansible-playbook -i "$workDir\inventory.ini" "$workDir\windows_harden.yml" -v

# Check exit code
if ($LASTEXITCODE -eq 0) {
    Write-Host "`n=== HARDENING COMPLETED SUCCESSFULLY ===" -ForegroundColor Green
    Write-Host "Review the output above for any issues or suspicious findings." -ForegroundColor Yellow
    Write-Host "Sysinternals tools are available in C:\Sysinternals" -ForegroundColor Cyan
} else {
    Write-Host "`n=== HARDENING COMPLETED WITH ERRORS ===" -ForegroundColor Yellow
    Write-Host "Check the output above for details." -ForegroundColor Yellow
}

Write-Host "`nLog files saved in: $workDir" -ForegroundColor Cyan
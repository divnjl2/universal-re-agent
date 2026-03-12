# Step 1: Enable OpenSSH Server on Windows
# Run as Administrator on the target server via RDP

Write-Host "=== Enabling OpenSSH Server ===" -ForegroundColor Green

# Install OpenSSH Server feature
$sshCapability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
if ($sshCapability.State -ne 'Installed') {
    Write-Host "Installing OpenSSH Server..."
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
} else {
    Write-Host "OpenSSH Server already installed"
}

# Start and enable the service
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Ensure firewall rule exists
$rule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
if (-not $rule) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' `
        -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
    Write-Host "Firewall rule created"
} else {
    Write-Host "Firewall rule already exists"
}

# Set default shell to PowerShell
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell `
    -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -PropertyType String -Force | Out-Null

Write-Host "`n=== SSH Server is running ===" -ForegroundColor Green
Write-Host "Connect with: ssh Administrator@144.31.164.254"

# Also install Python if not present
$pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
if ($pythonPath) {
    Write-Host "`nPython found: $pythonPath"
    python --version
} else {
    Write-Host "`nPython NOT found. Installing via winget..." -ForegroundColor Yellow
    winget install Python.Python.3.12 --accept-package-agreements --accept-source-agreements
    Write-Host "Restart PowerShell after Python install!"
}

# Check if pip/frida available
Write-Host "`n=== Installing dependencies ==="
python -m pip install --upgrade pip 2>$null
python -m pip install frida frida-tools psutil 2>$null

Write-Host "`n=== Done! SSH should be accessible now ===" -ForegroundColor Green

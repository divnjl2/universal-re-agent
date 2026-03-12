# Step 2: Reconnaissance - find what's running, where binaries are
# Run via SSH or RDP

Write-Host "=== Server Reconnaissance ===" -ForegroundColor Green

# System info
Write-Host "`n--- System ---"
$os = Get-CimInstance Win32_OperatingSystem
Write-Host "OS: $($os.Caption) $($os.Version)"
Write-Host "RAM: $([math]::Round($os.TotalVisibleMemorySize/1MB, 1)) GB"

# Find Python processes and Nuitka binaries
Write-Host "`n--- Running Processes (Python/Bot related) ---"
Get-Process | Where-Object {
    $_.ProcessName -match 'python|kyc|bot|bybit|manager|nuitka|main' -or
    $_.Path -match 'python|kyc|bot|bybit'
} | Format-Table Id, ProcessName, Path, WorkingSet64 -AutoSize

# Find all exe/dll files that could be our targets
Write-Host "`n--- Searching for target binaries ---"
$searchPaths = @("C:\", "D:\")
$patterns = @("kyc_bot*.exe", "bybit_manager*.exe", "main.dll", "start_bot*")

foreach ($base in $searchPaths) {
    if (Test-Path $base) {
        foreach ($pat in $patterns) {
            $found = Get-ChildItem -Path $base -Filter $pat -Recurse -ErrorAction SilentlyContinue -Depth 5
            foreach ($f in $found) {
                Write-Host "  FOUND: $($f.FullName) ($([math]::Round($f.Length/1MB, 1)) MB)" -ForegroundColor Cyan
            }
        }
    }
}

# Find Python installations
Write-Host "`n--- Python installations ---"
$pythonPaths = @(
    "C:\Python*",
    "C:\Program Files\Python*",
    "C:\Users\*\AppData\Local\Programs\Python\*",
    "C:\Users\*\miniconda*",
    "C:\Users\*\anaconda*"
)
foreach ($pp in $pythonPaths) {
    $found = Get-Item $pp -ErrorAction SilentlyContinue
    foreach ($f in $found) { Write-Host "  $($f.FullName)" }
}

# Check for python312.dll / python313.dll in system
Write-Host "`n--- Python DLLs ---"
Get-ChildItem -Path C:\ -Filter "python3*.dll" -Recurse -ErrorAction SilentlyContinue -Depth 5 |
    Select-Object -First 20 |
    ForEach-Object { Write-Host "  $($_.FullName)" }

# Network connections
Write-Host "`n--- Network Connections (ESTABLISHED) ---"
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { $_.RemotePort -notin @(443, 80) -or $_.LocalPort -gt 1024 } |
    Select-Object -First 30 |
    Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess -AutoSize

# Scheduled tasks that might auto-start the bot
Write-Host "`n--- Scheduled Tasks (non-Microsoft) ---"
Get-ScheduledTask | Where-Object {
    $_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled"
} | Format-Table TaskName, State, TaskPath -AutoSize

# Services
Write-Host "`n--- Services (Running, non-Microsoft) ---"
Get-Service | Where-Object {
    $_.Status -eq 'Running' -and
    $_.DisplayName -notmatch 'Windows|Microsoft|DCOM|Remote|Print|Network|Plug|Security|Update|Defender|WMI|DNS|DHCP|Event|COM\+'
} | Format-Table Name, DisplayName, Status -AutoSize

Write-Host "`n=== Recon complete ===" -ForegroundColor Green

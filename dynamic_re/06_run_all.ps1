# Master orchestrator — runs the full dynamic RE pipeline
# Run as Administrator on the target server
# Usage: .\06_run_all.ps1 -TargetExe "C:\path\to\kyc_bot_v1.exe"

param(
    [string]$TargetExe = "",
    [string]$DumpDir = "$PSScriptRoot\dumps",
    [int]$DumpDelay = 20
)

$ErrorActionPreference = "Continue"

Write-Host @"
============================================================
  DYNAMIC REVERSE ENGINEERING PIPELINE
  Target: $TargetExe
============================================================
"@ -ForegroundColor Green

# Create output directory
New-Item -ItemType Directory -Path $DumpDir -Force | Out-Null

# --- Step 1: Find target if not specified ---
if (-not $TargetExe) {
    Write-Host "`n[1/5] Searching for target binaries..." -ForegroundColor Yellow

    $candidates = @()
    $searchPaths = @("C:\", "D:\")
    $patterns = @("kyc_bot*.exe", "bybit_manager*.exe")

    foreach ($base in $searchPaths) {
        if (Test-Path $base) {
            foreach ($pat in $patterns) {
                $found = Get-ChildItem -Path $base -Filter $pat -Recurse -ErrorAction SilentlyContinue -Depth 5
                $candidates += $found
            }
        }
    }

    # Also check running processes
    $running = Get-Process | Where-Object {
        $_.Path -and ($_.Path -match 'kyc|bot|bybit')
    }

    if ($running) {
        Write-Host "  Running bot processes:" -ForegroundColor Cyan
        $running | Format-Table Id, ProcessName, Path -AutoSize
    }

    if ($candidates) {
        Write-Host "  Found binaries:"
        $i = 0
        foreach ($c in $candidates) {
            Write-Host "    [$i] $($c.FullName) ($([math]::Round($c.Length/1MB, 1)) MB)"
            $i++
        }
        $selection = Read-Host "  Select target [0-$($i-1)]"
        $TargetExe = $candidates[$selection].FullName
    } else {
        Write-Host "  No binaries found! Enter path manually:" -ForegroundColor Red
        $TargetExe = Read-Host "  Path"
    }
}

if (-not (Test-Path $TargetExe)) {
    Write-Host "ERROR: $TargetExe not found!" -ForegroundColor Red
    exit 1
}

$targetDir = Split-Path $TargetExe -Parent
$targetName = Split-Path $TargetExe -Leaf

Write-Host "`n  Target: $TargetExe" -ForegroundColor Cyan
Write-Host "  Target dir: $targetDir"

# --- Step 2: Install hooks ---
Write-Host "`n[2/5] Installing introspection hooks..." -ForegroundColor Yellow

# Copy sitecustomize.py next to the exe
Copy-Item "$PSScriptRoot\05_sitecustomize.py" "$targetDir\sitecustomize.py" -Force
Copy-Item "$PSScriptRoot\03_nuitka_introspect.py" "$targetDir\03_nuitka_introspect.py" -Force
Write-Host "  Copied sitecustomize.py and 03_nuitka_introspect.py to $targetDir"

# --- Step 3: Launch the target with hooks enabled ---
Write-Host "`n[3/5] Launching target with introspection..." -ForegroundColor Yellow

$env:NUITKA_DUMP_ON_START = "1"
$env:NUITKA_DUMP_DELAY = "$DumpDelay"
$env:DUMP_OUTPUT_DIR = $DumpDir
$env:PYTHONPATH = "$targetDir;$PSScriptRoot"

# Check if already running
$existing = Get-Process | Where-Object { $_.Path -eq $TargetExe }
if ($existing) {
    Write-Host "  Target is already running (PID $($existing.Id))!" -ForegroundColor Cyan
    Write-Host "  Will dump from running process instead."

    # Run memory dump on existing process
    Write-Host "`n[4/5] Memory dump of running process..." -ForegroundColor Yellow
    python "$PSScriptRoot\04_memory_dump.py" $existing.Id

    # Try to inject introspection via separate approach
    Write-Host "`n  Note: For full introspection, restart the process with hooks."
    Write-Host "  To restart: Stop-Process -Id $($existing.Id); then run this script again"
} else {
    # Start the process
    Write-Host "  Starting: $TargetExe"
    Write-Host "  Dump will trigger in ${DumpDelay}s..."

    $proc = Start-Process -FilePath $TargetExe -WorkingDirectory $targetDir -PassThru
    $pid = $proc.Id
    Write-Host "  Started with PID $pid"

    # Wait for dump delay + buffer
    $waitTime = $DumpDelay + 10
    Write-Host "  Waiting ${waitTime}s for introspection dump..."

    for ($i = 0; $i -lt $waitTime; $i++) {
        Start-Sleep -Seconds 1
        Write-Progress -Activity "Waiting for dump" -SecondsRemaining ($waitTime - $i)

        # Check if process is still alive
        if ($proc.HasExited) {
            Write-Host "  Process exited with code $($proc.ExitCode)" -ForegroundColor Red
            break
        }
    }

    # --- Step 4: Memory dump ---
    if (-not $proc.HasExited) {
        Write-Host "`n[4/5] Memory dump..." -ForegroundColor Yellow
        python "$PSScriptRoot\04_memory_dump.py" $pid
    }
}

# --- Step 5: Collect results ---
Write-Host "`n[5/5] Collecting results..." -ForegroundColor Yellow

$dumpFiles = Get-ChildItem -Path @($DumpDir, $targetDir) -Filter "*.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'nuitka_runtime|memory_dump|minimal_dump|exit_modules' } |
    Sort-Object LastWriteTime -Descending

if ($dumpFiles) {
    Write-Host "  Dump files:" -ForegroundColor Green
    foreach ($f in $dumpFiles) {
        $sizeMB = [math]::Round($f.Length / 1MB, 2)
        Write-Host "    $($f.FullName) ($sizeMB MB)"
    }
} else {
    Write-Host "  No dump files found yet. Check $DumpDir and $targetDir" -ForegroundColor Red

    # Check for sitecustomize output
    $siteOutput = Get-ChildItem -Path $targetDir -Filter "*dump*.json" -ErrorAction SilentlyContinue
    if ($siteOutput) {
        Write-Host "  Found in target dir:"
        $siteOutput | ForEach-Object { Write-Host "    $($_.FullName)" }
    }
}

# Cleanup hook files (optional)
# Remove-Item "$targetDir\sitecustomize.py" -ErrorAction SilentlyContinue
# Remove-Item "$targetDir\03_nuitka_introspect.py" -ErrorAction SilentlyContinue

Write-Host @"

============================================================
  DONE. Next steps:
  1. Copy dump files back to analysis machine
  2. Run: python 07_analyze_dump.py <dump_file.json>
============================================================
"@ -ForegroundColor Green

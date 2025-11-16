# ULTIMATE PROXY DLL INJECTION
# Combines: GAC rename + Process injection + Auto-restore

$ErrorActionPreference = "Stop"

Write-Host "================================================" -ForegroundColor Cyan
Write-Host " ULTIMATE PROXY DLL INJECTION" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: Requires ADMINISTRATOR!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit 1
}

$gacPath = "C:\WINDOWS\Microsoft.NET\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll"
$backupPath = "$gacPath.BACKUP_INJECT"

try {
    # Step 1: Rename GAC DLL
    Write-Host "[1/5] Renaming GAC DLL..." -ForegroundColor Yellow
    if (Test-Path $gacPath) {
        Move-Item $gacPath $backupPath -Force
        Write-Host "  SUCCESS - GAC DLL renamed" -ForegroundColor Green
    } else {
        Write-Host "  WARNING - GAC DLL already renamed?" -ForegroundColor Yellow
    }
    
    # Step 2: Start crackme
    Write-Host ""
    Write-Host "[2/5] Starting crackme..." -ForegroundColor Yellow
    Remove-Item "PROXY_LOADED.txt" -ErrorAction SilentlyContinue
    Remove-Item "proxy_log.txt" -ErrorAction SilentlyContinue
    Remove-Item "PROXY_ERROR.txt" -ErrorAction SilentlyContinue
    
    $proc = Start-Process ".\RikaCrackmeV1.exe" -PassThru
    Write-Host "  PID: $($proc.Id)" -ForegroundColor Green
    
    # Step 3: Wait for initialization
    Write-Host ""
    Write-Host "[3/5] Waiting for crackme to initialize..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    
    if ($proc.HasExited) {
        Write-Host "  ERROR - Crackme crashed immediately!" -ForegroundColor Red
        throw "Crackme crashed"
    }
    
    Write-Host "  Crackme running!" -ForegroundColor Green
    
    # Step 4: Analysis period
    Write-Host ""
    Write-Host "[4/5] Waiting for analysis (8 seconds)..." -ForegroundColor Yellow
    Write-Host "  Our DLL should load automatically (GAC is disabled)" -ForegroundColor Gray
    Start-Sleep -Seconds 8
    
    # Step 5: Check results
    Write-Host ""
    Write-Host "[5/5] Checking results..." -ForegroundColor Yellow
    
    $foundLog = $false
    
    if (Test-Path "PROXY_LOADED.txt") {
        Write-Host ""
        Write-Host "=== PROXY LOADED ===" -ForegroundColor Green
        Get-Content "PROXY_LOADED.txt"
        $foundLog = $true
    }
    
    if (Test-Path "proxy_log.txt") {
        Write-Host ""
        Write-Host "=== PROXY LOG ===" -ForegroundColor Green
        Get-Content "proxy_log.txt"
        $foundLog = $true
    }
    
    if (Test-Path "PROXY_ERROR.txt") {
        Write-Host ""
        Write-Host "=== PROXY ERROR ===" -ForegroundColor Red
        Get-Content "PROXY_ERROR.txt"
        $foundLog = $true
    }
    
    if (-not $foundLog) {
        Write-Host "  No logs found - DLL might not have loaded" -ForegroundColor Yellow
    }
    
} finally {
    # Always restore GAC
    Write-Host ""
    Write-Host "Cleaning up..." -ForegroundColor Yellow
    
    # Kill crackme
    try {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    } catch {}
    
    # Restore GAC DLL
    if (Test-Path $backupPath) {
        Move-Item $backupPath $gacPath -Force
        Write-Host "  GAC DLL restored" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host " System restored safely" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Cyan
}

Write-Host ""
pause


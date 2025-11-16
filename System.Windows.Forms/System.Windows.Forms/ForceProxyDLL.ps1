# Force load proxy DLL by temporarily renaming GAC version
$ErrorActionPreference = "Stop"

Write-Host "=== FORCING PROXY DLL TO LOAD ===" -ForegroundColor Cyan
Write-Host ""

# GAC path
$gacPath = "C:\WINDOWS\Microsoft.NET\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll"
$gacBackup = "$gacPath.BACKUP"

# Check if we have admin rights
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script requires ADMINISTRATOR privileges!" -ForegroundColor Red
    Write-Host "Right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "✓ Running as Administrator" -ForegroundColor Green
Write-Host ""

# Check if GAC DLL exists
if (-not (Test-Path $gacPath)) {
    Write-Host "WARNING: GAC DLL not found at expected path" -ForegroundColor Yellow
    Write-Host "Path: $gacPath" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Trying to find it..." -ForegroundColor Yellow
    
    $foundPath = Get-ChildItem "C:\WINDOWS\Microsoft.NET\assembly\GAC_MSIL\" -Recurse -Filter "System.Windows.Forms.dll" -ErrorAction SilentlyContinue | 
                 Where-Object { $_.Directory.Name -like "*b77a5c561934e089*" } | 
                 Select-Object -First 1 -ExpandProperty FullName
    
    if ($foundPath) {
        Write-Host "Found at: $foundPath" -ForegroundColor Green
        $gacPath = $foundPath
        $gacBackup = "$gacPath.BACKUP"
    } else {
        Write-Host "ERROR: Could not find GAC System.Windows.Forms.dll" -ForegroundColor Red
        exit 1
    }
}

Write-Host "GAC DLL: $gacPath" -ForegroundColor White
Write-Host ""

# Check if already backed up
if (Test-Path $gacBackup) {
    Write-Host "WARNING: Backup already exists!" -ForegroundColor Yellow
    Write-Host "Looks like GAC DLL was already renamed." -ForegroundColor Yellow
    Write-Host ""
    $response = Read-Host "Restore it? (y/n)"
    
    if ($response -eq 'y') {
        Write-Host "Restoring GAC DLL..." -ForegroundColor Yellow
        Move-Item $gacBackup $gacPath -Force
        Write-Host "✓ GAC DLL restored" -ForegroundColor Green
        Write-Host ""
    }
    exit 0
}

# Backup GAC DLL
Write-Host "Step 1: Backing up GAC DLL..." -ForegroundColor Yellow
try {
    Move-Item $gacPath $gacBackup -Force
    Write-Host "✓ GAC DLL backed up to: $gacBackup" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to backup GAC DLL" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "Try running 'net stop WinDefend' first (may help)" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "=== SUCCESS! ===" -ForegroundColor Green
Write-Host ""
Write-Host "Now run: .\RikaCrackmeV1.exe" -ForegroundColor Cyan
Write-Host ""
Write-Host "When done, run this script again to RESTORE the GAC DLL." -ForegroundColor Yellow
Write-Host ""

pause


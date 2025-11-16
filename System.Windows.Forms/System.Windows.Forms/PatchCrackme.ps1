# Patch RikaCrackmeV1.exe to remove PublicKeyToken requirement
$ErrorActionPreference = "Stop"

Write-Host "=== RikaCrackme PublicKeyToken Remover ===" -ForegroundColor Cyan
Write-Host ""

$exePath = ".\RikaCrackmeV1.exe"
$backupPath = ".\RikaCrackmeV1.exe.backup"

if (-not (Test-Path $exePath)) {
    Write-Host "ERROR: RikaCrackmeV1.exe not found!" -ForegroundColor Red
    exit 1
}

# Backup original
if (-not (Test-Path $backupPath)) {
    Write-Host "Creating backup: $backupPath" -ForegroundColor Yellow
    Copy-Item $exePath $backupPath -Force
}

Write-Host "Loading assembly..." -ForegroundColor Yellow

# Load Cecil (if available) or use dnSpy/ildasm approach
# For now, let's use a simpler binary patch

# Read file as bytes
$bytes = [System.IO.File]::ReadAllBytes($exePath)

# Search for the PublicKeyToken pattern
# System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
# We'll look for the token bytes: b7 7a 5c 56 19 34 e0 89

$tokenPattern = [byte[]](0xb7, 0x7a, 0x5c, 0x56, 0x19, 0x34, 0xe0, 0x89)
$nullToken = [byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

$found = 0
for ($i = 0; $i -lt ($bytes.Length - 8); $i++) {
    $match = $true
    for ($j = 0; $j -lt 8; $j++) {
        if ($bytes[$i + $j] -ne $tokenPattern[$j]) {
            $match = $false
            break
        }
    }
    
    if ($match) {
        Write-Host "Found PublicKeyToken at offset: 0x$($i.ToString('X8'))" -ForegroundColor Green
        
        # Replace with null token
        for ($j = 0; $j -lt 8; $j++) {
            $bytes[$i + $j] = $nullToken[$j]
        }
        $found++
    }
}

if ($found -gt 0) {
    Write-Host ""
    Write-Host "Patched $found occurrence(s)" -ForegroundColor Green
    Write-Host "Saving patched file..." -ForegroundColor Yellow
    
    # Save patched file
    [System.IO.File]::WriteAllBytes($exePath, $bytes)
    
    Write-Host ""
    Write-Host "=== SUCCESS! ===" -ForegroundColor Green
    Write-Host "RikaCrackmeV1.exe has been patched." -ForegroundColor Green
    Write-Host "Original backup saved as: $backupPath" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Now run: .\RikaCrackmeV1.exe" -ForegroundColor Cyan
} else {
    Write-Host ""
    Write-Host "WARNING: PublicKeyToken pattern not found" -ForegroundColor Yellow
    Write-Host "The executable might be obfuscated or packed." -ForegroundColor Yellow
}

Write-Host ""


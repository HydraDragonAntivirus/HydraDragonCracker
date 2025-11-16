# Simple Password Finder - String Search in Binary
Write-Host "=== SIMPLE PASSWORD FINDER ===" -ForegroundColor Cyan
Write-Host ""

$exePath = ".\RikaCrackmeV1.exe"
$bytes = [System.IO.File]::ReadAllBytes($exePath)

Write-Host "Searching for readable strings in binary..." -ForegroundColor Yellow
Write-Host ""

# Extract all ASCII strings (min 4 chars)
$strings = @()
$currentString = ""

for ($i = 0; $i -lt $bytes.Length; $i++) {
    $byte = $bytes[$i]
    
    # Printable ASCII range
    if ($byte -ge 32 -and $byte -le 126) {
        $currentString += [char]$byte
    } else {
        if ($currentString.Length -ge 4) {
            $strings += $currentString
        }
        $currentString = ""
    }
}

# Filter interesting strings
$keywords = @('pass', 'key', 'serial', 'code', 'correct', 'wrong', 'success', 'fail', 'enter', 'login', 'valid')

Write-Host "INTERESTING STRINGS FOUND:" -ForegroundColor Green
Write-Host ""

foreach ($str in $strings) {
    $lower = $str.ToLower()
    $isInteresting = $false
    
    foreach ($keyword in $keywords) {
        if ($lower -contains $keyword) {
            $isInteresting = $true
            break
        }
    }
    
    # Also show any string that looks like a password (alphanumeric, 5-20 chars)
    if ($str -match '^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};:,.<>?]{5,20}$') {
        $isInteresting = $true
    }
    
    if ($isInteresting) {
        Write-Host "  $str" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=== NEXT STEPS ===" -ForegroundColor Cyan
Write-Host "1. Look for suspicious strings above" -ForegroundColor White
Write-Host "2. Try them as passwords in the crackme" -ForegroundColor White
Write-Host "3. Or use dnSpy for deeper analysis" -ForegroundColor White
Write-Host ""

# Also save to file
$strings | Out-File "all_strings.txt"
Write-Host "All strings saved to: all_strings.txt" -ForegroundColor Gray
Write-Host ""


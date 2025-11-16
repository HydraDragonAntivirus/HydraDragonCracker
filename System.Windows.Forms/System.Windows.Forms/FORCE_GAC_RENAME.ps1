# Force GAC DLL Rename with TrustedInstaller bypass

# Requires Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: Must run as Administrator!" -ForegroundColor Red
    exit 1
}

$gacPaths = @(
    "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll",
    "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Drawing\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Drawing.dll"
)

Write-Host "=== FORCE GAC RENAME ===" -ForegroundColor Cyan
Write-Host ""

foreach ($dllPath in $gacPaths) {
    $dllName = Split-Path $dllPath -Leaf
    $backupPath = "$dllPath.backup"
    
    Write-Host "Processing: $dllName" -ForegroundColor Yellow
    
    if (-not (Test-Path $dllPath)) {
        Write-Host "  Already renamed or not found" -ForegroundColor Gray
        continue
    }
    
    # Try direct rename first
    try {
        Move-Item -Path $dllPath -Destination $backupPath -Force -ErrorAction Stop
        Write-Host "  SUCCESS: Renamed directly" -ForegroundColor Green
        continue
    } catch {
        Write-Host "  Direct rename failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Method 2: Take ownership and change ACL
    Write-Host "  Trying ownership takeover..." -ForegroundColor Yellow
    
    try {
        # Take ownership
        $acl = Get-Acl $dllPath
        $adminGroup = New-Object System.Security.Principal.NTAccount("Administrators")
        $acl.SetOwner($adminGroup)
        Set-Acl -Path $dllPath -AclObject $acl -ErrorAction Stop
        
        # Grant full control
        $acl = Get-Acl $dllPath
        $permission = $adminGroup, "FullControl", "Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $dllPath -AclObject $acl -ErrorAction Stop
        
        # Try rename again
        Move-Item -Path $dllPath -Destination $backupPath -Force -ErrorAction Stop
        Write-Host "  SUCCESS: Renamed after ownership change" -ForegroundColor Green
        
    } catch {
        Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "  This DLL might be locked by a running process." -ForegroundColor Yellow
        Write-Host "  Try:" -ForegroundColor Yellow
        Write-Host "    1. Close all .NET applications" -ForegroundColor White
        Write-Host "    2. Restart in Safe Mode" -ForegroundColor White
        Write-Host "    3. Use LockHunter or Unlocker to force unlock" -ForegroundColor White
    }
    
    Write-Host ""
}

Write-Host "=== VERIFICATION ===" -ForegroundColor Cyan
Write-Host ""

foreach ($dllPath in $gacPaths) {
    $dllName = Split-Path $dllPath -Leaf
    $backupPath = "$dllPath.backup"
    
    if (Test-Path $backupPath) {
        Write-Host "[OK] $dllName.backup exists" -ForegroundColor Green
    }
    if (-not (Test-Path $dllPath)) {
        Write-Host "[OK] $dllName removed" -ForegroundColor Green
    }
    if ((Test-Path $dllPath) -and -not (Test-Path $backupPath)) {
        Write-Host "[FAIL] $dllName not renamed" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Press Enter to continue..."
$null = Read-Host


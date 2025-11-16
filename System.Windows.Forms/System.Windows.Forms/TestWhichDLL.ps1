Write-Host "=== Testing which System.Windows.Forms.dll is loaded ===" -ForegroundColor Cyan
Write-Host ""

# Start the process
Write-Host "Starting RikaCrackmeV1.exe..." -ForegroundColor Yellow
$proc = Start-Process ".\RikaCrackmeV1.exe" -PassThru

Start-Sleep -Seconds 2

if ($proc.HasExited) {
    Write-Host ""
    Write-Host "ERROR: Process crashed immediately!" -ForegroundColor Red
    Write-Host "Check Windows Event Viewer for details." -ForegroundColor Yellow
    exit 1
}

Write-Host "Process started (PID: $($proc.Id))" -ForegroundColor Green
Write-Host ""
Write-Host "Loaded System.Windows.Forms modules:" -ForegroundColor Yellow

try {
    $modules = (Get-Process -Id $proc.Id).Modules | Where-Object {$_.ModuleName -like "*System.Windows.Forms*"}
    
    if ($modules) {
        foreach ($module in $modules) {
            Write-Host "  Path: $($module.FileName)" -ForegroundColor White
            
            $fileInfo = Get-Item $module.FileName
            Write-Host "  Size: $($fileInfo.Length) bytes" -ForegroundColor Gray
            Write-Host "  Modified: $($fileInfo.LastWriteTime)" -ForegroundColor Gray
            
            # Check if it's our proxy DLL
            $ourDLL = Resolve-Path ".\System.Windows.Forms.dll" -ErrorAction SilentlyContinue
            if ($ourDLL -and ($module.FileName -eq $ourDLL.Path)) {
                Write-Host "  >>> THIS IS OUR PROXY DLL! [SUCCESS]" -ForegroundColor Green
            } elseif ($module.FileName -like "*GAC_MSIL*") {
                Write-Host "  >>> THIS IS GAC VERSION (NOT our proxy) [FAILED]" -ForegroundColor Red
            }
            Write-Host ""
        }
    } else {
        Write-Host "  No System.Windows.Forms.dll loaded yet (wait a moment...)" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Checking for proxy_log.txt..." -ForegroundColor Yellow
    Start-Sleep -Seconds 4
    
    if (Test-Path "proxy_log.txt") {
        Write-Host ""
        Write-Host "=== PROXY LOG FOUND! Our DLL is working! ===" -ForegroundColor Green
        Write-Host ""
        Get-Content "proxy_log.txt" | Select-Object -First 10
        Write-Host ""
        Write-Host "Full log available in: proxy_log.txt" -ForegroundColor Cyan
    } else {
        Write-Host ""
        Write-Host "No proxy_log.txt found - GAC version is being used" -ForegroundColor Red
        Write-Host ""
        Write-Host "SOLUTION: You MUST disable strong-name verification!" -ForegroundColor Yellow
        Write-Host "Run: .\BYPASS_STRONGNAME.bat as Administrator" -ForegroundColor Cyan
    }
} catch {
    Write-Host "Error reading modules: $_" -ForegroundColor Red
} finally {
    Write-Host ""
    Write-Host "Stopping process..." -ForegroundColor Yellow
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "=== Test Complete ===" -ForegroundColor Cyan


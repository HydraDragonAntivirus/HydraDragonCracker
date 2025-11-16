# Find Main() EntryPoint in RikaCrackmeV1.exe

Write-Host "=== FINDING ENTRY POINT ===" -ForegroundColor Cyan
Write-Host ""

try {
    $asmPath = ".\RikaCrackmeV1.exe"
    $asm = [System.Reflection.Assembly]::LoadFile((Resolve-Path $asmPath).Path)
    
    $entryPoint = $asm.EntryPoint
    
    if ($entryPoint) {
        Write-Host "ENTRY POINT FOUND!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Method: $($entryPoint.Name)" -ForegroundColor Yellow
        Write-Host "Class:  $($entryPoint.DeclaringType.FullName)" -ForegroundColor Yellow
        Write-Host "Module: $($entryPoint.Module.Name)" -ForegroundColor Yellow
        Write-Host ""
        
        Write-Host "=== INSTRUCTIONS ===" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1. dnSpy navigate to: $($entryPoint.DeclaringType.FullName)" -ForegroundColor White
        Write-Host "   Method: $($entryPoint.Name)()" -ForegroundColor White
        Write-Host ""
        Write-Host "2. Right click method -> Edit Method (C#)..." -ForegroundColor White
        Write-Host ""
        Write-Host "3. Add at the BEGINNING:" -ForegroundColor White
        Write-Host ""
        Write-Host "   try { var t = typeof(System.Drawing.Graphics); } catch { }" -ForegroundColor Green
        Write-Host ""
        Write-Host "4. Compile -> File -> Save Module" -ForegroundColor White
        Write-Host ""
    } else {
        Write-Host "Entry Point not found!" -ForegroundColor Red
    }
    
} catch {
    Write-Host "ERROR occurred" -ForegroundColor Red
    Write-Host $_.Exception.Message
}

$ErrorActionPreference = "Continue"
$asmPath = ".\RikaCrackmeV1.exe"

Write-Host "=== Inspecting $asmPath ===" -ForegroundColor Cyan

# Load assembly for inspection
$asm = [System.Reflection.Assembly]::LoadFile((Resolve-Path $asmPath).Path)

Write-Host "`nAssembly Full Name: $($asm.FullName)" -ForegroundColor Yellow

Write-Host "`nReferenced Assemblies:" -ForegroundColor Green
$asm.GetReferencedAssemblies() | ForEach-Object {
    if ($_.Name -like "*Windows.Forms*") {
        Write-Host "  >> $($_.FullName)" -ForegroundColor Red
    } else {
        Write-Host "  $($_.FullName)"
    }
}

Write-Host "`nEntry Point:" -ForegroundColor Green
$entry = $asm.EntryPoint
if ($entry) {
    Write-Host "  $($entry.DeclaringType.FullName)::$($entry.Name)"
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan


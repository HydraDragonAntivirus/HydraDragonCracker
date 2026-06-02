param(
    [string]$TargetDir = (Join-Path $PSScriptRoot "..\..\..\Rika Inc\Rika.NET"),
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$projectDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$proxyDll = Join-Path $projectDir "bin\$Configuration\net8.0\dnlib.dll"
$realDll = Join-Path $projectDir "dnlib.real.dll"
$targetDirResolved = (Resolve-Path $TargetDir).Path
$targetDnlib = Join-Path $targetDirResolved "dnlib.dll"
$targetReal = Join-Path $targetDirResolved "dnlib.real.dll"
$depsJson = Join-Path $targetDirResolved "RikaNET.WinUI.deps.json"

if (-not (Test-Path $proxyDll)) {
    throw "Proxy DLL not found. Build first: dotnet build `"$repoRoot\dnlib\dnlib.sln`" -c $Configuration"
}
if (-not (Test-Path $realDll)) {
    throw "Renamed real DLL not found: $realDll"
}
if (-not (Test-Path $depsJson)) {
    throw "Target deps.json not found: $depsJson"
}

$backup = Join-Path $targetDirResolved "dnlib.dll.original"
if ((Test-Path $targetDnlib) -and -not (Test-Path $backup)) {
    Copy-Item -Path $targetDnlib -Destination $backup
    Write-Host "Backed up original dnlib.dll -> $backup"
}

$depsBackup = Join-Path $targetDirResolved "RikaNET.WinUI.deps.json.original"
if ((Test-Path $depsJson) -and -not (Test-Path $depsBackup)) {
    Copy-Item -Path $depsJson -Destination $depsBackup
    Write-Host "Backed up RikaNET.WinUI.deps.json -> $depsBackup"
}

Copy-Item -Path $proxyDll -Destination $targetDnlib -Force
Copy-Item -Path $realDll -Destination $targetReal -Force

& (Join-Path $PSScriptRoot "PatchDepsForDnlibProxy.ps1") -DepsJsonPath $depsJson

Write-Host "Installed dnlib proxy into $targetDirResolved"
Write-Host "Run RikaNET.WinUI.exe and check dnlib_proxy_log.txt in the same folder."

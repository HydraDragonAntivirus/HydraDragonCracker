# Process Injection - Inject proxy DLL into running crackme
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Injector {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

Write-Host "=== PROXY DLL INJECTOR ===" -ForegroundColor Cyan
Write-Host ""

# Start crackme suspended
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = ".\RikaCrackmeV1.exe"
$psi.UseShellExecute = $false
$psi.WorkingDirectory = (Get-Location).Path

Write-Host "[1/5] Starting crackme..." -ForegroundColor Yellow
$proc = [System.Diagnostics.Process]::Start($psi)
Write-Host "  PID: $($proc.Id)" -ForegroundColor Green

Start-Sleep -Milliseconds 500

# Prepare DLL path
$dllPath = Join-Path (Get-Location) "System.Windows.Forms.dll"
if (-not (Test-Path $dllPath)) {
    Write-Host "[ERROR] System.Windows.Forms.dll not found!" -ForegroundColor Red
    Stop-Process -Id $proc.Id -Force
    exit 1
}

Write-Host "[2/5] Opening process handle..." -ForegroundColor Yellow
$PROCESS_ALL_ACCESS = 0x1F0FFF
$hProcess = [Injector]::OpenProcess($PROCESS_ALL_ACCESS, $false, $proc.Id)

if ($hProcess -eq [IntPtr]::Zero) {
    Write-Host "[ERROR] Cannot open process! Run as Administrator?" -ForegroundColor Red
    Stop-Process -Id $proc.Id -Force
    exit 1
}

Write-Host "[3/5] Allocating memory in target process..." -ForegroundColor Yellow
$MEM_COMMIT = 0x1000
$PAGE_READWRITE = 0x04
$pathBytes = [System.Text.Encoding]::Unicode.GetBytes($dllPath + "`0")
$pRemoteMemory = [Injector]::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]$pathBytes.Length, $MEM_COMMIT, $PAGE_READWRITE)

if ($pRemoteMemory -eq [IntPtr]::Zero) {
    Write-Host "[ERROR] Cannot allocate memory!" -ForegroundColor Red
    [Injector]::CloseHandle($hProcess)
    Stop-Process -Id $proc.Id -Force
    exit 1
}

Write-Host "[4/5] Writing DLL path to process memory..." -ForegroundColor Yellow
$bytesWritten = 0
$result = [Injector]::WriteProcessMemory($hProcess, $pRemoteMemory, $pathBytes, [uint32]$pathBytes.Length, [ref]$bytesWritten)

if (-not $result) {
    Write-Host "[ERROR] Cannot write memory!" -ForegroundColor Red
    [Injector]::CloseHandle($hProcess)
    Stop-Process -Id $proc.Id -Force
    exit 1
}

Write-Host "[5/5] Creating remote thread (LoadLibrary)..." -ForegroundColor Yellow
$hKernel32 = [Injector]::GetModuleHandle("kernel32.dll")
$pLoadLibrary = [Injector]::GetProcAddress($hKernel32, "LoadLibraryW")

$hThread = [Injector]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $pLoadLibrary, $pRemoteMemory, 0, [IntPtr]::Zero)

if ($hThread -eq [IntPtr]::Zero) {
    Write-Host "[ERROR] Cannot create remote thread!" -ForegroundColor Red
    [Injector]::CloseHandle($hProcess)
    Stop-Process -Id $proc.Id -Force
    exit 1
}

Write-Host ""
Write-Host "=== SUCCESS! ===" -ForegroundColor Green
Write-Host "Proxy DLL injected into PID $($proc.Id)" -ForegroundColor Green
Write-Host ""
Write-Host "Waiting 10 seconds for analysis..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

Write-Host ""
Write-Host "Checking for logs..." -ForegroundColor Cyan
if (Test-Path "proxy_log.txt") {
    Write-Host ""
    Write-Host "=== PROXY LOG FOUND! ===" -ForegroundColor Green
    Get-Content "proxy_log.txt"
} else {
    Write-Host "No proxy_log.txt - check PROXY_ERROR.txt" -ForegroundColor Yellow
}

[Injector]::CloseHandle($hThread)
[Injector]::CloseHandle($hProcess)

Write-Host ""
Write-Host "Press any key to terminate crackme..." -ForegroundColor Gray
$null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue


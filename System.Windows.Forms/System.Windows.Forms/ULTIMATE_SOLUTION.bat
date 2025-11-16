@echo off
echo ================================================
echo  ULTIMATE PROXY DLL INJECTION
echo ================================================
echo.
echo This combines:
echo 1. GAC DLL rename (forces our DLL)
echo 2. Process injection (after unpack)
echo 3. Auto-restore GAC
echo.
echo REQUIRES ADMINISTRATOR!
echo.
pause

cd /d "%~dp0"

set GAC_PATH=C:\WINDOWS\Microsoft.NET\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll
set BACKUP_PATH=%GAC_PATH%.BACKUP_TEMP

echo.
echo [1/6] Backing up GAC DLL...
move /Y "%GAC_PATH%" "%BACKUP_PATH%"
if %ERRORLEVEL% NEQ 0 (
    echo FAILED! Run as Administrator!
    pause
    exit /b 1
)
echo SUCCESS

echo.
echo [2/6] Starting crackme...
start "" RikaCrackmeV1.exe

echo Waiting for crackme to initialize (3 seconds)...
timeout /t 3 /nobreak >nul

echo.
echo [3/6] Finding crackme process...
for /f "tokens=2" %%i in ('tasklist /FI "IMAGENAME eq RikaCrackmeV1.exe" /FO LIST ^| find "PID:"') do set PID=%%i

if "%PID%"=="" (
    echo ERROR: Crackme not running!
    move /Y "%BACKUP_PATH%" "%GAC_PATH%"
    pause
    exit /b 1
)

echo Found PID: %PID%

echo.
echo [4/6] Injecting proxy DLL...
powershell -ExecutionPolicy Bypass -Command "& { $dllPath = (Resolve-Path 'System.Windows.Forms.dll').Path; Write-Host 'Injecting: ' $dllPath; [System.Reflection.Assembly]::LoadFile($dllPath); Write-Host 'Injection attempt complete' }"

echo.
echo [5/6] Waiting for analysis (10 seconds)...
timeout /t 10 /nobreak

echo.
echo [6/6] Restoring GAC DLL...
taskkill /PID %PID% /F >nul 2>&1
move /Y "%BACKUP_PATH%" "%GAC_PATH%"
echo GAC restored

echo.
echo ================================================
echo  CHECKING RESULTS
echo ================================================
echo.

if exist proxy_log.txt (
    echo === PROXY LOG FOUND! ===
    type proxy_log.txt
) else if exist PROXY_LOADED.txt (
    echo === PROXY LOADED ===
    type PROXY_LOADED.txt
) else if exist PROXY_ERROR.txt (
    echo === PROXY ERROR ===
    type PROXY_ERROR.txt
) else (
    echo No logs found
)

echo.
pause


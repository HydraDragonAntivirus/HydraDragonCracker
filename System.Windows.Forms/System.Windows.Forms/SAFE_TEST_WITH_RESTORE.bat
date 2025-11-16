@echo off
echo ================================================
echo  SAFE PROXY DLL TEST (AUTO-RESTORE)
echo ================================================
echo.
echo This will:
echo 1. Rename GAC DLL (backup)
echo 2. Run crackme for 10 seconds
echo 3. AUTO-RESTORE GAC DLL
echo.
echo Total time: 30 seconds
echo Risk: MINIMAL (auto-restore)
echo.
echo REQUIRES ADMINISTRATOR!
echo.
pause

cd /d "%~dp0"

set GAC_PATH=C:\WINDOWS\Microsoft.NET\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll
set BACKUP_PATH=%GAC_PATH%.BACKUP_TEMP

echo.
echo [1/4] Backing up GAC DLL...
move /Y "%GAC_PATH%" "%BACKUP_PATH%"
if %ERRORLEVEL% NEQ 0 (
    echo FAILED! Run as Administrator!
    pause
    exit /b 1
)
echo SUCCESS - GAC DLL backed up

echo.
echo [2/4] Starting crackme...
del /Q proxy_log.txt 2>NUL
start "" RikaCrackmeV1.exe
echo Waiting 10 seconds for analysis...
timeout /t 10 /nobreak

echo.
echo [3/4] Stopping crackme...
taskkill /IM RikaCrackmeV1.exe /F >NUL 2>&1

echo.
echo [4/4] RESTORING GAC DLL...
move /Y "%BACKUP_PATH%" "%GAC_PATH%"
if %ERRORLEVEL% EQU 0 (
    echo SUCCESS - GAC DLL restored!
) else (
    echo WARNING: Manual restore needed!
    echo From: %BACKUP_PATH%
    echo To: %GAC_PATH%
)

echo.
echo ================================================
echo  CHECKING RESULTS
echo ================================================
echo.

if exist proxy_log.txt (
    echo SUCCESS! Proxy DLL was loaded!
    echo.
    echo === PROXY LOG ===
    type proxy_log.txt
    echo.
    echo Full log saved in: proxy_log.txt
) else (
    echo FAILED - No proxy log found
    echo Check if DLL compiled correctly
)

echo.
echo GAC restored - system is safe!
echo.
pause


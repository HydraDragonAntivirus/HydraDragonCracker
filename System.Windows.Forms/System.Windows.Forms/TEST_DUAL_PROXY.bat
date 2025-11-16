@echo off
echo ================================================
echo   DUAL PROXY TEST (System.Windows.Forms + System.Drawing)
echo ================================================
echo.

REM Admin check
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Please run as Administrator!
    pause
    exit /b 1
)

set "GAC_WINFORMS=C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll"
set "GAC_DRAWING=C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Drawing\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Drawing.dll"
set "BACKUP_WINFORMS=%GAC_WINFORMS%.backup"
set "BACKUP_DRAWING=%GAC_DRAWING%.backup"

echo [1/6] Renaming GAC DLLs...
move "%GAC_WINFORMS%" "%BACKUP_WINFORMS%" >nul 2>&1
if %errorLevel% equ 0 (
    echo   - System.Windows.Forms renamed
) else (
    echo   - System.Windows.Forms already renamed or error
)

move "%GAC_DRAWING%" "%BACKUP_DRAWING%" >nul 2>&1
if %errorLevel% equ 0 (
    echo   - System.Drawing renamed
) else (
    echo   - System.Drawing already renamed or error
)

echo.
echo [2/6] Cleaning old logs...
del /Q DRAWING_*.txt >nul 2>&1
del /Q PROXY_*.txt >nul 2>&1
del /Q proxy_log.txt >nul 2>&1

echo.
echo [3/6] Starting crackme...
start /B RikaCrackmeV1.exe

echo.
echo [4/6] Waiting for analysis (6 seconds)...
timeout /t 6 /nobreak >nul

echo.
echo [5/6] Stopping crackme...
taskkill /F /IM RikaCrackmeV1.exe >nul 2>&1

timeout /t 1 /nobreak >nul

echo.
echo [6/6] Checking results...
echo.

if exist DRAWING_PROXY_LOG.txt (
    echo === System.Drawing PROXY LOG ===
    type DRAWING_PROXY_LOG.txt
    echo.
) else (
    echo NO System.Drawing logs found!
)

if exist PROXY_LOADED.txt (
    echo === System.Windows.Forms PROXY LOG ===
    type PROXY_LOADED.txt
    echo.
) else (
    echo NO System.Windows.Forms logs found!
)

echo.
echo ================================================
echo   RESTORING GAC DLLs...
echo ================================================

move "%BACKUP_WINFORMS%" "%GAC_WINFORMS%" >nul 2>&1
if %errorLevel% equ 0 (
    echo   - System.Windows.Forms restored
) else (
    echo   - System.Windows.Forms restore failed or already restored
)

move "%BACKUP_DRAWING%" "%GAC_DRAWING%" >nul 2>&1
if %errorLevel% equ 0 (
    echo   - System.Drawing restored
) else (
    echo   - System.Drawing restore failed or already restored
)

echo.
echo ================================================
echo   TEST COMPLETE - System restored safely
echo ================================================
pause


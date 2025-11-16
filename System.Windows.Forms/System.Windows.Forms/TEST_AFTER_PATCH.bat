@echo off
echo ================================================
echo   TESTING PATCHED CRACKME
echo ================================================
echo.

echo Cleaning old logs...
del /Q DRAWING_*.txt PROXY_*.txt proxy_log.txt 2>nul

echo.
echo Starting crackme...
start /B RikaCrackmeV1.exe

echo.
echo Waiting 5 seconds for analysis...
timeout /t 5 /nobreak >nul

echo.
echo Stopping crackme...
taskkill /F /IM RikaCrackmeV1.exe >nul 2>&1

timeout /t 1 /nobreak >nul

echo.
echo ================================================
echo   RESULTS:
echo ================================================
echo.

if exist DRAWING_PROXY_LOG.txt (
    echo === System.Drawing Proxy Loaded! ===
    type DRAWING_PROXY_LOG.txt
    echo.
) else (
    echo No System.Drawing logs
)

if exist PROXY_LOADED.txt (
    echo === System.Windows.Forms Proxy Loaded! ===
    type PROXY_LOADED.txt
    echo.
) else (
    echo No System.Windows.Forms logs
)

echo.
pause


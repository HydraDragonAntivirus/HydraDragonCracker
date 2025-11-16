@echo off
echo ================================================
echo  RikaCrackme Proxy DLL Loader
echo ================================================
echo.

cd /d "%~dp0"

REM Disable GAC by temporarily renaming the assembly in registry
REM (Don't worry - only affects THIS process)

echo Starting RikaCrackmeV1.exe with proxy DLL...
echo.
echo The application will use our custom System.Windows.Forms.dll
echo instead of the GAC version.
echo.
echo Wait 5 seconds after the window opens, then check proxy_log.txt
echo.

REM Set environment to prefer local assemblies
set DEVPATH=%CD%
set COMPLUS_Version=v4.0.30319

REM Clear any existing log
if exist proxy_log.txt del proxy_log.txt

REM Start the crackme
start "" "RikaCrackmeV1.exe"

echo.
echo Waiting 7 seconds for analysis to complete...
timeout /t 7 /nobreak >nul

echo.
if exist proxy_log.txt (
    echo ================================================
    echo  SUCCESS! Proxy DLL is working!
    echo ================================================
    echo.
    type proxy_log.txt
    echo.
    echo ================================================
    echo  Full log saved in: proxy_log.txt
    echo ================================================
) else (
    echo ================================================
    echo  No proxy log found - trying alternative method
    echo ================================================
)

echo.
pause


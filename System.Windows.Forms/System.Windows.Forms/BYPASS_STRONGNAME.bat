@echo off
echo ============================================
echo  STRONG-NAME VERIFICATION BYPASS
echo ============================================
echo.
echo This MUST run as ADMINISTRATOR!
echo.
echo Right-click this file and select:
echo  "Run as administrator"
echo.
pause

cd /d "%~dp0"

echo.
echo Running sn.exe to disable verification...
echo.

"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\sn.exe" -Vr System.Windows.Forms,b77a5c561934e089

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================
    echo  SUCCESS!
    echo ============================================
    echo.
    echo Strong-name verification has been disabled.
    echo Now you can run RikaCrackmeV1.exe
    echo.
) else (
    echo.
    echo ============================================
    echo  FAILED!
    echo ============================================
    echo.
    echo Make sure you ran this as ADMINISTRATOR!
    echo.
)

pause


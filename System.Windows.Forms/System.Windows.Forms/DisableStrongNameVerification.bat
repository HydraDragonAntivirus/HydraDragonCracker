@echo off
echo ==================================================
echo Strong-Name Verification Disabler for System.Windows.Forms
echo ==================================================
echo.
echo This script requires ADMINISTRATOR privileges!
echo.
pause

cd /d "%~dp0"

"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\sn.exe" -Vr System.Windows.Forms,b77a5c561934e089

if %ERRORLEVEL% EQU 0 (
    echo.
    echo SUCCESS! Strong-name verification disabled.
    echo You can now run RikaCrackmeV1.exe with the proxy DLL.
) else (
    echo.
    echo FAILED! Make sure to run this as Administrator.
)

echo.
pause


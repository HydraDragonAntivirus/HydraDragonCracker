@echo off
echo ================================================
echo  INSTALL PROXY DLL TO GAC
echo ================================================
echo.
echo This will install our proxy DLL to the GAC.
echo Since it has the same version, it will REPLACE
echo the original temporarily.
echo.
echo REQUIRES ADMINISTRATOR!
echo.
pause

cd /d "%~dp0"

echo.
echo Installing to GAC...
echo.

"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\gacutil.exe" /i "System.Windows.Forms.dll" /f

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ================================================
    echo  SUCCESS!
    echo ================================================
    echo.
    echo Proxy DLL installed to GAC.
    echo Now run: RikaCrackmeV1.exe
    echo.
    echo To UNINSTALL later:
    echo   gacutil /u System.Windows.Forms
    echo.
) else (
    echo.
    echo FAILED! Make sure you run as Administrator!
)

pause


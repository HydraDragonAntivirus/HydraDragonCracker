@echo off
echo ================================================
echo  RENAME GAC DLL (TEMPORARY)
echo ================================================
echo.
echo This will TEMPORARILY rename the GAC DLL
echo so Windows MUST use our proxy DLL.
echo.
echo REQUIRES ADMINISTRATOR!
echo.
pause

cd /d "%~dp0"

set GAC_PATH=C:\WINDOWS\Microsoft.NET\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll
set BACKUP_PATH=%GAC_PATH%.BACKUP

if exist "%BACKUP_PATH%" (
    echo.
    echo Backup exists! Restoring GAC DLL...
    move /Y "%BACKUP_PATH%" "%GAC_PATH%"
    if %ERRORLEVEL% EQU 0 (
        echo SUCCESS! GAC DLL restored.
    ) else (
        echo FAILED! Check permissions.
    )
) else (
    echo.
    echo Renaming GAC DLL...
    move /Y "%GAC_PATH%" "%BACKUP_PATH%"
    if %ERRORLEVEL% EQU 0 (
        echo SUCCESS! GAC DLL renamed.
        echo.
        echo Now run: RikaCrackmeV1.exe
        echo.
        echo When done, run this script again to RESTORE.
    ) else (
        echo FAILED! Run as Administrator!
    )
)

echo.
pause


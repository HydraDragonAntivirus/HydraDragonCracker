@echo off
echo ================================================
echo  ENABLE FUSION LOG (Assembly Binding Debug)
echo ================================================
echo.
echo This will enable detailed assembly binding logs
echo to see WHY our DLL is not being loaded.
echo.
echo REQUIRES ADMINISTRATOR!
echo.
pause

reg add "HKLM\Software\Microsoft\Fusion" /v EnableLog /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Fusion" /v ForceLog /t REG_DWORD /d 1 /f  
reg add "HKLM\Software\Microsoft\Fusion" /v LogFailures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Fusion" /v LogResourceBinds /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Fusion" /v LogPath /t REG_SZ /d "C:\FusionLog" /f

if not exist "C:\FusionLog" mkdir "C:\FusionLog"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo SUCCESS! Fusion logging enabled.
    echo.
    echo Now:
    echo 1. Run RikaCrackmeV1.exe
    echo 2. Check logs in: C:\FusionLog
    echo 3. Look for System.Windows.Forms binding
    echo.
) else (
    echo FAILED! Run as Administrator!
)

pause


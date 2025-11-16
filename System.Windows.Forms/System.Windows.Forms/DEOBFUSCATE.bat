@echo off
echo ================================================
echo  DEOBFUSCATE CRACKME
echo ================================================
echo.
echo This will clean obfuscation from RikaCrackmeV1.exe
echo.
pause

cd /d "%~dp0"

echo.
echo Downloading de4dot...
powershell -Command "& {Invoke-WebRequest -Uri 'https://github.com/de4dot/de4dot/releases/download/v3.1.41592.3405/de4dot-net35-bin-3.1.41592.3405.zip' -OutFile 'de4dot.zip'; Expand-Archive -Path 'de4dot.zip' -DestinationPath '.' -Force}"

if exist "de4dot.exe" (
    echo.
    echo Running de4dot...
    de4dot.exe RikaCrackmeV1.exe
    
    if exist "RikaCrackmeV1-cleaned.exe" (
        echo.
        echo ================================================
        echo  SUCCESS!
        echo ================================================
        echo.
        echo Deobfuscated file: RikaCrackmeV1-cleaned.exe
        echo.
        echo Now open this file in dnSpy to see clean code!
        echo.
    )
) else (
    echo.
    echo de4dot download failed!
    echo Please download manually from:
    echo https://github.com/de4dot/de4dot/releases
)

pause


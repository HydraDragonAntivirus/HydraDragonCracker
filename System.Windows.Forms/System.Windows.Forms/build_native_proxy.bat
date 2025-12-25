@echo off
REM Build System.Windows.Forms native proxy DLL

echo ================================================================================
echo Building Native System.Windows.Forms Proxy DLL
echo ================================================================================
echo.

REM First, backup the existing .NET proxy DLL
if exist System.Windows.Forms.dll (
    echo [BACKUP] Renaming existing .NET System.Windows.Forms.dll to System.Windows.Forms.dll.net_backup
    move /Y System.Windows.Forms.dll System.Windows.Forms.dll.net_backup
)

REM Compile with GCC (MinGW)
echo [BUILD] Compiling with GCC...
gcc -shared -o System.Windows.Forms.dll System.Windows.Forms_proxy.c -Wl,--enable-stdcall-fixup -static-libgcc

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] GCC compilation failed!
    echo.
    echo Trying with MSVC (cl.exe)...

    REM Try MSVC
    cl /LD /Fe:System.Windows.Forms.dll System.Windows.Forms_proxy.c

    if %ERRORLEVEL% NEQ 0 (
        echo.
        echo [FATAL] Both GCC and MSVC compilation failed!
        echo.
        echo Please install one of the following:
        echo   - MinGW-w64: https://www.mingw-w64.org/
        echo   - Visual Studio Build Tools
        echo.
        pause
        exit /b 1
    )
)

echo.
echo [SUCCESS] Native proxy DLL compiled!
echo.

REM Check if orig.dll exists
if not exist orig.dll (
    echo [WARNING] orig.dll not found!
    echo.
    echo You need to rename the original System.Windows.Forms.dll to orig.dll
    echo.
    echo Suggested actions:
    echo   1. Copy from GAC:
    echo      copy "C:\WINDOWS\Microsoft.NET\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll" orig.dll
    echo.
    echo   2. Or use the backed up .NET proxy's orig.dll if it exists
    echo.
)

echo.
echo [INFO] Build complete!
echo [INFO] File created: System.Windows.Forms.dll (native proxy)
echo [INFO] Make sure orig.dll exists in the same directory!
echo.

dir /b *.dll | findstr /i "System.Windows.Forms orig"

echo.
echo ================================================================================
echo Ready to test with RikaPy.exe
echo ================================================================================
pause

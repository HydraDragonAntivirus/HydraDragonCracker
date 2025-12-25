@echo off
REM Universal DLL Proxy Builder
REM This creates a generic proxy for ANY DLL

setlocal enabledelayedexpansion

echo ================================================================================
echo          UNIVERSAL DLL PROXY BUILDER
echo ================================================================================
echo.

REM Configuration
set "TARGET_DLL=System.Windows.Forms.dll"
set "ORIGINAL_DLL=orig.dll"
set "PROXY_SOURCE=generic_proxy.c"
set "OUTPUT_DLL=System.Windows.Forms.dll"

echo [CONFIG] Target DLL: %TARGET_DLL%
echo [CONFIG] Original DLL will be renamed to: %ORIGINAL_DLL%
echo.

REM Step 1: Backup existing DLL if needed
if exist "%OUTPUT_DLL%" (
    if not exist "%OUTPUT_DLL%.backup" (
        echo [BACKUP] Backing up existing %OUTPUT_DLL%...
        copy /Y "%OUTPUT_DLL%" "%OUTPUT_DLL%.backup"
    )
)

REM Step 2: Check if orig.dll exists
if not exist "%ORIGINAL_DLL%" (
    echo [INFO] %ORIGINAL_DLL% not found
    echo.
    echo Please ensure %ORIGINAL_DLL% exists in this directory.
    echo You can copy it from GAC:
    echo   copy "C:\WINDOWS\Microsoft.NET\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll" %ORIGINAL_DLL%
    echo.
    pause
    exit /b 1
)

echo [OK] Found %ORIGINAL_DLL% (size: %~z1 bytes)
echo.

REM Step 3: Compile the generic proxy
echo [BUILD] Compiling generic proxy DLL...
echo.

gcc -shared -o "%OUTPUT_DLL%" "%PROXY_SOURCE%" -Wl,--enable-stdcall-fixup -static-libgcc 2>build_errors.txt

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Compilation failed!
    echo.
    type build_errors.txt
    echo.
    echo Make sure GCC (MinGW) is installed and in PATH.
    echo Download from: https://www.mingw-w64.org/
    pause
    exit /b 1
)

echo [SUCCESS] Compilation complete!
echo.

REM Step 4: Verify the output
if exist "%OUTPUT_DLL%" (
    echo [VERIFY] Generated DLL: %OUTPUT_DLL%
    dir "%OUTPUT_DLL%" | findstr /i "%OUTPUT_DLL%"
    echo.
) else (
    echo [ERROR] Output DLL not created!
    exit /b 1
)

echo ================================================================================
echo                           BUILD COMPLETE!
echo ================================================================================
echo.
echo Files in directory:
dir /b *.dll | findstr /i "System.Windows.Forms orig"
echo.
echo The proxy DLL will log all calls to: generic_proxy.log
echo.
echo Ready to test with RikaPy.exe!
echo ================================================================================
pause

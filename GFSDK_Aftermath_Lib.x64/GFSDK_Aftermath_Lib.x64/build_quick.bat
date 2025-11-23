@echo off
REM Quick Build Script for GFSDK_Aftermath_Lib.x64 Proxy DLL
REM This script attempts to build using MSBuild from command line

echo ========================================
echo GFSDK_Aftermath_Lib.x64 Proxy DLL - Quick Build
echo ========================================
echo.

REM Check if orig_GFSDK_Aftermath_Lib.x64.dll exists
if not exist "orig_GFSDK_Aftermath_Lib.x64.dll" (
    echo WARNING: orig_GFSDK_Aftermath_Lib.x64.dll not found!
    echo Please ensure the original DLL is backed up as orig_GFSDK_Aftermath_Lib.x64.dll
    echo.
    pause
    exit /b 1
)

REM Check if import library exists
if not exist "orig_GFSDK_Aftermath_Lib.x64.lib" (
    echo WARNING: orig_GFSDK_Aftermath_Lib.x64.lib not found!
    echo.
    echo You need to create the import library first.
    echo Please run: create_import_lib.bat
    echo.
    echo This needs to be done from a Visual Studio Developer Command Prompt.
    echo.
    pause
    exit /b 1
)

REM Try to find MSBuild
set MSBUILD_PATH=

REM Try Visual Studio 2022
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
)

if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD_PATH=C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
)

if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD_PATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
)

REM Try Visual Studio 2019
if "%MSBUILD_PATH%"=="" (
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe" (
        set "MSBUILD_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
    )
)

if "%MSBUILD_PATH%"=="" (
    echo ERROR: MSBuild not found!
    echo Please install Visual Studio 2019 or 2022
    echo Or open GFSDK_Aftermath_Lib.x64.vcxproj in Visual Studio and build manually
    pause
    exit /b 1
)

echo Found MSBuild: %MSBUILD_PATH%
echo.

REM Ask for platform
echo Select platform:
echo   1. x64 (64-bit) - Recommended for GFSDK_Aftermath_Lib.x64
echo   2. Win32 (32-bit)
echo.
set /p PLATFORM_CHOICE="Enter choice (1 or 2): "

if "%PLATFORM_CHOICE%"=="1" (
    set BUILD_PLATFORM=x64
) else if "%PLATFORM_CHOICE%"=="2" (
    set BUILD_PLATFORM=Win32
) else (
    echo Invalid choice, defaulting to x64
    set BUILD_PLATFORM=x64
)

REM Ask for configuration
echo.
echo Select configuration:
echo   1. Release - Recommended
echo   2. Debug
echo.
set /p CONFIG_CHOICE="Enter choice (1 or 2): "

if "%CONFIG_CHOICE%"=="1" (
    set BUILD_CONFIG=Release
) else if "%CONFIG_CHOICE%"=="2" (
    set BUILD_CONFIG=Debug
) else (
    echo Invalid choice, defaulting to Release
    set BUILD_CONFIG=Release
)

echo.
echo Building: %BUILD_PLATFORM% - %BUILD_CONFIG%
echo.
echo ========================================

REM Build the project
"%MSBUILD_PATH%" GFSDK_Aftermath_Lib.x64.vcxproj /p:Configuration=%BUILD_CONFIG% /p:Platform=%BUILD_PLATFORM% /m

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo BUILD SUCCESSFUL!
    echo ========================================
    echo.
    echo Output DLL location:
    echo   %BUILD_PLATFORM%\%BUILD_CONFIG%\GFSDK_Aftermath_Lib.x64.dll
    echo.
    echo To use:
    echo   1. Copy %BUILD_PLATFORM%\%BUILD_CONFIG%\GFSDK_Aftermath_Lib.x64.dll to your application directory
    echo   2. Copy orig_GFSDK_Aftermath_Lib.x64.dll to the same directory
    echo   3. Optionally copy config.ini to configure logging
    echo.
    echo The proxy DLL will forward all calls to orig_GFSDK_Aftermath_Lib.x64.dll
    echo and log operations to GFSDK_Aftermath_proxy.log if logging is enabled.
    echo.
) else (
    echo.
    echo ========================================
    echo BUILD FAILED!
    echo ========================================
    echo Please check the error messages above
    echo.
)

pause

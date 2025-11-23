@echo off
REM Create import library from orig_GFSDK_Aftermath_Lib.x64.dll
REM This allows the linker to resolve forwarded exports

echo ========================================
echo Creating Import Library for GFSDK_Aftermath_Lib.x64
echo ========================================
echo.

if not exist "orig_GFSDK_Aftermath_Lib.x64.dll" (
    echo ERROR: orig_GFSDK_Aftermath_Lib.x64.dll not found!
    echo Please ensure the original DLL is backed up as orig_GFSDK_Aftermath_Lib.x64.dll
    pause
    exit /b 1
)

if not exist "GFSDK_Aftermath_Lib.x64.def" (
    echo ERROR: GFSDK_Aftermath_Lib.x64.def not found!
    echo Please run: python extract_gfsdk_exports.py
    pause
    exit /b 1
)

REM Find lib.exe (part of Visual Studio)
set LIB_EXE=

REM Try to use lib.exe from PATH (works in Developer Command Prompt)
where lib.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set LIB_EXE=lib.exe
)

REM Try Visual Studio 2022 paths
if "%LIB_EXE%"=="" (
    for /f "delims=" %%i in ('dir /b /s "C:\Program Files\Microsoft Visual Studio\2022\*\lib.exe" 2^>nul ^| findstr "Hostx64\\x64\\lib.exe" ^| findstr /v "arm"') do (
        set LIB_EXE=%%i
        goto :found
    )
)

REM Try Visual Studio 2019 paths
if "%LIB_EXE%"=="" (
    for /f "delims=" %%i in ('dir /b /s "C:\Program Files (x86)\Microsoft Visual Studio\2019\*\lib.exe" 2^>nul ^| findstr "Hostx64\\x64\\lib.exe" ^| findstr /v "arm"') do (
        set LIB_EXE=%%i
        goto :found
    )
)

:found
if "%LIB_EXE%"=="" (
    echo ERROR: lib.exe not found!
    echo.
    echo Please run this from a Visual Studio Developer Command Prompt
    echo.
    echo To open Developer Command Prompt:
    echo   1. Open Visual Studio
    echo   2. Go to Tools ^> Command Line ^> Developer Command Prompt
    echo   3. Navigate to this directory
    echo   4. Run this script again
    echo.
    echo Alternatively, you can use the Visual Studio x64 Native Tools Command Prompt
    pause
    exit /b 1
)

echo Found lib.exe: %LIB_EXE%
echo.

REM Create import library for x64
echo Creating orig_GFSDK_Aftermath_Lib.x64.lib (x64)...
"%LIB_EXE%" /DEF:GFSDK_Aftermath_Lib.x64.def /OUT:orig_GFSDK_Aftermath_Lib.x64.lib /MACHINE:X64

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo [SUCCESS] Created orig_GFSDK_Aftermath_Lib.x64.lib
    echo ========================================
    echo.
    echo Files created:
    echo   - orig_GFSDK_Aftermath_Lib.x64.lib
    echo   - orig_GFSDK_Aftermath_Lib.x64.exp
    echo.
    echo You can now build the project in Visual Studio!
    echo.
) else (
    echo.
    echo ========================================
    echo [ERROR] Failed to create import library
    echo ========================================
    echo.
    echo Try running this script from:
    echo   Visual Studio Developer Command Prompt
    echo   (or x64 Native Tools Command Prompt)
    echo.
    pause
    exit /b 1
)

pause

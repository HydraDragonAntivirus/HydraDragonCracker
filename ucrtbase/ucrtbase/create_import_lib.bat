@echo off
REM Create import library from orig_ucrtbase.dll
REM This allows the linker to resolve forwarded exports

echo ========================================
echo Creating Import Library for orig_ucrtbase.dll
echo ========================================
echo.

if not exist "orig_ucrtbase.dll" (
    echo ERROR: orig_ucrtbase.dll not found!
    echo Please run: python prepare_build.py
    pause
    exit /b 1
)

if not exist "ucrtbase.def" (
    echo ERROR: ucrtbase.def not found!
    echo Please run: python extract_ucrtbase_exports.py
    pause
    exit /b 1
)

REM Find lib.exe (part of Visual Studio)
set LIB_EXE=

REM Try Visual Studio 2022
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\lib.exe" (
    set LIB_EXE=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\lib.exe
)

if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\lib.exe" (
    set LIB_EXE=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\lib.exe
)

REM If not found, try to use Developer Command Prompt path
if "%LIB_EXE%"=="" (
    where lib.exe >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        set LIB_EXE=lib.exe
    )
)

if "%LIB_EXE%"=="" (
    echo ERROR: lib.exe not found!
    echo Please run this from a Visual Studio Developer Command Prompt
    echo Or use the Visual Studio Developer Command Prompt to run this script
    pause
    exit /b 1
)

echo Found lib.exe
echo.

REM Create import library for x64
echo Creating orig_ucrtbase.lib (x64)...
"%LIB_EXE%" /DEF:ucrtbase.def /OUT:orig_ucrtbase.lib /MACHINE:X64

if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Created orig_ucrtbase.lib
    echo.
    echo You can now build the project in Visual Studio!
) else (
    echo [ERROR] Failed to create import library
    echo.
    echo Try running this script from:
    echo   Visual Studio Developer Command Prompt
    pause
    exit /b 1
)

echo.
echo ========================================
pause

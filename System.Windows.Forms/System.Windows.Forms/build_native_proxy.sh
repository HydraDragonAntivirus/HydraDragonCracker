#!/bin/bash
# Build System.Windows.Forms native proxy DLL

echo "================================================================================"
echo "Building Native System.Windows.Forms Proxy DLL"
echo "================================================================================"
echo

# First, backup the existing .NET proxy DLL
if [ -f "System.Windows.Forms.dll" ]; then
    echo "[BACKUP] Renaming existing .NET System.Windows.Forms.dll to System.Windows.Forms.dll.net_backup"
    mv -f System.Windows.Forms.dll System.Windows.Forms.dll.net_backup
fi

# Compile with GCC (MinGW)
echo "[BUILD] Compiling with GCC..."
gcc -shared -o System.Windows.Forms.dll System.Windows.Forms_proxy.c -Wl,--enable-stdcall-fixup -static-libgcc

if [ $? -ne 0 ]; then
    echo
    echo "[FATAL] GCC compilation failed!"
    echo
    echo "Please install MinGW-w64 or use Windows and build_native_proxy.bat"
    echo
    exit 1
fi

echo
echo "[SUCCESS] Native proxy DLL compiled!"
echo

# Check if orig.dll exists
if [ ! -f "orig.dll" ]; then
    echo "[WARNING] orig.dll not found!"
    echo
    echo "You need to rename the original System.Windows.Forms.dll to orig.dll"
    echo
    echo "Suggested action:"
    echo "  cp /c/WINDOWS/Microsoft.NET/assembly/GAC_MSIL/System.Windows.Forms/v4.0_4.0.0.0__b77a5c561934e089/System.Windows.Forms.dll orig.dll"
    echo
fi

echo
echo "[INFO] Build complete!"
echo "[INFO] File created: System.Windows.Forms.dll (native proxy)"
echo "[INFO] Make sure orig.dll exists in the same directory!"
echo

ls -lh *.dll 2>/dev/null | grep -i "System.Windows.Forms\|orig"

echo
echo "================================================================================"
echo "Ready to test with RikaPy.exe"
echo "================================================================================"

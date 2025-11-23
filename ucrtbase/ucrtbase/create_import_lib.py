#!/usr/bin/env python3
"""
Create import library from orig_ucrtbase.dll

This script creates a .lib file that the linker needs to resolve forwarded exports
"""

import subprocess
import os
import sys
from pathlib import Path

def find_lib_exe():
    """Find lib.exe from Visual Studio installation"""

    # Common Visual Studio paths
    vs_paths = [
        r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC",
        r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC",
        r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Tools\MSVC",
    ]

    for vs_path in vs_paths:
        if os.path.exists(vs_path):
            # Find the version subdirectory
            for version_dir in Path(vs_path).iterdir():
                if version_dir.is_dir():
                    lib_path = version_dir / "bin" / "Hostx64" / "x64" / "lib.exe"
                    if lib_path.exists():
                        return str(lib_path)

    # Try to find in PATH
    try:
        result = subprocess.run(["where", "lib.exe"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip().split('\n')[0]
    except:
        pass

    return None

def main():
    print("=" * 80)
    print("Creating Import Library for orig_ucrtbase.dll")
    print("=" * 80)
    print()

    script_dir = Path(__file__).parent
    os.chdir(script_dir)

    # Check required files
    if not (script_dir / "ucrtbase.def").exists():
        print("ERROR: ucrtbase.def not found!")
        print("Please run: python extract_ucrtbase_exports.py")
        return 1

    print("[1] Finding lib.exe...")
    lib_exe = find_lib_exe()

    if not lib_exe:
        print("ERROR: lib.exe not found!")
        print()
        print("Please run this script from Visual Studio Developer Command Prompt:")
        print("  1. Open 'Developer Command Prompt for VS 2022'")
        print("  2. Navigate to this directory")
        print("  3. Run: python create_import_lib.py")
        print()
        print("Or run: create_import_lib.bat from Developer Command Prompt")
        return 1

    print(f"    Found: {lib_exe}")
    print()

    # Create import library for x64
    print("[2] Creating orig_ucrtbase.lib (x64)...")

    cmd = [
        lib_exe,
        "/DEF:ucrtbase.def",
        "/OUT:orig_ucrtbase.lib",
        "/MACHINE:X64"
    ]

    print(f"    Command: {' '.join(cmd)}")
    print()

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print("    [SUCCESS] Created orig_ucrtbase.lib")

        # Check if file was created
        lib_file = script_dir / "orig_ucrtbase.lib"
        if lib_file.exists():
            print(f"    Size: {lib_file.stat().st_size:,} bytes")

        print()
        print("=" * 80)
        print("[SUCCESS] Import library created!")
        print()
        print("Next steps:")
        print("  1. The orig_ucrtbase.lib will be automatically linked")
        print("  2. Build the project in Visual Studio (Ctrl+Shift+B)")
        print("=" * 80)
        return 0
    else:
        print("    [ERROR] Failed to create import library")
        print()
        print("Output:")
        print(result.stdout)
        if result.stderr:
            print("Errors:")
            print(result.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
UCRTBASE Proxy DLL - Build Preparation Script

This script prepares the environment for building the ucrtbase.dll proxy:
1. Copies the original ucrtbase.dll from System32 to the build directory as orig_ucrtbase.dll
2. Verifies all required files are present
3. Checks that the .def file exists
"""

import os
import sys
import shutil
from pathlib import Path

def find_system_ucrtbase():
    """Find the original ucrtbase.dll in System32"""

    # Try System32
    system32 = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32'
    ucrtbase_path = system32 / 'ucrtbase.dll'

    if ucrtbase_path.exists():
        return ucrtbase_path

    # Try SysWOW64 for 32-bit on 64-bit systems
    syswow64 = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'SysWOW64'
    ucrtbase_path_wow64 = syswow64 / 'ucrtbase.dll'

    if ucrtbase_path_wow64.exists():
        return ucrtbase_path_wow64

    return None

def main():
    print("=" * 80)
    print("UCRTBASE Proxy DLL - Build Preparation")
    print("=" * 80)
    print()

    # Get script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)

    print(f"Working directory: {script_dir}")
    print()

    # Step 1: Find and copy original ucrtbase.dll
    print("[1] Looking for original ucrtbase.dll in System32...")
    system_ucrtbase = find_system_ucrtbase()

    if not system_ucrtbase:
        print("ERROR: Could not find ucrtbase.dll in System32 or SysWOW64")
        return 1

    print(f"    Found: {system_ucrtbase}")
    print(f"    Size:  {system_ucrtbase.stat().st_size:,} bytes")

    # Copy to current directory as orig_ucrtbase.dll
    orig_ucrtbase = script_dir / "orig_ucrtbase.dll"

    if orig_ucrtbase.exists():
        print(f"    Note: orig_ucrtbase.dll already exists (size: {orig_ucrtbase.stat().st_size:,} bytes)")
        print("    Skipping copy (file already exists)")
    else:
        print(f"    Copying to: {orig_ucrtbase}")
        shutil.copy2(system_ucrtbase, orig_ucrtbase)
        print("    [OK] Copied successfully")

    print()

    # Step 2: Verify required files
    print("[2] Verifying required files...")

    required_files = [
        "ucrtbase_forwarding.def",
        "dllmain.cpp",
        "pch.h",
        "pch.cpp",
        "framework.h",
        "ucrtbase.vcxproj",
        "config.ini"
    ]

    all_found = True
    for filename in required_files:
        filepath = script_dir / filename
        if filepath.exists():
            print(f"    [OK] {filename}")
        else:
            print(f"    [MISSING] {filename}")
            all_found = False

    print()

    # Step 3: Check .def file
    print("[3] Checking .def file...")
    def_file = script_dir / "ucrtbase_forwarding.def"

    if def_file.exists():
        with open(def_file, 'r') as f:
            lines = f.readlines()

        export_count = sum(1 for line in lines if '=' in line and '@' in line)
        print(f"    [OK] Found {export_count} export forwards in .def file")

        # Verify it forwards to orig_ucrtbase.dll
        if export_count > 0:
            sample_line = next(line for line in lines if '=' in line and '@' in line)
            if "orig_ucrtbase.dll" in sample_line:
                print(f"    [OK] Exports forward to orig_ucrtbase.dll")
            else:
                print(f"    [WARNING] Exports may not forward correctly")
                print(f"      Sample: {sample_line.strip()}")
    else:
        print("    [MISSING] ucrtbase_forwarding.def not found!")
        all_found = False

    print()

    # Summary
    print("=" * 80)
    if all_found and orig_ucrtbase.exists():
        print("[SUCCESS] Build preparation complete!")
        print()
        print("Next steps:")
        print("  1. Open ucrtbase.vcxproj in Visual Studio")
        print("  2. Select your target platform (x64 or Win32)")
        print("  3. Build the solution (Release or Debug)")
        print("  4. The built ucrtbase.dll will be in the x64/Release or Win32/Release folder")
        print()
        print("Usage:")
        print("  - Place your built ucrtbase.dll in the same directory as your target executable")
        print("  - Place orig_ucrtbase.dll in the same directory")
        print("  - Optionally copy config.ini to enable/disable logging")
        print("=" * 80)
        return 0
    else:
        print("[ERROR] Build preparation incomplete - please fix the errors above")
        print("=" * 80)
        return 1

if __name__ == "__main__":
    sys.exit(main())

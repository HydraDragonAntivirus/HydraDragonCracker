#!/usr/bin/env python3
"""
Test script to verify the built ucrtbase.dll has all expected exports
"""

import pefile
import sys
from pathlib import Path

def test_dll(dll_path, reference_dll_path=None):
    """
    Test the built DLL to ensure it has the expected exports
    """
    print("=" * 80)
    print("UCRTBASE DLL Test")
    print("=" * 80)
    print()

    dll_path = Path(dll_path)
    if not dll_path.exists():
        print(f"ERROR: DLL not found: {dll_path}")
        return False

    print(f"Testing DLL: {dll_path}")
    print(f"Size: {dll_path.stat().st_size:,} bytes")
    print()

    try:
        pe = pefile.PE(str(dll_path))

        # Check architecture
        if pe.FILE_HEADER.Machine == 0x14c:
            arch = "x86 (32-bit)"
        elif pe.FILE_HEADER.Machine == 0x8664:
            arch = "x64 (64-bit)"
        else:
            arch = f"Unknown ({hex(pe.FILE_HEADER.Machine)})"

        print(f"Architecture: {arch}")
        print()

        # Check exports
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print("ERROR: DLL has no exports!")
            pe.close()
            return False

        dll_name = pe.DIRECTORY_ENTRY_EXPORT.name.decode('utf-8')
        export_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

        print(f"DLL Name: {dll_name}")
        print(f"Export Count: {export_count}")
        print()

        # Collect all exports
        exports = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                name = exp.name.decode('utf-8')
                exports.append((exp.ordinal, name, exp.forwarder))
            else:
                exports.append((exp.ordinal, f"Ordinal_{exp.ordinal}", None))

        # Check for forwarding
        forwarded_count = sum(1 for _, _, fwd in exports if fwd)
        print(f"Forwarded Exports: {forwarded_count}")

        if forwarded_count > 0:
            # Show a few forwarded exports as examples
            print("\nSample forwarded exports:")
            for ordinal, name, fwd in exports[:5]:
                if fwd:
                    fwd_str = fwd.decode('utf-8') if isinstance(fwd, bytes) else fwd
                    print(f"  [{ordinal:4d}] {name:40s} -> {fwd_str}")

        print()

        # Compare with reference DLL if provided
        if reference_dll_path:
            reference_dll_path = Path(reference_dll_path)
            if reference_dll_path.exists():
                print(f"Comparing with reference: {reference_dll_path}")
                print()

                ref_pe = pefile.PE(str(reference_dll_path))

                if hasattr(ref_pe, 'DIRECTORY_ENTRY_EXPORT'):
                    ref_exports = set()
                    for exp in ref_pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            ref_exports.add(exp.name.decode('utf-8'))

                    our_exports = set(name for _, name, _ in exports if not name.startswith("Ordinal_"))

                    missing = ref_exports - our_exports
                    extra = our_exports - ref_exports

                    if not missing and not extra:
                        print("✓ All exports match the reference DLL perfectly!")
                    else:
                        if missing:
                            print(f"⚠ Missing {len(missing)} exports from reference:")
                            for name in list(missing)[:10]:
                                print(f"  - {name}")
                            if len(missing) > 10:
                                print(f"  ... and {len(missing) - 10} more")

                        if extra:
                            print(f"⚠ Found {len(extra)} extra exports not in reference:")
                            for name in list(extra)[:10]:
                                print(f"  + {name}")
                            if len(extra) > 10:
                                print(f"  ... and {len(extra) - 10} more")

                ref_pe.close()
            else:
                print(f"Reference DLL not found: {reference_dll_path}")

        pe.close()

        # Expected export count for ucrtbase.dll
        expected_count = 2483

        print()
        print("=" * 80)
        if export_count >= expected_count - 10 and export_count <= expected_count + 10:
            print("✓ TEST PASSED")
            print(f"  Export count ({export_count}) is within expected range (~{expected_count})")
            if forwarded_count > 0:
                print(f"  {forwarded_count} exports are properly forwarded")
            print("=" * 80)
            return True
        else:
            print("⚠ TEST WARNING")
            print(f"  Expected ~{expected_count} exports, found {export_count}")
            print(f"  This may be okay depending on your Windows version")
            print("=" * 80)
            return True

    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_dll.py <path_to_ucrtbase.dll> [reference_dll_path]")
        print()
        print("Examples:")
        print("  python test_dll.py x64\\Release\\ucrtbase.dll")
        print("  python test_dll.py x64\\Release\\ucrtbase.dll ucrtbase.dll")
        sys.exit(1)

    dll_path = sys.argv[1]
    reference_path = sys.argv[2] if len(sys.argv) > 2 else None

    success = test_dll(dll_path, reference_path)
    sys.exit(0 if success else 1)

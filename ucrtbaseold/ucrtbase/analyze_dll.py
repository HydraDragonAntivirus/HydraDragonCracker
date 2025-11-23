import pefile
import sys

def analyze_dll(dll_path):
    """
    Analyze DLL and show detailed information including entry point
    """
    try:
        pe = pefile.PE(dll_path)

        print("=" * 80)
        print(f"DLL Analysis: {dll_path}")
        print("=" * 80)

        # Entry Point
        print(f"\n[ENTRY POINT]")
        print(f"  Address (RVA):     0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")
        print(f"  Image Base:        0x{pe.OPTIONAL_HEADER.ImageBase:016X}")
        print(f"  Virtual Address:   0x{pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint:016X}")

        # File Info
        print(f"\n[FILE INFO]")
        print(f"  Machine:           {hex(pe.FILE_HEADER.Machine)}")
        if pe.FILE_HEADER.Machine == 0x14c:
            print(f"  Architecture:      x86 (32-bit)")
        elif pe.FILE_HEADER.Machine == 0x8664:
            print(f"  Architecture:      x64 (64-bit)")
        print(f"  Sections:          {pe.FILE_HEADER.NumberOfSections}")
        print(f"  Timestamp:         {pe.FILE_HEADER.TimeDateStamp}")

        # Optional Header
        print(f"\n[OPTIONAL HEADER]")
        print(f"  Magic:             {hex(pe.OPTIONAL_HEADER.Magic)}")
        print(f"  Subsystem:         {pe.OPTIONAL_HEADER.Subsystem}")
        print(f"  DLL Characteristics: {hex(pe.OPTIONAL_HEADER.DllCharacteristics)}")

        # Sections
        print(f"\n[SECTIONS]")
        for section in pe.sections:
            name = section.Name.decode('utf-8').rstrip('\x00')
            print(f"  {name:10s} VirtualAddress: 0x{section.VirtualAddress:08X}  "
                  f"VirtualSize: 0x{section.Misc_VirtualSize:08X}  "
                  f"RawSize: 0x{section.SizeOfRawData:08X}")

        # Exports
        print(f"\n[EXPORTS]")
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print(f"  DLL Name: {pe.DIRECTORY_ENTRY_EXPORT.name.decode('utf-8')}")
            print(f"  Number of exports: {len(pe.DIRECTORY_ENTRY_EXPORT.symbols)}")
            print(f"\n  First 20 exports:")
            for i, exp in enumerate(pe.DIRECTORY_ENTRY_EXPORT.symbols[:20]):
                if exp.name:
                    name = exp.name.decode('utf-8')
                    print(f"    [{exp.ordinal:3d}] {name}")
                else:
                    print(f"    [{exp.ordinal:3d}] (ordinal only)")
        else:
            print("  No exports found")

        # Imports
        print(f"\n[IMPORTS]")
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            print(f"  Number of imported DLLs: {len(pe.DIRECTORY_ENTRY_IMPORT)}")
            for entry in pe.DIRECTORY_ENTRY_IMPORT[:10]:
                dll_name = entry.dll.decode('utf-8')
                print(f"  - {dll_name} ({len(entry.imports)} functions)")
        else:
            print("  No imports found")

        pe.close()
        print("\n" + "=" * 80)

    except Exception as e:
        print(f"Error analyzing DLL: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    dll_path = "LX63.dll"

    if len(sys.argv) > 1:
        dll_path = sys.argv[1]

    analyze_dll(dll_path)

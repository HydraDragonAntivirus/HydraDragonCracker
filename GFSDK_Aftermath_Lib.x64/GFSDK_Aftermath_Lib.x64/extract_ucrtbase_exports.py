import pefile
import os

def extract_exports_to_def(dll_path, def_file):
    """
    Extract exports from a DLL and write them to a .def file
    """
    try:
        # Load the DLL
        pe = pefile.PE(dll_path)

        # Get the DLL name
        dll_name = os.path.basename(dll_path)
        library_name = os.path.splitext(dll_name)[0]

        # Extract all exported functions
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print(f"DLL Name: {pe.DIRECTORY_ENTRY_EXPORT.name.decode('utf-8')}")
            print(f"Number of exports: {len(pe.DIRECTORY_ENTRY_EXPORT.symbols)}")

            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    name = exp.name.decode('utf-8')
                    exports.append((exp.ordinal, name))
                else:
                    # Export by ordinal only
                    exports.append((exp.ordinal, f"Ordinal_{exp.ordinal}"))

        # Sort by ordinal
        exports.sort(key=lambda x: x[0])

        print(f"\nFound {len(exports)} exports in {dll_name}")

        # Write to .def file
        with open(def_file, 'w') as f:
            f.write(f"LIBRARY {library_name}\n")
            f.write("EXPORTS\n")

            for ordinal, name in exports:
                f.write(f"    {name} @{ordinal}\n")

        print(f"\nWritten to: {def_file}")
        print(f"Total exports: {len(exports)}")

        pe.close()
        return True

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    dll_path = r"ucrtbase.dll"
    def_file = r"ucrtbase.def"

    extract_exports_to_def(dll_path, def_file)

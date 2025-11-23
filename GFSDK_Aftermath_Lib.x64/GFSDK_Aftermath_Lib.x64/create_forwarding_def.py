import pefile
import os

def create_forwarding_def(dll_path, def_file, orig_dll_name="orig_ucrtbase.dll"):
    """
    Create a .def file that forwards all exports to another DLL
    This creates a proxy DLL that redirects all calls
    """
    try:
        # Load the DLL
        pe = pefile.PE(dll_path)

        # Get the library name from the def file name
        library_name = os.path.splitext(os.path.basename(def_file))[0]

        # Extract all exported functions
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print(f"DLL Name: {pe.DIRECTORY_ENTRY_EXPORT.name.decode('utf-8')}")
            print(f"Number of exports: {len(pe.DIRECTORY_ENTRY_EXPORT.symbols)}")

            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    name = exp.name.decode('utf-8')
                    # Forward to orig_ucrtbase.dll
                    exports.append((exp.ordinal, name))
                else:
                    # Export by ordinal only - this is rare in ucrtbase
                    exports.append((exp.ordinal, f"Ordinal_{exp.ordinal}"))

        # Sort by ordinal
        exports.sort(key=lambda x: x[0])

        print(f"\nFound {len(exports)} exports")

        # Write forwarding .def file
        with open(def_file, 'w') as f:
            f.write(f"LIBRARY {library_name}\n")
            f.write("EXPORTS\n")

            for ordinal, name in exports:
                # Create forwarding export: FunctionName=orig_ucrtbase.FunctionName @ordinal
                f.write(f"    {name}={orig_dll_name}.{name} @{ordinal}\n")

        print(f"\nWritten forwarding .def to: {def_file}")
        print(f"All exports will be forwarded to {orig_dll_name}")

        pe.close()
        return True

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    dll_path = r"ucrtbase.dll"
    def_file = r"ucrtbase_forwarding.def"

    print("Creating forwarding .def file...")
    print("This will redirect all ucrtbase.dll calls to orig_ucrtbase.dll")
    print()

    create_forwarding_def(dll_path, def_file, "orig_ucrtbase.dll")

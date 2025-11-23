import pefile
import os

def extract_imports_to_def(dll_path, def_files):
    """
    Extract imports from a DLL and write them as exports to .def files
    This is useful for creating proxy DLLs

    Args:
        dll_path: Path to the DLL file
        def_files: List of .def file paths to write
    """
    try:
        # Load the DLL
        pe = pefile.PE(dll_path)

        # Get the DLL name
        dll_name = os.path.basename(dll_path)
        library_name = os.path.splitext(dll_name)[0].upper()

        # Extract all imported functions
        imports = set()
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_import_name = entry.dll.decode('utf-8') if isinstance(entry.dll, bytes) else entry.dll
                print(f"Importing from: {dll_import_name}")

                for imp in entry.imports:
                    if imp.name:
                        # Decode the import name
                        name = imp.name.decode('utf-8') if isinstance(imp.name, bytes) else imp.name
                        imports.add(name)
                        print(f"  - {name}")
                    elif imp.ordinal:
                        # Import by ordinal
                        imports.add(f"Ordinal_{imp.ordinal}")
                        print(f"  - Ordinal {imp.ordinal}")

        # Sort imports alphabetically
        imports = sorted(imports)

        print(f"\nFound {len(imports)} unique imports in {dll_name}")

        # Write to each .def file
        for def_file in def_files:
            with open(def_file, 'w') as f:
                f.write(f"LIBRARY {library_name}\n")
                f.write("EXPORTS\n")

                for i, name in enumerate(imports, start=1):
                    f.write(f"    {name} @{i}\n")

            print(f"Written to: {def_file}")

        pe.close()
        return True

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    dll_path = r"C:\Users\victim\Documents\GitHub\HydraDragonCracker\LX63\LX63\orig.dll"
    def_files = [
        r"C:\Users\victim\Documents\GitHub\HydraDragonCracker\LX63\LX63\orig.def",
        r"C:\Users\victim\Documents\GitHub\HydraDragonCracker\LX63\LX63\LX63.def"
    ]

    extract_imports_to_def(dll_path, def_files)

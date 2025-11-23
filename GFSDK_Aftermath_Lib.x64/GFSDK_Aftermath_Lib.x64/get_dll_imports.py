import pefile
import json

def get_dll_imports(dll_path):
    """
    Extract all imports from DLL and save to JSON
    """
    try:
        pe = pefile.PE(dll_path)

        imports_data = {
            'dll_name': dll_path,
            'architecture': 'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86',
            'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
            'imports': {}
        }

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8')
                imports_data['imports'][dll_name] = []

                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8')
                        imports_data['imports'][dll_name].append({
                            'name': func_name,
                            'ordinal': imp.ordinal if imp.ordinal else None
                        })
                    elif imp.ordinal:
                        imports_data['imports'][dll_name].append({
                            'name': f'Ordinal_{imp.ordinal}',
                            'ordinal': imp.ordinal
                        })

        # Save to JSON
        json_path = dll_path.replace('.dll', '_imports.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(imports_data, f, indent=2)

        print(f"✓ Imports saved to: {json_path}")

        # Print summary
        print(f"\n{'='*60}")
        print(f"DLL: {dll_path}")
        print(f"Architecture: {imports_data['architecture']}")
        print(f"Entry Point: {imports_data['entry_point']}")
        print(f"Total DLLs imported: {len(imports_data['imports'])}")
        print(f"{'='*60}\n")

        for dll, funcs in imports_data['imports'].items():
            print(f"  {dll}: {len(funcs)} functions")

        pe.close()
        return imports_data

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    import sys

    dll_path = "LX63.dll"
    if len(sys.argv) > 1:
        dll_path = sys.argv[1]

    get_dll_imports(dll_path)

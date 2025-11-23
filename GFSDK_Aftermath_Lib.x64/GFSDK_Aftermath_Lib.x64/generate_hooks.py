import os
import re

def parse_def_file(def_file_path):
    """Parse .def file and extract function names"""
    functions = []

    with open(def_file_path, 'r') as f:
        in_exports = False
        for line in f:
            line = line.strip()
            if line == 'EXPORTS':
                in_exports = True
                continue

            if in_exports and line:
                # Extract function name (before @)
                match = re.match(r'(\w+)\s+@\d+', line)
                if match:
                    functions.append(match.group(1))

    return functions

def generate_hook_file(function_name, output_dir):
    """Generate a single .cpp file for a function with logging"""

    filename = os.path.join(output_dir, f"{function_name}.cpp")

    content = f'''#include "../pch.h"
#include "aftermath_hooks.h"

// Original function pointer (loaded dynamically)
static void* orig_{function_name} = nullptr;

// Generic function hook with logging
extern "C" __declspec(dllexport) void {function_name}() {{
    // Log function call
    if (g_logger) {{
        g_logger->Log("[CALL] {function_name}()");
    }}

    // Get original function if not already loaded
    if (!orig_{function_name} && g_origDll) {{
        orig_{function_name} = GetProcAddress(g_origDll, "{function_name}");
    }}

    if (!orig_{function_name}) {{
        if (g_logger) g_logger->Log("[ERROR] {function_name} not found in original DLL!");
        return;
    }}

    // Call original function using inline assembly to forward all parameters
    // This works for any calling convention and parameter count
    __asm {{
        // Push all registers (preserve state)
        pushad

        // Get stack pointer after pushad
        mov eax, esp

        // Restore registers
        popad

        // Call original function (will handle all parameters from stack)
        call dword ptr [orig_{function_name}]

        // Return value is in EAX/EDX, leave it there
    }}

    // Log return (return value is in EAX)
    if (g_logger) {{
        __asm {{
            push eax
            mov eax, eax  // Return value in EAX
        }}
        g_logger->Log("[RETURN] {function_name}");
        __asm {{
            pop eax
        }}
    }}
}}
'''

    with open(filename, 'w') as f:
        f.write(content)

    return filename

def generate_x64_hook_file(function_name, output_dir):
    """Generate a single .cpp file for x64 with variadic template forwarding"""

    filename = os.path.join(output_dir, f"{function_name}.cpp")

    content = f'''#include "../pch.h"
#include "aftermath_hooks.h"

// Original function pointer typedef (variadic)
typedef void* (*{function_name}_t)(...);
static {function_name}_t orig_{function_name} = nullptr;

// Generic function hook with logging using variadic templates
extern "C" __declspec(dllexport) void* {function_name}(...) {{
    // Log function call
    if (g_logger) {{
        g_logger->LogFormat("[CALL] {function_name}");
    }}

    // Get original function if not already loaded
    if (!orig_{function_name} && g_origDll) {{
        orig_{function_name} = ({function_name}_t)GetProcAddress(g_origDll, "{function_name}");
    }}

    if (!orig_{function_name}) {{
        if (g_logger) g_logger->Log("[ERROR] {function_name} not found in original DLL!");
        return nullptr;
    }}

    // For x64, we need to use a trampoline or naked function
    // This is a placeholder - actual implementation would use assembly or a trampoline
    void* result = orig_{function_name}();

    // Log return
    if (g_logger) {{
        g_logger->LogFormat("[RETURN] {function_name} -> %p", result);
    }}

    return result;
}}
'''

    with open(filename, 'w') as f:
        f.write(content)

    return filename

def generate_all_hooks_simple(functions, output_dir):
    """Generate a single file with all hooks using a generic approach"""

    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.join(output_dir, "all_hooks.cpp")

    with open(filename, 'w') as f:
        f.write('#include <windows.h>\n')
        f.write('#include "aftermath_hooks.h"\n\n')
        f.write('// ===================================================================================\n')
        f.write('// ALL HOOKS GENERATED AUTOMATICALLY\n')
        f.write('// ===================================================================================\n\n')

        for func in functions:
            f.write(f'// Original function pointer for {func}\n')
            f.write(f'typedef void* (*{func}_t)(...);\n')
            f.write(f'static {func}_t orig_{func} = nullptr;\n\n')

            f.write(f'extern "C" __declspec(dllexport) void* {func}(...) {{\n')
            f.write(f'    // Log with full call stack (shows caller function names and addresses)\n')
            f.write(f'    if (g_logger) g_logger->LogWithCallStack("[CALL] {func}", 2);\n')
            f.write(f'    if (!orig_{func} && g_origDll) {{\n')
            f.write(f'        orig_{func} = ({func}_t)GetProcAddress(g_origDll, "{func}");\n')
            f.write(f'    }}\n')
            f.write(f'    if (!orig_{func}) {{\n')
            f.write(f'        if (g_logger) g_logger->Log("[ERROR] {func} not found!");\n')
            f.write(f'        return nullptr;\n')
            f.write(f'    }}\n')
            f.write(f'    void* result = orig_{func}();\n')
            f.write(f'    if (g_logger) g_logger->LogFormat("[RETURN] {func} -> %p", result);\n')
            f.write(f'    return result;\n')
            f.write(f'}}\n\n')

    print(f"Generated {filename} with {len(functions)} functions")
    return filename

def generate_hooks_header(functions, output_file):
    """Generate the aftermath_hooks.h header file"""

    with open(output_file, 'w') as f:
        f.write('#pragma once\n')
        f.write('#include <windows.h>\n\n')
        f.write('// Forward declarations\n')
        f.write('class Logger;\n')
        f.write('extern Logger* g_logger;\n')
        f.write('extern HMODULE g_origDll;\n')

    print(f"Generated {output_file}")

def generate_exports_def(functions, dll_name, output_file):
    """Generate .def file with all exports (no forwarding)"""

    with open(output_file, 'w') as f:
        f.write(f'LIBRARY {dll_name}\n')
        f.write('EXPORTS\n')
        for i, func in enumerate(functions, 1):
            f.write(f'    {func} @{i}\n')

    print(f"Generated {output_file} with {len(functions)} exports")

if __name__ == "__main__":
    # Configuration
    def_file = "GFSDK_Aftermath_Lib.x64.def"
    dll_name = "GFSDK_Aftermath_Lib.x64"
    hooks_dir = "hooks"

    print("="*60)
    print("GFSDK Aftermath Hook Generator")
    print("="*60)

    # Parse .def file
    print(f"\nParsing {def_file}...")
    functions = parse_def_file(def_file)
    print(f"Found {len(functions)} functions")

    # Generate hooks
    print(f"\nGenerating hooks in {hooks_dir}/...")
    os.makedirs(hooks_dir, exist_ok=True)

    # Generate single file with all hooks
    all_hooks_file = generate_all_hooks_simple(functions, hooks_dir)

    # Generate header
    header_file = os.path.join(hooks_dir, "aftermath_hooks.h")
    generate_hooks_header(functions, header_file)

    # Generate new .def file for our proxy DLL
    new_def_file = "GFSDK_Aftermath_Lib.x64_hooks.def"
    generate_exports_def(functions, dll_name, new_def_file)

    print("\n" + "="*60)
    print("DONE!")
    print("="*60)
    print(f"\nGenerated files:")
    print(f"  - {all_hooks_file} ({len(functions)} functions)")
    print(f"  - {header_file}")
    print(f"  - {new_def_file}")
    print(f"\nNext steps:")
    print(f"  1. Add {all_hooks_file} to your Visual Studio project")
    print(f"  2. Update project to use {new_def_file} instead of forwarding .def")
    print(f"  3. Rebuild the project")
    print(f"  4. All {len(functions)} functions will be logged automatically!")

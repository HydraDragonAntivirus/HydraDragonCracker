#!/usr/bin/env python3
"""
===================================================================================
       C++ SOURCE CODE EXTRACTOR - COMPREHENSIVE REVERSE ENGINEERING
===================================================================================
Extracts C++ source code, functions, classes, and symbols from compiled binaries.
Called by the C++ proxy DLL to perform deep analysis.

This is the C++ equivalent of the Nuitka Python extractor.
"""

import sys
import os
import struct
import re
import json
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from collections import defaultdict


class CPPSourceExtractor:
    def __init__(self):
        self.exe_dir = Path(os.getcwd())
        self.output_dir = self.exe_dir / "Extracted_CPP_Source_Code"
        self.symbols = {}
        self.strings = {}
        self.functions = {}
        self.classes = {}
        
    def create_directories(self):
        """Create output directory structure"""
        (self.output_dir).mkdir(exist_ok=True)
        (self.output_dir / "Shaders").mkdir(exist_ok=True)
        (self.output_dir / "CPP_SOURCE").mkdir(exist_ok=True)
        (self.output_dir / "HEADERS").mkdir(exist_ok=True)
        (self.output_dir / "BINARY_ANALYSIS").mkdir(exist_ok=True)
        (self.output_dir / "RECONSTRUCTED_CODE").mkdir(exist_ok=True)
        (self.output_dir / "DISASSEMBLY").mkdir(exist_ok=True)
        
    def extract_shader(self):
        """Extract shader source code from temp file"""
        temp_file = self.exe_dir / "temp_shader_data.bin"
        
        if not temp_file.exists():
            return
        
        try:
            with open(temp_file, 'rb') as f:
                shader_data = f.read()
            
            counter = self.get_shader_counter()
            
            shader_file = self.output_dir / "Shaders" / f"shader_{counter:04d}.hlsl"
            with open(shader_file, 'wb') as f:
                header = f"""// ============================================
// EXTRACTED SHADER SOURCE CODE
// ============================================
// Capture Index: {counter}
// Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
// Size: {len(shader_data)} bytes
// ============================================

""".encode('utf-8')
                f.write(header)
                f.write(shader_data)
            
            raw_file = self.output_dir / "Shaders" / f"shader_{counter:04d}_raw.bin"
            with open(raw_file, 'wb') as f:
                f.write(shader_data)
            
            temp_file.unlink()
            print(f"[CPP-EXTRACT] Extracted shader: {shader_file.name}")
            
        except Exception as e:
            self.log_error(f"Shader extraction error: {e}")
    
    def get_shader_counter(self):
        """Get and increment shader counter"""
        counter_file = self.output_dir / "Shaders" / ".counter"
        counter = 1
        
        if counter_file.exists():
            try:
                with open(counter_file, 'r') as f:
                    counter = int(f.read().strip()) + 1
            except:
                counter = 1
        
        with open(counter_file, 'w') as f:
            f.write(str(counter))
        
        return counter
    
    def analyze_executable(self):
        """Deep analysis of the main executable"""
        exe_files = list(self.exe_dir.glob("*.exe"))
        
        if not exe_files:
            print("[CPP-EXTRACT] No .exe files found in the current directory.")
            return None
        
        main_exe = exe_files[0]
        print(f"[CPP-EXTRACT] Analyzing: {main_exe.name}")
        
        analysis = {
            'file_path': str(main_exe),
            'file_name': main_exe.name,
            'file_size': main_exe.stat().st_size,
            'timestamp': datetime.now().isoformat(),
            'pe_analysis': self.analyze_pe_structure(main_exe),
            'strings': self.extract_strings(main_exe),
            'symbols': self.extract_symbols(main_exe),
            'functions': self.extract_functions(main_exe),
            'classes': self.extract_classes(main_exe),
            'imports': self.extract_imports(main_exe),
            'exports': self.extract_exports(main_exe)
        }
        
        return analysis
    
    def analyze_pe_structure(self, exe_path):
        """Analyze PE (Portable Executable) structure"""
        try:
            with open(exe_path, 'rb') as f:
                # DOS header
                dos_header = f.read(64)
                if dos_header[:2] != b'MZ':
                    return {'error': 'Not a valid PE file'}
                
                # PE offset
                pe_offset = struct.unpack('<I', dos_header[60:64])[0]
                f.seek(pe_offset)
                
                # PE signature
                pe_sig = f.read(4)
                if pe_sig != b'PE\x00\x00':
                    return {'error': 'Invalid PE signature'}
                
                # COFF header
                coff_header = f.read(20)
                machine = struct.unpack('<H', coff_header[0:2])[0]
                num_sections = struct.unpack('<H', coff_header[2:4])[0]
                timestamp = struct.unpack('<I', coff_header[4:8])[0]
                
                # Optional header
                optional_header_size = struct.unpack('<H', coff_header[16:18])[0]
                optional_header = f.read(optional_header_size)
                
                # Section headers
                sections = []
                for i in range(num_sections):
                    section_data = f.read(40)
                    if len(section_data) == 40:
                        name = section_data[:8].rstrip(b'\x00').decode('utf-8', errors='ignore')
                        virtual_size = struct.unpack('<I', section_data[8:12])[0]
                        virtual_addr = struct.unpack('<I', section_data[12:16])[0]
                        raw_size = struct.unpack('<I', section_data[16:20])[0]
                        raw_ptr = struct.unpack('<I', section_data[20:24])[0]
                        characteristics = struct.unpack('<I', section_data[36:40])[0]
                        
                        sections.append({
                            'name': name,
                            'virtual_size': virtual_size,
                            'virtual_address': virtual_addr,
                            'raw_size': raw_size,
                            'raw_pointer': raw_ptr,
                            'characteristics': hex(characteristics),
                            'executable': bool(characteristics & 0x20000000),
                            'readable': bool(characteristics & 0x40000000),
                            'writable': bool(characteristics & 0x80000000)
                        })
                
                return {
                    'machine_type': hex(machine),
                    'num_sections': num_sections,
                    'timestamp': timestamp,
                    'sections': sections
                }
        
        except Exception as e:
            return {'error': str(e)}
    
    def extract_strings(self, exe_path):
        """Extract all meaningful strings from binary"""
        strings = {
            'urls': [],
            'file_paths': [],
            'function_patterns': [],
            'class_patterns': [],
            'api_calls': [],
            'error_messages': [],
            'all_strings': []
        }
        
        try:
            with open(exe_path, 'rb') as f:
                content = f.read()
            
            # ASCII strings
            ascii_pattern = rb'[ -~]{4,}'
            for match in re.finditer(ascii_pattern, content):
                string_val = match.group().decode('ascii', errors='ignore')
                self.categorize_string(string_val, strings)
            
            # Unicode strings (UTF-16LE)
            unicode_pattern = rb'(?:[\x20-\x7E]\x00){4,}'
            for match in re.finditer(unicode_pattern, content):
                try:
                    string_val = match.group().decode('utf-16le', errors='ignore')
                    self.categorize_string(string_val, strings)
                except:
                    pass
        
        except Exception as e:
            strings['error'] = str(e)
        
        return strings
    
    def categorize_string(self, string_val, strings_dict):
        """Categorize extracted strings"""
        if len(string_val) > 200:  # Too long
            return
        
        string_lower = string_val.lower()
        
        # URLs
        if string_val.startswith(('http://', 'https://', 'ftp://')):
            strings_dict['urls'].append(string_val)
        
        # File paths
        elif ('\\' in string_val or '/' in string_val) and len(string_val) > 3:
            if any(ext in string_lower for ext in ['.dll', '.exe', '.txt', '.log', '.cfg', '.ini']):
                strings_dict['file_paths'].append(string_val)
        
        # Function patterns (C++ naming conventions)
        elif '::' in string_val:  # C++ namespace/class member
            strings_dict['function_patterns'].append(string_val)
        
        # Class patterns (starts with uppercase)
        elif len(string_val) > 2 and string_val[0].isupper() and '::' in string_val:
            strings_dict['class_patterns'].append(string_val)
        
        # Windows API calls
        elif any(api in string_val for api in ['CreateFile', 'ReadFile', 'WriteFile', 'GetProcAddress']):
            strings_dict['api_calls'].append(string_val)
        
        # Error messages
        elif any(keyword in string_lower for keyword in ['error', 'failed', 'exception', 'invalid']):
            strings_dict['error_messages'].append(string_val)
        
        # Add to all strings
        if string_val not in strings_dict['all_strings']:
            strings_dict['all_strings'].append(string_val)
    
    def extract_symbols(self, exe_path):
        """Extract symbols using various methods"""
        symbols = {
            'function_symbols': [],
            'class_symbols': [],
            'variable_symbols': [],
            'vtable_symbols': []
        }
        
        # Try using dumpbin (if available on Windows)
        dumpbin_symbols = self.extract_symbols_dumpbin(exe_path)
        if dumpbin_symbols:
            symbols.update(dumpbin_symbols)
        
        # Try using objdump (if available)
        objdump_symbols = self.extract_symbols_objdump(exe_path)
        if objdump_symbols:
            for key in objdump_symbols:
                if key in symbols:
                    symbols[key].extend(objdump_symbols[key])
                else:
                    symbols[key] = objdump_symbols[key]
        
        # Pattern-based symbol extraction from strings
        pattern_symbols = self.extract_symbols_patterns(exe_path)
        if pattern_symbols:
            for key in pattern_symbols:
                if key in symbols:
                    symbols[key].extend(pattern_symbols[key])
                else:
                    symbols[key] = pattern_symbols[key]
        
        # Remove duplicates
        for key in symbols:
            if isinstance(symbols[key], list):
                symbols[key] = sorted(list(set(symbols[key])))
        
        return symbols
    
    def extract_symbols_dumpbin(self, exe_path):
        """Extract symbols using dumpbin (Visual Studio tool)"""
        if shutil.which("dumpbin") is None:
            return None
        try:
            result = subprocess.run(
                ['dumpbin', '/SYMBOLS', str(exe_path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
            
            if result.returncode != 0:
                return None
            
            symbols = {
                'function_symbols': [],
                'class_symbols': []
            }
            
            for line in result.stdout.splitlines():
                # Parse dumpbin symbol output
                if 'SECT' in line and 'External' in line:
                    parts = line.split('|')
                    if len(parts) > 1:
                        symbol_name = parts[1].strip()
                        if '()' in symbol_name:
                             symbols['function_symbols'].append(symbol_name.replace('()',''))
                        elif '::' in symbol_name:
                            symbols['class_symbols'].append(symbol_name)

            return symbols
        except Exception:
            return None
    
    def extract_symbols_objdump(self, exe_path):
        """Extract symbols using objdump (MinGW/Linux tool)"""
        if shutil.which("objdump") is None:
            return None
        try:
            result = subprocess.run(
                ['objdump', '-t', str(exe_path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
            
            if result.returncode != 0:
                return None
            
            symbols = {
                'function_symbols': [],
                'class_symbols': []
            }
            
            for line in result.stdout.splitlines():
                if '.text' in line:  # Code section
                    parts = line.split()
                    if len(parts) > 3:
                        symbol_name = parts[-1]
                        demangled = self.demangle_cpp_name(symbol_name)
                        if demangled:
                            if '::' in demangled:
                                symbols['class_symbols'].append(demangled)
                            else:
                                symbols['function_symbols'].append(demangled)
            
            return symbols
        
        except Exception:
            return None
    
    def extract_symbols_patterns(self, exe_path):
        """Extract symbols using pattern matching"""
        symbols = {
            'function_symbols': [],
            'class_symbols': [],
            'vtable_symbols': []
        }
        
        try:
            with open(exe_path, 'rb') as f:
                content = f.read()
            
            # Search for C++ patterns in strings
            strings_all = re.findall(rb'[ -~]{8,}', content)
            
            for string_bytes in strings_all:
                try:
                    string_val = string_bytes.decode('ascii', errors='ignore')
                    
                    # C++ namespace/class patterns
                    if '::' in string_val:
                        if 'vtable' in string_val.lower():
                            symbols['vtable_symbols'].append(string_val)
                        elif '(' in string_val and ')' in string_val:
                            symbols['function_symbols'].append(string_val)
                        else:
                            symbols['class_symbols'].append(string_val)
                
                except:
                    continue
        
        except Exception:
            pass
        
        return symbols
    
    def demangle_cpp_name(self, mangled_name):
        """Attempt to demangle C++ names"""
        if shutil.which("c++filt") is None:
            return mangled_name # Return original if tool is not found
        try:
            # Try using c++filt
            result = subprocess.run(
                ['c++filt', mangled_name],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
        
        except:
            pass
        
        return mangled_name
    
    def extract_functions(self, exe_path):
        """Extract function information"""
        functions = []
        
        # Get functions from symbols
        symbols = self.extract_symbols(exe_path)
        
        for func_name in symbols.get('function_symbols', []):
            functions.append({
                'name': func_name,
                'type': 'function',
                'source': 'symbol_table'
            })
        
        # Get functions from strings patterns
        strings = self.extract_strings(exe_path)
        
        for func_pattern in strings.get('function_patterns', []):
            if func_pattern not in [f['name'] for f in functions]:
                functions.append({
                    'name': func_pattern,
                    'type': 'function',
                    'source': 'string_pattern'
                })
        
        return functions
    
    def extract_classes(self, exe_path):
        """Extract class information"""
        classes = defaultdict(lambda: {'methods': [], 'vtables': []})
        
        # Get classes from symbols
        symbols = self.extract_symbols(exe_path)
        
        for class_symbol in symbols.get('class_symbols', []):
            if '::' in class_symbol:
                parts = class_symbol.split('::')
                class_name = parts[0]
                method_name = '::'.join(parts[1:])
                classes[class_name]['methods'].append(method_name)
        
        # Add vtable information
        for vtable in symbols.get('vtable_symbols', []):
            for class_name in classes:
                if class_name in vtable:
                    classes[class_name]['vtables'].append(vtable)

        # Convert back to regular dict for JSON serialization
        final_classes = {k: {'name': k, 'methods': sorted(list(set(v['methods']))), 'vtables': sorted(list(set(v['vtables'])))} for k, v in classes.items()}

        return final_classes
    
    def extract_imports(self, exe_path):
        """Extract imported DLLs and functions"""
        if shutil.which("dumpbin") is None:
            return {}
        imports = defaultdict(list)
        
        try:
            # Use dumpbin if available
            result = subprocess.run(
                ['dumpbin', '/IMPORTS', str(exe_path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
            
            if result.returncode == 0:
                current_dll = None
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        current_dll = None
                        continue
                    
                    if line.endswith('.dll'):
                        current_dll = line
                        continue
                        
                    if current_dll and line:
                        parts = line.split()
                        if len(parts) > 1:
                            func_name = parts[-1]
                            if func_name not in imports[current_dll]:
                                imports[current_dll].append(func_name)
        
        except Exception:
            pass
        
        return dict(imports)
    
    def extract_exports(self, exe_path):
        """Extract exported functions"""
        if shutil.which("dumpbin") is None:
            return []
        exports = []
        
        try:
            # Use dumpbin if available
            result = subprocess.run(
                ['dumpbin', '/EXPORTS', str(exe_path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
            
            if result.returncode == 0:
                summary_started = False
                for line in result.stdout.splitlines():
                    if 'ordinal hint RVA      name' in line:
                        summary_started = True
                        continue
                    if summary_started and line.strip():
                        parts = line.split()
                        if len(parts) >= 4 and parts[0].isdigit():
                            exports.append({
                                'ordinal': parts[0],
                                'hint': parts[1],
                                'address': parts[2],
                                'name': ' '.join(parts[3:])
                            })
        
        except Exception:
            pass
        
        return exports
    
    def disassemble_functions(self, exe_path, analysis):
        """Disassemble key functions"""
        if shutil.which("objdump") is None:
            print("[CPP-EXTRACT] objdump not found. Skipping disassembly.")
            return

        print("[CPP-EXTRACT] Disassembling executable...")
        
        disasm_dir = self.output_dir / "DISASSEMBLY"
        
        # Try using objdump for disassembly
        try:
            result = subprocess.run(
                ['objdump', '-d', '-M', 'intel', str(exe_path)],
                capture_output=True,
                text=True,
                timeout=120, # Increased timeout for larger files
                check=False
            )
            
            if result.returncode == 0:
                disasm_file = disasm_dir / f"{exe_path.stem}_full_disassembly.asm"
                with open(disasm_file, 'w', encoding='utf-8') as f:
                    f.write(result.stdout)
                
                print(f"[CPP-EXTRACT] Full disassembly saved: {disasm_file.name}")
        
        except Exception as e:
            print(f"[CPP-EXTRACT] Disassembly error: {e}")
            self.log_error(f"Disassembly error: {e}")
    
    def reconstruct_cpp_source(self, analysis):
        """Reconstruct C++ source code from analysis"""
        print("[CPP-EXTRACT] Reconstructing C++ source code...")
        
        # Generate header file
        self.generate_header_file(analysis)
        
        # Generate implementation file
        self.generate_implementation_file(analysis)
        
        # Generate class files
        self.generate_class_files(analysis)
    
    def generate_header_file(self, analysis):
        """Generate reconstructed header file"""
        header_file = self.output_dir / "HEADERS" / "reconstructed.h"
        
        with open(header_file, 'w', encoding='utf-8') as f:
            f.write("// ============================================\n")
            f.write("// RECONSTRUCTED C++ HEADER FILE\n")
            f.write("// ============================================\n")
            f.write(f"// Source: {analysis['file_name']}\n")
            f.write(f"// Extracted: {datetime.now()}\n")
            f.write("// NOTE: This is an auto-generated file based on binary analysis.\n")
            f.write("// It may not be 100% accurate or complete.\n")
            f.write("// ============================================\n\n")
            
            f.write("#pragma once\n\n")
            f.write("#include <windows.h>\n")
            f.write("#include <string>\n")
            f.write("#include <vector>\n\n")
            
            # Write class declarations
            f.write("// ============================================\n")
            f.write("// CLASS DECLARATIONS\n")
            f.write("// ============================================\n\n")
            
            for class_name, class_info in analysis['classes'].items():
                f.write(f"class {class_name} {{\n")
                f.write("public:\n")
                
                # Constructor/Destructor
                f.write(f"    {class_name}();\n")
                f.write(f"    virtual ~{class_name}();\n\n")
                
                # Methods
                for method in class_info['methods']:
                    if method != class_name and not method.startswith('~'):
                        # Basic attempt to guess return type and params
                        f.write(f"    virtual void {method}(); // Parameters and return type are unknown\n")
                
                f.write("\nprivate:\n")
                f.write("    // Member variables are unknown\n")
                f.write("    char placeholder[256]; // Placeholder for unknown member variables\n")
                f.write("};\n\n")
            
            # Write function declarations
            f.write("// ============================================\n")
            f.write("// FUNCTION DECLARATIONS (NON-MEMBER)\n")
            f.write("// ============================================\n\n")
            
            for func in analysis['functions']:
                func_name = func['name']
                if '::' not in func_name:  # Skip class methods
                    f.write(f"void {func_name}(); // Parameters and return type are unknown\n")
        
        print(f"[CPP-EXTRACT] Header file generated: {header_file.name}")
    
    def generate_implementation_file(self, analysis):
        """Generate reconstructed implementation file"""
        impl_file = self.output_dir / "CPP_SOURCE" / "reconstructed.cpp"
        
        with open(impl_file, 'w', encoding='utf-8') as f:
            f.write("// ============================================\n")
            f.write("// RECONSTRUCTED C++ IMPLEMENTATION\n")
            f.write("// ============================================\n")
            f.write(f"// Source: {analysis['file_name']}\n")
            f.write(f"// Extracted: {datetime.now()}\n")
            f.write("// ============================================\n\n")
            
            f.write('#include "reconstructed.h"\n\n')
            
            # Write string constants
            f.write("// ============================================\n")
            f.write("// EXTRACTED STRING CONSTANTS\n")
            f.write("// ============================================\n\n")
            
            for i, url in enumerate(analysis['strings'].get('urls', [])[:20]):
                f.write(f'const char* URL_{i} = "{url}";\n')
            
            for i, path in enumerate(analysis['strings'].get('file_paths', [])[:20]):
                f.write(f'const char* FILE_PATH_{i} = "{path.replace("\\", "/")}";\n')

            f.write("\n")
            
            # Write function implementations
            f.write("// ============================================\n")
            f.write("// FUNCTION IMPLEMENTATIONS (NON-MEMBER)\n")
            f.write("// ============================================\n\n")
            
            for func in analysis['functions'][:30]:  # Limit to first 30
                func_name = func['name']
                if '::' not in func_name:
                    f.write(f"void {func_name}() {{\n")
                    f.write(f"    // Reconstructed from binary analysis ({func['source']})\n")
                    f.write(f"    // TODO: Implement function logic based on disassembly.\n")
                    f.write(f"}}\n\n")
        
        print(f"[CPP-EXTRACT] Implementation file generated: {impl_file.name}")
    
    # +++ ADDED HELPER FUNCTION +++
    def sanitize_filename(self, filename):
        """Remove invalid characters from a string to make it a valid filename."""
        if not filename:
            return "_empty_"
        # Remove invalid characters (e.g., \ / : * ? " < > |) and control characters
        invalid_chars = r'[\x00-\x1f\\/:"*?<>|]'
        sanitized = re.sub(invalid_chars, '_', filename)
        
        # Replace other potentially problematic chars just in case
        sanitized = sanitized.replace(' ', '_').replace('$', '_S_')
        
        # Limit length to avoid "File name too long" errors
        return sanitized[:100]

    def generate_class_files(self, analysis):
        """Generate separate files for each class"""
        class_dir = self.output_dir / "CPP_SOURCE" / "classes"
        class_dir.mkdir(exist_ok=True)

        for class_name, class_info in list(analysis['classes'].items())[:15]:  # Limit to 15
            
            # +++ FIX: Sanitize the class_name before using it as a filename +++
            sanitized_class_name = self.sanitize_filename(class_name)
            class_file = class_dir / f"{sanitized_class_name}.cpp"
            
            try:
                with open(class_file, 'w', encoding='utf-8') as f:
                    f.write(f"// ============================================\n")
                    f.write(f"// RECONSTRUCTED CLASS: {class_name}\n")
                    f.write(f"// (Filename sanitized to: {sanitized_class_name}.cpp)\n")
                    f.write(f"// ============================================\n\n")
                    
                    f.write('#include "../HEADERS/reconstructed.h"\n\n')
                    
                    # Constructor
                    # NOTE: We use the *original* class_name in the C++ code
                    f.write(f"{class_name}::{class_name}() {{\n")
                    f.write(f"    // Reconstructed constructor\n")
                    f.write(f"}}\n\n")
                    
                    # Destructor
                    f.write(f"{class_name}::~{class_name}() {{\n")
                    f.write(f"    // Reconstructed destructor\n")
                    f.write(f"}}\n\n")
                    
                    # Methods
                    for method in class_info['methods'][:20]:  # Limit to 20 methods
                        if method != class_name and not method.startswith('~'):
                            f.write(f"void {class_name}::{method}() {{\n")
                            f.write(f"    // Reconstructed method\n")
                            f.write(f"    // TODO: Implement method logic based on disassembly.\n")
                            f.write(f"}}\n\n")
            
            except Exception as e:
                self.log_error(f"Failed to write class file for: {class_name} (Sanitized: {sanitized_class_name}). Error: {e}")
                print(f"[CPP-EXTRACT] WARNING: Could not write class file for '{class_name}'. Error: {e}")
        
        print(f"[CPP-EXTRACT] Class implementation files generated in: {class_dir.name}")
    
    def generate_reports(self, analysis):
        """Generate comprehensive analysis reports"""
        print("[CPP-EXTRACT] Generating analysis reports...")
        # JSON report
        json_file = self.output_dir / "BINARY_ANALYSIS" / "ANALYSIS_REPORT.json"
        try:
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(analysis, f, indent=4, ensure_ascii=False)
        except Exception as e:
            self.log_error(f"Failed to write JSON report: {e}")

        # Text report
        text_file = self.output_dir / "ANALYSIS_REPORT.txt"
        try:
            with open(text_file, 'w', encoding='utf-8') as f:
                f.write("=" * 70 + "\n")
                f.write("       C++ SOURCE CODE EXTRACTION & REVERSE ENGINEERING REPORT\n")
                f.write("=" * 70 + "\n\n")
                
                f.write(f"File Analyzed: {analysis['file_name']}\n")
                f.write(f"File Size: {analysis['file_size']:,} bytes\n")
                f.write(f"Analysis Timestamp: {analysis['timestamp']}\n\n")
                
                f.write("STATISTICS SUMMARY:\n")
                f.write("-" * 70 + "\n")
                f.write(f"Functions Identified: {len(analysis['functions'])}\n")
                f.write(f"Classes Identified: {len(analysis['classes'])}\n")
                f.write(f"Total Strings Extracted: {len(analysis['strings'].get('all_strings', []))}\n")
                f.write(f"URLs Found: {len(analysis['strings'].get('urls', []))}\n")
                f.write(f"Imported DLLs: {len(analysis['imports'])}\n")
                f.write(f"Exported Functions: {len(analysis['exports'])}\n\n")
                
                f.write("PE STRUCTURE:\n")
                f.write("-" * 70 + "\n")
                if 'pe_analysis' in analysis and 'sections' in analysis['pe_analysis']:
                    f.write(f"{'Section':<10} {'VirtSize':>10} {'RawSize':>10}   {'Permissions'}\n")
                    f.write(f"{'-'*8:<10} {'-'*8:>10} {'-'*8:>10}   {'-----------'}\n")
                    for section in analysis['pe_analysis']['sections']:
                        perms = f"{'R' if section['readable'] else '-'}{'W' if section['writable'] else '-'}{'X' if section['executable'] else '-'}"
                        f.write(f"{section['name']:<10} {section['virtual_size']:>10,} {section['raw_size']:>10,}   {perms}\n")
                f.write("\n")
                
                f.write("FUNCTIONS (First 20):\n")
                f.write("-" * 70 + "\n")
                for func in analysis['functions'][:20]:
                    f.write(f"  - {func['name']} (Source: {func['source']})\n")
                if len(analysis['functions']) > 20:
                    f.write("  - ... and more\n")
                f.write("\n")
                
                f.write("CLASSES (First 10):\n")
                f.write("-" * 70 + "\n")
                for class_name, class_info in list(analysis['classes'].items())[:10]:
                    f.write(f"  - {class_name} ({len(class_info['methods'])} methods identified)\n")
                if len(analysis['classes']) > 10:
                    f.write("  - ... and more\n")
                f.write("\n")
                
                f.write("URLs FOUND:\n")
                f.write("-" * 70 + "\n")
                if analysis['strings'].get('urls'):
                    for url in analysis['strings'].get('urls', [])[:15]:
                        f.write(f"  - {url}\n")
                else:
                    f.write("  - None\n")
                f.write("\n")

                f.write("IMPORTED DLLs:\n")
                f.write("-" * 70 + "\n")
                if analysis['imports']:
                    for dll, funcs in analysis['imports'].items():
                        f.write(f"  - {dll} ({len(funcs)} functions)\n")
                else:
                    f.write("  - None\n")
        except Exception as e:
            self.log_error(f"Failed to write text report: {e}")

        
        print(f"[CPP-EXTRACT] Reports generated successfully.")
    
    def log_error(self, message):
        """Log errors to file"""
        error_log = self.output_dir / "extraction_errors.log"
        try:
            with open(error_log, 'a', encoding='utf-8') as f:
                f.write(f"[{datetime.now()}] ERROR: {message}\n")
        except:
            pass
    
    def initialize(self):
        """Run full initialization and extraction"""
        try:
            self.create_directories()
            
            print("[CPP-EXTRACT] =============================================")
            print("[CPP-EXTRACT] C++ SOURCE CODE EXTRACTION STARTED")
            print("[CPP-EXTRACT] =============================================")

            # Check for and extract any pending shader data
            self.extract_shader()
            
            # Analyze executable
            analysis = self.analyze_executable()
            
            if analysis:
                # Disassemble
                exe_path = Path(analysis['file_path'])
                self.disassemble_functions(exe_path, analysis)
                
                # Reconstruct source
                self.reconstruct_cpp_source(analysis)
                
                # Generate reports
                self.generate_reports(analysis)
                
                print("[CPP-EXTRACT] =============================================")
                print("[CPP-EXTRACT] EXTRACTION PROCESS COMPLETED SUCCESSFULLY")
                print(f"[CPP-EXTRACT] All output saved to: {self.output_dir.resolve()}")
                print("[CPP-EXTRACT] =============================================")

            else:
                print("[CPP-EXTRACT] Analysis could not be completed.")

        except Exception as e:
            error_message = f"A critical error occurred during initialization: {e}"
            print(f"[CPP-EXTRACT] {error_message}")
            self.log_error(error_message)

def main():
    """Main entry point for the script"""
    extractor = CPPSourceExtractor()
    extractor.initialize()

if __name__ == "__main__":
    main()
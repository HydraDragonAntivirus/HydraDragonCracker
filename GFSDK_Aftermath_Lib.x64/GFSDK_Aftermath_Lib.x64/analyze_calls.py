#!/usr/bin/env python3
"""
Advanced Function Call Analyzer - Synchronized with C++
Analyzes function calls from EXE and DLLs with full context recovery
"""

import sys
import os
import json
import re
from collections import defaultdict, Counter
from datetime import datetime
import html

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    print("[WARNING] networkx not installed - call graph visualization disabled")

try:
    from capstone import *
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print("[WARNING] capstone not installed - disassembly analysis disabled")

class FunctionCallAnalyzer:
    def __init__(self):
        self.calls = []
        self.calls_by_function = defaultdict(list)
        self.calls_by_module = defaultdict(list)
        self.calls_by_target_module = defaultdict(list)
        self.unknown_calls = []
        self.hooked_calls = []
        self.exe_calls = []
        self.call_graph = None
        
    def load_json_data(self, json_file="function_calls.json"):
        """Load function call data from JSON file created by C++"""
        if not os.path.exists(json_file):
            print(f"[ERROR] {json_file} not found. Waiting for C++ to create it...")
            return False
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.calls = data.get('calls', [])
            self.scan_count = data.get('scan_count', 0)
            self.total_calls = data.get('total_calls', 0)
            self.timestamp = data.get('timestamp', 0)
            
            print(f"[INFO] Loaded {len(self.calls)} function calls from {json_file}")
            print(f"[INFO] Scan count: {self.scan_count}, Timestamp: {self.timestamp}")
            
            return True
        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse JSON: {e}")
            return False
        except Exception as e:
            print(f"[ERROR] Failed to load data: {e}")
            return False
    
    def categorize_calls(self):
        """Categorize all calls by various criteria"""
        for call in self.calls:
            func_name = call.get('func_name', 'Unknown')
            module = call.get('module', 'Unknown')
            target_module = call.get('target_module', 'Unknown')
            
            if func_name == "Unknown":
                self.unknown_calls.append(call)
            else:
                self.calls_by_function[func_name].append(call)
            
            self.calls_by_module[module].append(call)
            self.calls_by_target_module[target_module].append(call)
            
            if call.get('is_exe', False):
                self.exe_calls.append(call)
            
            if call.get('is_hooked', False):
                self.hooked_calls.append(call)
    
    def build_call_graph(self):
        """Build a call graph using NetworkX"""
        if not HAS_NETWORKX:
            return
        
        self.call_graph = nx.DiGraph()
        
        for call in self.calls:
            caller = call.get('module', 'Unknown')
            callee = call.get('func_name', 'Unknown')
            target_mod = call.get('target_module', 'Unknown')
            
            # Create edge: caller -> callee
            if caller and callee and callee != "Unknown":
                if not self.call_graph.has_edge(caller, callee):
                    self.call_graph.add_edge(caller, callee, 
                                            weight=1,
                                            target_module=target_mod,
                                            is_hooked=call.get('is_hooked', False))
                else:
                    # Increase weight for duplicate calls
                    self.call_graph[caller][callee]['weight'] += 1
    
    def analyze_patterns(self):
        """Analyze patterns in function calls"""
        patterns = {
            'windows_api': [],
            'crt_functions': [],
            'anti_debug': [],
            'exit_functions': [],
            'memory_ops': [],
            'file_ops': [],
            'network_ops': [],
            'registry_ops': []
        }
        
        api_patterns = {
            'windows_api': [r'^[A-Z][a-zA-Z]+$', r'^Nt[A-Z]', r'^Zw[A-Z]'],
            'crt_functions': [r'^_[a-z]', r'^malloc$', r'^free$', r'^strcpy', r'^memcpy'],
            'anti_debug': [r'IsDebuggerPresent', r'CheckRemoteDebugger', r'OutputDebugString', 
                          r'NtQueryInformationProcess', r'NtSetInformationThread'],
            'exit_functions': [r'TerminateProcess', r'ExitProcess', r'exit', r'abort'],
            'memory_ops': [r'VirtualAlloc', r'VirtualFree', r'VirtualProtect', r'HeapAlloc', r'HeapFree'],
            'file_ops': [r'CreateFile', r'ReadFile', r'WriteFile', r'DeleteFile', r'FindFirstFile'],
            'network_ops': [r'socket', r'connect', r'send', r'recv', r'WSASend', r'WSARecv'],
            'registry_ops': [r'RegOpenKey', r'RegQueryValue', r'RegSetValue', r'RegCreateKey']
        }
        
        for call in self.calls:
            func_name = call.get('func_name', '')
            for pattern_type, pattern_list in api_patterns.items():
                for pattern in pattern_list:
                    if re.search(pattern, func_name, re.IGNORECASE):
                        patterns[pattern_type].append(call)
                        break
        
        return patterns
    
    def disassemble_call_bytes(self, call_bytes_hex):
        """Disassemble call instruction bytes using Capstone"""
        if not HAS_CAPSTONE:
            return None
        
        try:
            # Convert hex string to bytes
            if isinstance(call_bytes_hex, str):
                # Remove 0x prefix if present
                call_bytes_hex = call_bytes_hex.replace('0x', '').replace(' ', '')
                bytes_data = bytes.fromhex(call_bytes_hex)
            else:
                bytes_data = call_bytes_hex
            
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True
            
            instructions = []
            for i in md.disasm(bytes_data, 0x1000):
                instructions.append({
                    'address': hex(i.address),
                    'mnemonic': i.mnemonic,
                    'op_str': i.op_str,
                    'bytes': i.bytes.hex()
                })
            
            return instructions
        except Exception as e:
            return None
    
    def generate_html_report(self, output_file="function_calls_analysis.html"):
        """Generate a comprehensive HTML report"""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Function Call Analysis Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #d4d4d4; }}
        h1, h2, h3 {{ color: #4ec9b0; }}
        .stats {{ background: #252526; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        .stat-item {{ display: inline-block; margin: 10px 20px; }}
        .stat-value {{ font-size: 24px; color: #4ec9b0; font-weight: bold; }}
        .stat-label {{ font-size: 12px; color: #858585; }}
        table {{ width: 100%; border-collapse: collapse; background: #252526; margin: 10px 0; }}
        th {{ background: #007acc; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 8px; border-bottom: 1px solid #3e3e42; }}
        tr:hover {{ background: #2d2d30; }}
        .hooked {{ color: #f48771; font-weight: bold; }}
        .exe-call {{ color: #4ec9b0; }}
        .unknown {{ color: #ce9178; }}
        .code {{ font-family: 'Consolas', monospace; background: #1e1e1e; padding: 2px 5px; border-radius: 3px; }}
        .section {{ margin: 30px 0; }}
    </style>
</head>
<body>
    <h1>🔍 Function Call Analysis Report</h1>
    <div class="stats">
        <div class="stat-item">
            <div class="stat-value">{len(self.calls)}</div>
            <div class="stat-label">Total Calls</div>
        </div>
        <div class="stat-item">
            <div class="stat-value">{len(self.calls_by_function)}</div>
            <div class="stat-label">Unique Functions</div>
        </div>
        <div class="stat-item">
            <div class="stat-value">{len(self.exe_calls)}</div>
            <div class="stat-label">EXE Calls</div>
        </div>
        <div class="stat-item">
            <div class="stat-value">{len(self.unknown_calls)}</div>
            <div class="stat-label">Unknown Calls</div>
        </div>
        <div class="stat-item">
            <div class="stat-value">{len(self.hooked_calls)}</div>
            <div class="stat-label">Hooked Calls</div>
        </div>
    </div>
    
    <div class="section">
        <h2>📊 Most Called Functions</h2>
        <table>
            <tr><th>Function</th><th>Call Count</th><th>Target Module</th><th>Status</th></tr>
"""
        
        # Most called functions
        sorted_funcs = sorted(self.calls_by_function.items(), 
                            key=lambda x: sum(c.get('call_count', 1) for c in x[1]), 
                            reverse=True)
        
        for func_name, calls in sorted_funcs[:30]:
            total_calls = sum(c.get('call_count', 1) for c in calls)
            target_mod = calls[0].get('target_module', 'Unknown') if calls else 'Unknown'
            is_hooked = any(c.get('is_hooked', False) for c in calls)
            hook_status = '<span class="hooked">HOOKED</span>' if is_hooked else ''
            
            html_content += f"""
            <tr>
                <td class="code">{html.escape(func_name)}</td>
                <td>{total_calls}</td>
                <td>{html.escape(target_mod)}</td>
                <td>{hook_status}</td>
            </tr>
"""
        
        html_content += """
        </table>
    </div>
    
    <div class="section">
        <h2>🎯 EXE Function Calls (Priority)</h2>
        <table>
            <tr><th>Call Site</th><th>Target</th><th>Function</th><th>Target Module</th><th>Status</th></tr>
"""
        
        # EXE calls
        for call in self.exe_calls[:100]:  # Limit to first 100
            call_site = call.get('call_site', '0x0')
            target = call.get('target', '0x0')
            func_name = call.get('func_name', 'Unknown')
            target_mod = call.get('target_module', 'Unknown')
            is_hooked = call.get('is_hooked', False)
            hook_status = '<span class="hooked">HOOKED</span>' if is_hooked else ''
            
            func_class = 'unknown' if func_name == 'Unknown' else ''
            
            html_content += f"""
            <tr class="{func_class}">
                <td class="code">{html.escape(call_site)}</td>
                <td class="code">{html.escape(target)}</td>
                <td class="code">{html.escape(func_name)}</td>
                <td>{html.escape(target_mod)}</td>
                <td>{hook_status}</td>
            </tr>
"""
        
        html_content += """
        </table>
    </div>
    
    <div class="section">
        <h2>❓ Unknown Function Calls</h2>
        <table>
            <tr><th>Call Site</th><th>Target</th><th>Target Module</th></tr>
"""
        
        # Unknown calls
        for call in self.unknown_calls[:50]:
            call_site = call.get('call_site', '0x0')
            target = call.get('target', '0x0')
            target_mod = call.get('target_module', 'Unknown')
            
            html_content += f"""
            <tr>
                <td class="code">{html.escape(call_site)}</td>
                <td class="code">{html.escape(target)}</td>
                <td>{html.escape(target_mod)}</td>
            </tr>
"""
        
        html_content += """
        </table>
    </div>
    
    <div class="section">
        <h2>🔗 Module Call Statistics</h2>
        <table>
            <tr><th>Module</th><th>Call Count</th></tr>
"""
        
        # Module statistics
        sorted_modules = sorted(self.calls_by_module.items(), 
                            key=lambda x: len(x[1]), reverse=True)
        
        for module, calls in sorted_modules[:30]:
            html_content += f"""
            <tr>
                <td>{html.escape(module)}</td>
                <td>{len(calls)}</td>
            </tr>
"""
        
        html_content += """
        </table>
    </div>
    
    <div class="section">
        <h2>🪝 Hooked Functions</h2>
        <table>
            <tr><th>Function</th><th>Call Site</th><th>Target Module</th></tr>
"""
        
        # Hooked functions
        hooked_by_func = defaultdict(list)
        for call in self.hooked_calls:
            hooked_by_func[call.get('func_name', 'Unknown')].append(call)
        
        for func_name, calls in sorted(hooked_by_func.items(), key=lambda x: len(x[1]), reverse=True):
            for call in calls[:5]:  # Show first 5 call sites per function
                call_site = call.get('call_site', '0x0')
                target_mod = call.get('target_module', 'Unknown')
                
                html_content += f"""
            <tr>
                <td class="code">{html.escape(func_name)}</td>
                <td class="code">{html.escape(call_site)}</td>
                <td>{html.escape(target_mod)}</td>
            </tr>
"""
        
        html_content += """
        </table>
    </div>
    
    <div class="section">
        <h2>📈 Pattern Analysis</h2>
"""
        
        # Pattern analysis
        patterns = self.analyze_patterns()
        for pattern_type, pattern_calls in patterns.items():
            if pattern_calls:
                html_content += f"""
        <h3>{pattern_type.replace('_', ' ').title()}: {len(pattern_calls)} calls</h3>
        <ul>
"""
                for call in pattern_calls[:10]:
                    func_name = call.get('func_name', 'Unknown')
                    html_content += f"            <li class='code'>{html.escape(func_name)}</li>\n"
                html_content += "        </ul>\n"
        
        html_content += """
    </div>
    
    <footer style="margin-top: 50px; padding: 20px; text-align: center; color: #858585;">
        <p>Generated by Function Call Analyzer - Synchronized with C++</p>
        <p>Scan Count: """ + str(self.scan_count) + """, Timestamp: """ + str(self.timestamp) + """</p>
    </footer>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[SUCCESS] HTML report generated: {output_file}")
    
    def generate_text_report(self, output_file="function_calls_analysis.txt"):
        """Generate a detailed text report"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("FUNCTION CALL ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Scan Count: {self.scan_count}\n")
            f.write(f"Total Calls: {len(self.calls)}\n")
            f.write(f"Unique Functions: {len(self.calls_by_function)}\n")
            f.write(f"EXE Calls: {len(self.exe_calls)}\n")
            f.write(f"Unknown Calls: {len(self.unknown_calls)}\n")
            f.write(f"Hooked Calls: {len(self.hooked_calls)}\n")
            f.write(f"Timestamp: {self.timestamp}\n\n")
            
            # Most called functions
            f.write("\n" + "=" * 80 + "\n")
            f.write("MOST CALLED FUNCTIONS\n")
            f.write("=" * 80 + "\n\n")
            
            sorted_funcs = sorted(self.calls_by_function.items(), 
                                key=lambda x: sum(c.get('call_count', 1) for c in x[1]), 
                                reverse=True)
            
            for func_name, calls in sorted_funcs[:50]:
                total_calls = sum(c.get('call_count', 1) for c in calls)
                target_mod = calls[0].get('target_module', 'Unknown') if calls else 'Unknown'
                is_hooked = any(c.get('is_hooked', False) for c in calls)
                hook_status = " [HOOKED]" if is_hooked else ""
                
                f.write(f"{func_name}: {total_calls} call(s) -> {target_mod}{hook_status}\n")
            
            # EXE calls
            f.write("\n" + "=" * 80 + "\n")
            f.write("EXE FUNCTION CALLS (PRIORITY)\n")
            f.write("=" * 80 + "\n\n")
            
            for call in self.exe_calls[:100]:
                call_site = call.get('call_site', '0x0')
                target = call.get('target', '0x0')
                func_name = call.get('func_name', 'Unknown')
                target_mod = call.get('target_module', 'Unknown')
                is_hooked = call.get('is_hooked', False)
                hook_status = " [HOOKED]" if is_hooked else ""
                
                f.write(f"{call_site} -> {target} | {func_name} | {target_mod}{hook_status}\n")
            
            # Unknown calls
            if self.unknown_calls:
                f.write("\n" + "=" * 80 + "\n")
                f.write("UNKNOWN FUNCTION CALLS\n")
                f.write("=" * 80 + "\n\n")
                
                for call in self.unknown_calls[:100]:
                    call_site = call.get('call_site', '0x0')
                    target = call.get('target', '0x0')
                    target_mod = call.get('target_module', 'Unknown')
                    
                    f.write(f"{call_site} -> {target} | {target_mod}\n")
            
            # Pattern analysis
            f.write("\n" + "=" * 80 + "\n")
            f.write("PATTERN ANALYSIS\n")
            f.write("=" * 80 + "\n\n")
            
            patterns = self.analyze_patterns()
            for pattern_type, pattern_calls in patterns.items():
                if pattern_calls:
                    f.write(f"{pattern_type.replace('_', ' ').title()}: {len(pattern_calls)} calls\n")
                    for call in pattern_calls[:20]:
                        func_name = call.get('func_name', 'Unknown')
                        f.write(f"  - {func_name}\n")
                    f.write("\n")
        
        print(f"[SUCCESS] Text report generated: {output_file}")
    
    def analyze(self):
        """Run complete analysis"""
        print("[INFO] Starting function call analysis...")
        
        if not self.load_json_data():
            return False
        
        print("[INFO] Categorizing calls...")
        self.categorize_calls()
        
        print("[INFO] Building call graph...")
        self.build_call_graph()
        
        print("[INFO] Generating reports...")
        self.generate_text_report()
        self.generate_html_report()
        
        print("[INFO] Analysis complete!")
        return True

    def reconstruct_source_code(self, call):
        """Reconstruct source code from call information"""
        source_file = call.get('source_file', '')
        source_line = call.get('source_line', 0)
        call_site = call.get('call_site', '0x0')
        func_name = call.get('func_name', 'Unknown')
        
        if not source_file or source_line == 0:
            return None
        
        reconstructed = {
            'call_site': call_site,
            'function': func_name,
            'source_file': source_file,
            'source_line': source_line,
            'code_lines': []
        }
        
        # Try to read source file
        if os.path.exists(source_file):
            try:
                with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    
                    # Get context around the call (10 lines before and after)
                    start_line = max(0, source_line - 11)
                    end_line = min(len(lines), source_line + 10)
                    
                    for i in range(start_line, end_line):
                        line_num = i + 1
                        line_content = lines[i].rstrip()
                        is_target = (line_num == source_line)
                        
                        reconstructed['code_lines'].append({
                            'line_number': line_num,
                            'content': line_content,
                            'is_target': is_target
                        })
            except Exception as e:
                print(f"[WARNING] Failed to read source file {source_file}: {e}")
        
        return reconstructed
    
    def generate_source_reconstruction_report(self):
        """Generate source code reconstruction report"""
        output_file = "source_code_reconstruction.txt"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("SOURCE CODE RECONSTRUCTION REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            # Reconstruct source for EXE calls with source info
            reconstructed_count = 0
            for call in self.exe_calls:
                if call.get('source_file') and call.get('source_line', 0) > 0:
                    reconstructed = self.reconstruct_source_code(call)
                    if reconstructed:
                        reconstructed_count += 1
                        
                        f.write("\n" + "=" * 80 + "\n")
                        f.write(f"Function: {reconstructed['function']}\n")
                        f.write(f"Call Site: {reconstructed['call_site']}\n")
                        f.write(f"Source: {reconstructed['source_file']}:{reconstructed['source_line']}\n")
                        f.write("-" * 80 + "\n")
                        
                        for line_info in reconstructed['code_lines']:
                            marker = ">>>" if line_info['is_target'] else "   "
                            f.write(f"{marker} {line_info['line_number']:4d}: {line_info['content']}\n")
            
            f.write(f"\n\nTotal Reconstructed: {reconstructed_count} function calls\n")
        
        print(f"[SUCCESS] Source code reconstruction report: {output_file}")
        return reconstructed_count
    
    def write_block_commands(self):
        """Write commands to C++ to block exit calls"""
        response_file = "python_response.json"
        
        # Analyze which functions should be blocked
        exit_patterns = [
            'TerminateProcess', 'ExitProcess', 'exit', 'abort',
            'NtTerminateProcess', 'NtTerminateThread', '_exit'
        ]
        
        functions_to_block = []
        for call in self.calls:
            func_name = call.get('func_name', '')
            for pattern in exit_patterns:
                if pattern.lower() in func_name.lower():
                    functions_to_block.append(func_name)
                    break
        
        # Write response
        with open(response_file, 'w', encoding='utf-8') as f:
            f.write("{\n")
            f.write('  "block_exit": true,\n')
            f.write('  "hook_functions": [\n')
            for i, func in enumerate(set(functions_to_block)):
                f.write(f'    "{func}"')
                if i < len(set(functions_to_block)) - 1:
                    f.write(',')
                f.write('\n')
            f.write('  ],\n')
            f.write(f'  "total_exit_calls_found": {len(functions_to_block)},\n')
            f.write(f'  "timestamp": {int(datetime.now().timestamp())}\n')
            f.write('}\n')
        
        print(f"[SUCCESS] Block commands written to {response_file}")
        print(f"[INFO] Found {len(functions_to_block)} exit function calls to block")
    
    def analyze(self):
        """Run complete analysis"""
        print("[INFO] Starting function call analysis...")
        
        # Check for command file from C++
        command_file = "python_commands.json"
        if os.path.exists(command_file):
            try:
                with open(command_file, 'r', encoding='utf-8') as f:
                    commands = json.load(f)
                    print(f"[INFO] Received commands: {commands}")
            except:
                pass
        
        if not self.load_json_data():
            return False
        
        print("[INFO] Categorizing calls...")
        self.categorize_calls()
        
        print("[INFO] Building call graph...")
        self.build_call_graph()
        
        print("[INFO] Reconstructing source code...")
        reconstructed_count = self.generate_source_reconstruction_report()
        
        print("[INFO] Generating reports...")
        self.generate_text_report()
        self.generate_html_report()
        
        print("[INFO] Writing block commands to C++...")
        self.write_block_commands()
        
        print("[INFO] Analysis complete!")
        print(f"[INFO] Reconstructed {reconstructed_count} source code contexts")
        return True

def main():
    analyzer = FunctionCallAnalyzer()
    analyzer.analyze()

if __name__ == "__main__":
    main()

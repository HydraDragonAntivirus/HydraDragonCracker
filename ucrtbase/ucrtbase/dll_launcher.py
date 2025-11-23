#!/usr/bin/env python3
"""
DLL Launcher - DLL'i analiz et ve başlat
"""
import pefile
import ctypes
from ctypes import wintypes
import sys
import os
import json
import argparse
from pathlib import Path

# Windows API Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
VIRTUAL_MEM = (MEM_COMMIT | MEM_RESERVE)

class DLLLauncher:
    def __init__(self, dll_path):
        self.dll_path = Path(dll_path)
        self.dll_info = None
        self.dll_handle = None

    def analyze_dll(self):
        """DLL'i analiz et ve bilgileri al"""
        print(f"[*] Analyzing: {self.dll_path}")

        try:
            pe = pefile.PE(str(self.dll_path))

            self.dll_info = {
                'path': str(self.dll_path.absolute()),
                'name': self.dll_path.name,
                'architecture': 'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86',
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
                'exports': [],
                'imports': {},
                'sections': []
            }

            # Exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        name = exp.name.decode('utf-8')
                        self.dll_info['exports'].append({
                            'name': name,
                            'ordinal': exp.ordinal,
                            'address': hex(exp.address)
                        })

            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8')
                    self.dll_info['imports'][dll_name] = []

                    for imp in entry.imports:
                        if imp.name:
                            self.dll_info['imports'][dll_name].append(
                                imp.name.decode('utf-8')
                            )

            # Sections
            for section in pe.sections:
                self.dll_info['sections'].append({
                    'name': section.Name.decode('utf-8').rstrip('\x00'),
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': hex(section.Misc_VirtualSize),
                    'raw_size': hex(section.SizeOfRawData)
                })

            pe.close()

            print(f"[+] Architecture: {self.dll_info['architecture']}")
            print(f"[+] Entry Point: {self.dll_info['entry_point']}")
            print(f"[+] Exports: {len(self.dll_info['exports'])}")
            print(f"[+] Imports from {len(self.dll_info['imports'])} DLLs")

            return self.dll_info

        except Exception as e:
            print(f"[-] Analysis failed: {e}")
            return None

    def save_analysis(self, output_file=None):
        """Analiz sonuçlarını JSON'a kaydet"""
        if not self.dll_info:
            print("[-] No analysis data to save")
            return False

        if output_file is None:
            output_file = self.dll_path.stem + '_analysis.json'

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.dll_info, f, indent=2)
            print(f"[+] Analysis saved to: {output_file}")
            return True
        except Exception as e:
            print(f"[-] Failed to save analysis: {e}")
            return False

    def load_dll(self):
        """DLL'i mevcut process'e yükle"""
        print(f"[*] Loading DLL into current process...")

        try:
            # DLL'i yükle
            self.dll_handle = ctypes.WinDLL(str(self.dll_path.absolute()))
            print(f"[+] DLL loaded successfully!")
            print(f"[+] Handle: {self.dll_handle._handle}")

            # Export edilen fonksiyonları listele
            if self.dll_info and self.dll_info['exports']:
                print(f"\n[*] Available exports:")
                for exp in self.dll_info['exports'][:10]:  # İlk 10'u göster
                    print(f"    - {exp['name']} @ {exp['ordinal']}")

                if len(self.dll_info['exports']) > 10:
                    print(f"    ... and {len(self.dll_info['exports']) - 10} more")

            return True

        except Exception as e:
            print(f"[-] Failed to load DLL: {e}")
            return False

    def call_function(self, function_name, *args):
        """DLL'den bir fonksiyonu çağır"""
        if not self.dll_handle:
            print("[-] DLL not loaded!")
            return None

        try:
            func = getattr(self.dll_handle, function_name)
            print(f"[*] Calling {function_name}...")
            result = func(*args)
            print(f"[+] Result: {result}")
            return result
        except AttributeError:
            print(f"[-] Function '{function_name}' not found in DLL")
            return None
        except Exception as e:
            print(f"[-] Error calling function: {e}")
            return None

    def inject_into_process(self, process_name_or_pid):
        """DLL'i başka bir process'e inject et"""
        print(f"[*] Injecting DLL into process: {process_name_or_pid}")

        try:
            import subprocess

            # PowerShell ile injection (basit yöntem)
            # Gerçek injection için daha karmaşık kod gerekir

            if isinstance(process_name_or_pid, int):
                pid = process_name_or_pid
            else:
                # Process name'den PID bul
                import psutil
                pid = None
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['name'].lower() == process_name_or_pid.lower():
                        pid = proc.info['pid']
                        break

                if pid is None:
                    print(f"[-] Process not found: {process_name_or_pid}")
                    return False

            print(f"[*] Target PID: {pid}")

            # Windows API kullanarak injection
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

            # Process'i aç
            h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not h_process:
                print(f"[-] Failed to open process (Error: {ctypes.get_last_error()})")
                return False

            # DLL yolunu hazırla
            dll_path_bytes = str(self.dll_path.absolute()).encode('utf-16le') + b'\x00\x00'
            path_len = len(dll_path_bytes)

            # Bellek ayır
            arg_address = kernel32.VirtualAllocEx(
                h_process, None, path_len, VIRTUAL_MEM, PAGE_READWRITE
            )

            if not arg_address:
                print(f"[-] Failed to allocate memory (Error: {ctypes.get_last_error()})")
                kernel32.CloseHandle(h_process)
                return False

            # DLL yolunu yaz
            written = wintypes.DWORD(0)
            if not kernel32.WriteProcessMemory(
                h_process, arg_address, dll_path_bytes, path_len, ctypes.byref(written)
            ):
                print(f"[-] Failed to write memory (Error: {ctypes.get_last_error()})")
                kernel32.CloseHandle(h_process)
                return False

            # LoadLibraryW adresini al
            h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
            load_library_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryW")

            # Remote thread oluştur
            thread_id = wintypes.DWORD(0)
            h_thread = kernel32.CreateRemoteThread(
                h_process, None, 0, load_library_addr, arg_address, 0, ctypes.byref(thread_id)
            )

            if not h_thread:
                print(f"[-] Failed to create remote thread (Error: {ctypes.get_last_error()})")
                kernel32.CloseHandle(h_process)
                return False

            print(f"[+] DLL injected successfully!")
            print(f"[+] Thread ID: {thread_id.value}")

            # Thread'in bitmesini bekle
            kernel32.WaitForSingleObject(h_thread, 5000)  # 5 saniye timeout

            # Temizlik
            kernel32.CloseHandle(h_thread)
            kernel32.CloseHandle(h_process)

            return True

        except ImportError as e:
            print(f"[-] Required module not found: {e}")
            print("[*] Install: pip install psutil")
            return False
        except Exception as e:
            print(f"[-] Injection failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def launch_with_process(self, exe_path, args=None):
        """Yeni bir process başlat ve DLL'i inject et"""
        print(f"[*] Launching: {exe_path}")

        try:
            import subprocess

            # Process'i başlat (suspended olarak başlatmak için CreateProcess gerekir)
            cmd = [exe_path]
            if args:
                cmd.extend(args)

            # Basit yöntem - process'i normal başlat, sonra inject et
            proc = subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
            print(f"[+] Process started (PID: {proc.pid})")

            # Biraz bekle (process başlayana kadar)
            import time
            time.sleep(1)

            # DLL'i inject et
            return self.inject_into_process(proc.pid)

        except Exception as e:
            print(f"[-] Failed to launch process: {e}")
            return False

    def unload_dll(self):
        """DLL'i kaldır"""
        if self.dll_handle:
            try:
                ctypes.windll.kernel32.FreeLibrary(self.dll_handle._handle)
                self.dll_handle = None
                print("[+] DLL unloaded")
                return True
            except Exception as e:
                print(f"[-] Failed to unload DLL: {e}")
                return False
        return False


def main():
    parser = argparse.ArgumentParser(description='DLL Launcher - Analyze and launch DLLs')
    parser.add_argument('dll', help='Path to DLL file')
    parser.add_argument('-a', '--analyze', action='store_true', help='Analyze DLL only')
    parser.add_argument('-s', '--save', metavar='FILE', help='Save analysis to JSON file')
    parser.add_argument('-l', '--load', action='store_true', help='Load DLL into current process')
    parser.add_argument('-c', '--call', metavar='FUNC', help='Call exported function')
    parser.add_argument('-i', '--inject', metavar='PROCESS', help='Inject into process (name or PID)')
    parser.add_argument('-e', '--execute', metavar='EXE', help='Launch EXE and inject DLL')
    parser.add_argument('--args', nargs='*', help='Arguments for launched process')

    args = parser.parse_args()

    # DLL var mı kontrol et
    if not os.path.exists(args.dll):
        print(f"[-] DLL not found: {args.dll}")
        return 1

    launcher = DLLLauncher(args.dll)

    # Önce her zaman analiz yap
    if not launcher.analyze_dll():
        return 1

    # Analiz sonuçlarını kaydet
    if args.save:
        launcher.save_analysis(args.save)

    # Sadece analiz modunda ise çık
    if args.analyze:
        if not args.save:
            launcher.save_analysis()
        return 0

    # DLL'i yükle
    if args.load:
        if not launcher.load_dll():
            return 1

        # Fonksiyon çağır
        if args.call:
            launcher.call_function(args.call)

        input("\nPress Enter to unload DLL...")
        launcher.unload_dll()

    # Process'e inject et
    if args.inject:
        try:
            pid = int(args.inject)
        except ValueError:
            pid = args.inject

        if not launcher.inject_into_process(pid):
            return 1

    # Yeni process başlat
    if args.execute:
        if not launcher.launch_with_process(args.execute, args.args):
            return 1

    return 0


if __name__ == "__main__":
    print("=" * 70)
    print("  DLL Launcher v1.0 - Analyze & Launch DLLs")
    print("=" * 70)
    print()

    sys.exit(main())

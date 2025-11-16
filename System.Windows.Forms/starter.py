# check_winforms_proxy.py
# Usage:
#   python check_winforms_proxy.py [path_to_folder]
#
# What it does:
# - Lists files in the folder
# - Sets DEVPATH to that folder for the child process
# - Starts RikaCrackmeV1.exe (in that folder)
# - Waits briefly and then enumerates child process modules looking for System.Windows.Forms.dll
# - Prints module path if found, otherwise prints diagnostic hints
#
# Notes: Run as Administrator if you get "access denied" when enumerating modules.

import os
import sys
import subprocess
import time
import ctypes
from ctypes import wintypes

# --- WinAPI helpers (Toolhelp module enumeration + QueryFullProcessImageName) ---

TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPPROCESS = 0x00000002

MAX_PATH = 260

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('th32ModuleID', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('GlblcntUsage', wintypes.DWORD),
        ('ProccntUsage', wintypes.DWORD),
        ('modBaseAddr', wintypes.LPVOID),
        ('modBaseSize', wintypes.DWORD),
        ('hModule', wintypes.HMODULE),
        ('szModule', wintypes.WCHAR * 256),
        ('szExePath', wintypes.WCHAR * MAX_PATH)
    ]

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.c_void_p),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', wintypes.LONG),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', wintypes.WCHAR * 260)
    ]

CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
CreateToolhelp32Snapshot.restype = wintypes.HANDLE

Module32FirstW = kernel32.Module32FirstW
Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
Module32FirstW.restype = wintypes.BOOL

Module32NextW = kernel32.Module32NextW
Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
Module32NextW.restype = wintypes.BOOL

Process32FirstW = kernel32.Process32FirstW
Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
Process32FirstW.restype = wintypes.BOOL

Process32NextW = kernel32.Process32NextW
Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
Process32NextW.restype = wintypes.BOOL

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

QueryFullProcessImageNameW = kernel32.QueryFullProcessImageNameW
QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
QueryFullProcessImageNameW.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010

def enum_modules(pid):
    """Return list of (module_name, module_path) for given pid, or raise if snapshot failed."""
    flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
    hSnap = CreateToolhelp32Snapshot(flags, pid)
    if hSnap == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())

    me32 = MODULEENTRY32W()
    me32.dwSize = ctypes.sizeof(MODULEENTRY32W)

    modules = []
    ok = Module32FirstW(hSnap, ctypes.byref(me32))
    if not ok:
        CloseHandle(hSnap)
        # Could be access denied or 32/64 mismatch
        raise ctypes.WinError(ctypes.get_last_error())
    while ok:
        name = me32.szModule
        path = me32.szExePath
        modules.append((name, path))
        ok = Module32NextW(hSnap, ctypes.byref(me32))
    CloseHandle(hSnap)
    return modules

def get_parent_pid(pid):
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if hSnap == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    pe32 = PROCESSENTRY32W()
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    ok = Process32FirstW(hSnap, ctypes.byref(pe32))
    parent = None
    if not ok:
        CloseHandle(hSnap)
        raise ctypes.WinError(ctypes.get_last_error())
    while ok:
        if pe32.th32ProcessID == pid:
            parent = pe32.th32ParentProcessID
            break
        ok = Process32NextW(hSnap, ctypes.byref(pe32))
    CloseHandle(hSnap)
    return parent

def get_process_path(pid):
    # Try QueryFullProcessImageName
    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not hProc:
        return None
    buf_len = wintypes.DWORD(MAX_PATH)
    buf = ctypes.create_unicode_buffer(MAX_PATH)
    success = QueryFullProcessImageNameW(hProc, 0, buf, ctypes.byref(buf_len))
    CloseHandle(hProc)
    if not success:
        return None
    return buf.value

# --- main script flow ---
def main(folder):
    folder = os.path.abspath(folder)
    exe_name = "RikaCrackmeV1.exe"
    exe_path = os.path.join(folder, exe_name)
    if not os.path.exists(folder):
        print(f"Folder not found: {folder}")
        return 1
    print(f"Folder: {folder}")
    print("\nFiles in folder:")
    for entry in sorted(os.listdir(folder)):
        try:
            st = os.stat(os.path.join(folder, entry))
            print(f"  {entry:40} {st.st_size:10}  modified: {time.ctime(st.st_mtime)}")
        except Exception:
            print(f"  {entry:40} <could not stat>")

    if not os.path.exists(exe_path):
        print(f"\nERROR: {exe_name} not found in the folder. Launch the EXE from the folder where it actually resides.")
        return 2

    # Configure env for child
    env = os.environ.copy()
    env['DEVPATH'] = folder
    # Start the exe with DEVPATH set, child cwd set to folder
    print(f"\nStarting {exe_name} with DEVPATH set to this folder...")
    try:
        proc = subprocess.Popen([exe_path], cwd=folder, env=env)
    except Exception as e:
        print(f"Failed to start process: {e}")
        return 3

    print(f"Launched child PID: {proc.pid}")
    # Give the process a little time to initialize and bind assemblies
    time.sleep(0.8)

    # Try to enumerate modules and find System.Windows.Forms.dll
    try:
        modules = enum_modules(proc.pid)
        # filter for System.Windows.Forms.dll
        matches = [m for m in modules if m[0].lower() == "system.windows.forms.dll"]
        if matches:
            for name, path in matches:
                print(f"\nFOUND module in process PID {proc.pid}:")
                print(f"  ModuleName: {name}")
                print(f"  FileName  : {path}")
        else:
            print("\nNo System.Windows.Forms.dll module found in module list for the child process.")
            print("Full module count:", len(modules))
            # Optionally show some modules (first 10)
            print("\nFirst modules (name -> path):")
            for n, pth in modules[:10]:
                print(f"  {n} -> {pth}")
            print("\nIf module enumeration failed due to permissions or 32/64-bit mismatch, run this script as Administrator")
            print("or inspect the process with Process Explorer (procexp) to see loaded DLL paths.")
    except Exception as e:
        print("\nCould not enumerate modules for the child process. Error:")
        print(" ", e)
        print("\nThis is commonly caused by a 32/64-bit mismatch (running a 64-bit Python to inspect a 32-bit process or vice versa)")
        print("or by insufficient permissions. Try running as Administrator or use Process Explorer to check DLL paths.")
        # continue to parent info

    # Parent process info
    try:
        parent_pid = get_parent_pid(proc.pid)
        parent_path = get_process_path(parent_pid) if parent_pid else None
        print(f"\nChild PID: {proc.pid}; Parent PID: {parent_pid}; Parent Path: {parent_path}")
    except Exception as e:
        print("\nCould not determine parent process info:", e)

    return 0

if __name__ == "__main__":
    folder_arg = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    sys.exit(main(folder_arg))

// ===================================================================================
//              DLL INJECTION LAUNCHER
// ===================================================================================
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <filesystem>

// ===================================================================================
// PROCESS UTILITIES
// ===================================================================================
DWORD GetProcessIdByName(const std::wstring& processName) {
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    DWORD pid = 0;
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pid;
}

// ===================================================================================
// DLL INJECTION
// ===================================================================================
bool InjectDLL(DWORD processId, const std::wstring& dllPath) {
    std::wcout << L"[*] Injecting DLL into process ID: " << processId << std::endl;
    std::wcout << L"[*] DLL Path: " << dllPath << std::endl;

    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::wcerr << L"[-] Failed to open process. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Get full path
    WCHAR fullPath[MAX_PATH];
    GetFullPathNameW(dllPath.c_str(), MAX_PATH, fullPath, NULL);

    // Allocate memory in target process
    size_t pathSize = (wcslen(fullPath) + 1) * sizeof(WCHAR);
    LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!pRemotePath) {
        std::wcerr << L"[-] Failed to allocate memory. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write DLL path to target process
    if (!WriteProcessMemory(hProcess, pRemotePath, fullPath, pathSize, NULL)) {
        std::wcerr << L"[-] Failed to write memory. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get LoadLibraryW address
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");

    if (!pLoadLibrary) {
        std::wcerr << L"[-] Failed to get LoadLibraryW address." << std::endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create remote thread
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemotePath, 0, NULL);

    if (!hThread) {
        std::wcerr << L"[-] Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::wcout << L"[+] DLL injection successful!" << std::endl;

    // Wait for thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Cleanup
    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}

// ===================================================================================
// PROCESS LAUNCHER
// ===================================================================================
bool LaunchProcessWithDLL(const std::wstring& exePath, const std::wstring& dllPath,
                         const std::wstring& cmdLine = L"", const std::wstring& workDir = L"") {
    std::wcout << L"[*] Launching process: " << exePath << std::endl;
    std::wcout << L"[*] With DLL: " << dllPath << std::endl;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    std::wstring commandLine = L"\"" + exePath + L"\"";
    if (!cmdLine.empty()) {
        commandLine += L" " + cmdLine;
    }

    const WCHAR* workDirPtr = workDir.empty() ? NULL : workDir.c_str();

    // Create suspended process
    if (!CreateProcessW(NULL, const_cast<WCHAR*>(commandLine.c_str()), NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, workDirPtr, &si, &pi)) {
        std::wcerr << L"[-] Failed to create process. Error: " << GetLastError() << std::endl;
        return false;
    }

    std::wcout << L"[+] Process created (PID: " << pi.dwProcessId << L")" << std::endl;

    // Inject DLL
    bool success = InjectDLL(pi.dwProcessId, dllPath);

    // Resume process
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return success;
}

// ===================================================================================
// MAIN
// ===================================================================================
int wmain(int argc, wchar_t* argv[]) {
    std::wcout << L"========================================" << std::endl;
    std::wcout << L"     DLL Injection Launcher v1.0       " << std::endl;
    std::wcout << L"========================================" << std::endl << std::endl;

    if (argc < 2) {
        std::wcout << L"Usage:" << std::endl;
        std::wcout << L"  1. Inject into running process:" << std::endl;
        std::wcout << L"     launcher.exe -p <process_name.exe> -d <dll_path>" << std::endl;
        std::wcout << L"     launcher.exe -pid <process_id> -d <dll_path>" << std::endl;
        std::wcout << L"" << std::endl;
        std::wcout << L"  2. Launch new process with DLL:" << std::endl;
        std::wcout << L"     launcher.exe -l <exe_path> -d <dll_path> [-args <arguments>]" << std::endl;
        std::wcout << L"" << std::endl;
        std::wcout << L"Examples:" << std::endl;
        std::wcout << L"  launcher.exe -p game.exe -d LX63.dll" << std::endl;
        std::wcout << L"  launcher.exe -pid 1234 -d LX63.dll" << std::endl;
        std::wcout << L"  launcher.exe -l \"C:\\Games\\game.exe\" -d LX63.dll -args \"-windowed\"" << std::endl;
        return 1;
    }

    std::wstring mode, target, dllPath, args;
    DWORD pid = 0;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];

        if (arg == L"-p" && i + 1 < argc) {
            mode = L"process";
            target = argv[++i];
        }
        else if (arg == L"-pid" && i + 1 < argc) {
            mode = L"pid";
            pid = _wtoi(argv[++i]);
        }
        else if (arg == L"-l" && i + 1 < argc) {
            mode = L"launch";
            target = argv[++i];
        }
        else if (arg == L"-d" && i + 1 < argc) {
            dllPath = argv[++i];
        }
        else if (arg == L"-args" && i + 1 < argc) {
            args = argv[++i];
        }
    }

    // Validate DLL path
    if (dllPath.empty()) {
        std::wcerr << L"[-] DLL path not specified!" << std::endl;
        return 1;
    }

    if (!std::filesystem::exists(dllPath)) {
        std::wcerr << L"[-] DLL file not found: " << dllPath << std::endl;
        return 1;
    }

    // Execute based on mode
    bool success = false;

    if (mode == L"process") {
        pid = GetProcessIdByName(target);
        if (pid == 0) {
            std::wcerr << L"[-] Process not found: " << target << std::endl;
            return 1;
        }
        success = InjectDLL(pid, dllPath);
    }
    else if (mode == L"pid") {
        if (pid == 0) {
            std::wcerr << L"[-] Invalid process ID!" << std::endl;
            return 1;
        }
        success = InjectDLL(pid, dllPath);
    }
    else if (mode == L"launch") {
        if (!std::filesystem::exists(target)) {
            std::wcerr << L"[-] Executable not found: " << target << std::endl;
            return 1;
        }

        std::wstring workDir = std::filesystem::path(target).parent_path().wstring();
        success = LaunchProcessWithDLL(target, dllPath, args, workDir);
    }
    else {
        std::wcerr << L"[-] Invalid mode specified!" << std::endl;
        return 1;
    }

    if (success) {
        std::wcout << L"\n[+] Operation completed successfully!" << std::endl;
        return 0;
    }
    else {
        std::wcerr << L"\n[-] Operation failed!" << std::endl;
        return 1;
    }
}

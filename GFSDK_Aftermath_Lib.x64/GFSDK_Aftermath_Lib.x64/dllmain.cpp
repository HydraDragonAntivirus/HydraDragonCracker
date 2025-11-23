// ===================================================================================
//              GFSDK_Aftermath_Lib.x64 PROXY DLL WITH CONFIGURATION & LOGGING
// ===================================================================================
#include "pch.h"
#include <windows.h>
#include <shlwapi.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <filesystem>
#include <DbgHelp.h>
#include "logger.h"
#include "terminate_process_hook.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "dbghelp.lib")

// ===================================================================================
// CONFIGURATION MANAGER
// ===================================================================================
class Config {
private:
    std::map<std::string, std::string> settings;
    std::filesystem::path configPath;

    std::string trim(const std::string& str) {
        size_t start = str.find_first_not_of(" \t\r\n");
        size_t end = str.find_last_not_of(" \t\r\n");
        return (start == std::string::npos) ? "" : str.substr(start, end - start + 1);
    }

public:
    Config(const std::filesystem::path& iniPath) : configPath(iniPath) {
        Load();
    }

    void Load() {
        std::ifstream file(configPath);
        if (!file.is_open()) {
            CreateDefault();
            return;
        }

        std::string line, section;
        while (std::getline(file, line)) {
            line = trim(line);
            if (line.empty() || line[0] == ';' || line[0] == '#') continue;

            if (line[0] == '[' && line.back() == ']') {
                section = line.substr(1, line.length() - 2);
            }
            else {
                size_t pos = line.find('=');
                if (pos != std::string::npos) {
                    std::string key = trim(line.substr(0, pos));
                    std::string value = trim(line.substr(pos + 1));
                    size_t commentPos = value.find(';');
                    if (commentPos != std::string::npos) {
                        value = trim(value.substr(0, commentPos));
                    }
                    settings[section + "." + key] = value;
                }
            }
        }
    }

    void CreateDefault() {
        settings["General.EnableLogging"] = "1";
        settings["General.DebugMode"] = "0";
        settings["DLL.OriginalDLL"] = "orig_GFSDK_Aftermath_Lib.x64.dll";
        settings["DLL.LoadMethod"] = "0"; // 0=Same directory, 1=System32, 2=Custom path
        settings["DLL.LoadOriginal"] = "1"; // MUST be 1 for dynamic hooking
    }

    std::string Get(const std::string& key, const std::string& defaultValue = "") {
        auto it = settings.find(key);
        return (it != settings.end()) ? it->second : defaultValue;
    }

    int GetInt(const std::string& key, int defaultValue = 0) {
        std::string val = Get(key);
        return val.empty() ? defaultValue : std::stoi(val);
    }

    bool GetBool(const std::string& key, bool defaultValue = false) {
        return GetInt(key, defaultValue ? 1 : 0) != 0;
    }
};

static Config* g_config = nullptr;

// Global logger instance (used by hooks)
Logger* g_logger = nullptr;

// TerminateProcess hook - declared in terminate_process_hook.h
TerminateProcess_t g_origTerminateProcess = nullptr;

// Forward declaration
extern "C" BOOL WINAPI Hooked_TerminateProcess(HANDLE hProcess, UINT uExitCode);
static void InstallTerminateProcessHook();

// ===================================================================================
// UTILITY FUNCTIONS
// ===================================================================================
static std::filesystem::path GetExeDirectory() {
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    return std::filesystem::path(exePath).parent_path();
}

static std::filesystem::path GetCurrentDllDirectory() {
    WCHAR dllPath[MAX_PATH];
    HMODULE hModule = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)GetCurrentDllDirectory, &hModule);
    GetModuleFileNameW(hModule, dllPath, MAX_PATH);
    return std::filesystem::path(dllPath).parent_path();
}

// ===================================================================================
// ORIGINAL DLL LOADING (used by dynamic hooks)
// ===================================================================================
HMODULE g_origDll = NULL;

static bool LoadOriginalDll() {
    std::string dllName = g_config->Get("DLL.OriginalDLL", "orig_GFSDK_Aftermath_Lib.x64.dll");
    int loadMethod = g_config->GetInt("DLL.LoadMethod", 0);

    std::filesystem::path dllPath;

    switch (loadMethod) {
    case 0: // Same directory as our proxy DLL
        dllPath = GetCurrentDllDirectory() / dllName;
        break;
    case 1: // System32
        {
            WCHAR sysDir[MAX_PATH];
            GetSystemDirectoryW(sysDir, MAX_PATH);
            dllPath = std::filesystem::path(sysDir) / dllName;
        }
        break;
    case 2: // Custom path
        dllPath = g_config->Get("DLL.CustomPath", dllName);
        break;
    }

    if (g_logger) g_logger->Log("Loading original GFSDK_Aftermath_Lib.x64 DLL: " + dllPath.string());

    // Try to load the DLL
    g_origDll = LoadLibraryW(dllPath.c_str());

    if (!g_origDll) {
        // Fallback to just the name (will search system paths)
        g_origDll = LoadLibraryA(dllName.c_str());
    }

    if (!g_origDll) {
        if (g_logger) {
            g_logger->LogFormat("Failed to load original DLL. Error: %d", GetLastError());
            g_logger->Log("WARNING: Proxy DLL will rely on .def file forwarding");
        }
        return false;
    }

    if (g_logger) {
        g_logger->LogFormat("Original GFSDK_Aftermath_Lib.x64 DLL loaded successfully at: %p", g_origDll);
    }

    return true;
}

// ===================================================================================
// TERMINATE PROCESS HOOK INSTALLATION
// ===================================================================================
static void InstallTerminateProcessHook() {
    if (!g_logger) return;
    
    // Get kernel32.dll
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) {
        g_logger->Log("ERROR: Cannot get kernel32.dll handle for TerminateProcess hook");
        return;
    }
    
    // Get original TerminateProcess address
    g_origTerminateProcess = (TerminateProcess_t)GetProcAddress(kernel32, "TerminateProcess");
    if (!g_origTerminateProcess) {
        g_logger->Log("ERROR: Cannot find TerminateProcess in kernel32.dll");
        return;
    }
    
    // Hook using IAT (Import Address Table) hooking
    HMODULE hModule = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)InstallTerminateProcessHook, &hModule);
    
    if (hModule) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + 
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        
        while (importDesc->Name) {
            char* dllName = (char*)((BYTE*)hModule + importDesc->Name);
            if (_stricmp(dllName, "kernel32.dll") == 0) {
                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
                
                while (thunk->u1.Function) {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + thunk->u1.AddressOfData);
                    if (strcmp((char*)importByName->Name, "TerminateProcess") == 0) {
                        DWORD oldProtect;
                        if (VirtualProtect(&thunk->u1.Function, sizeof(DWORD_PTR), PAGE_READWRITE, &oldProtect)) {
                            thunk->u1.Function = (DWORD_PTR)Hooked_TerminateProcess;
                            VirtualProtect(&thunk->u1.Function, sizeof(DWORD_PTR), oldProtect, &oldProtect);
                            g_logger->Log("SUCCESS: TerminateProcess hook installed via IAT");
                            return;
                        }
                    }
                    thunk++;
                }
            }
            importDesc++;
        }
    }
    
    // Fallback: Inline hook
    DWORD oldProtect;
    if (VirtualProtect(g_origTerminateProcess, 16, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        unsigned char hookCode[] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xE0
        };
        *(DWORD64*)&hookCode[2] = (DWORD64)Hooked_TerminateProcess;
        
        memcpy((void*)g_origTerminateProcess, hookCode, sizeof(hookCode));
        VirtualProtect(g_origTerminateProcess, 16, oldProtect, &oldProtect);
        
        g_logger->Log("SUCCESS: TerminateProcess hook installed via inline patching");
    } else {
        g_logger->Log("ERROR: Failed to install TerminateProcess hook");
    }
}

// ===================================================================================
// HOOK FUNCTIONS (Examples - add your own as needed)
// ===================================================================================

// Example: Hook a specific GFSDK function if you want to intercept calls
// You would need to implement this manually and update the .def file
// to NOT forward that specific function to orig_GFSDK_Aftermath_Lib.x64.dll

/*
extern "C" __declspec(dllexport) int GFSDK_Aftermath_EnableGpuCrashDumps(
    unsigned int version,
    unsigned int flags,
    void* callback) {

    if (g_logger) {
        g_logger->LogFormat("GFSDK_Aftermath_EnableGpuCrashDumps called: version=%u, flags=%u", version, flags);
    }

    // Get original function from loaded DLL
    typedef int (*EnableGpuCrashDumps_t)(unsigned int, unsigned int, void*);
    static EnableGpuCrashDumps_t orig_func = nullptr;

    if (!orig_func && g_origDll) {
        orig_func = (EnableGpuCrashDumps_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_EnableGpuCrashDumps");
    }

    if (orig_func) {
        return orig_func(version, flags, callback);
    }

    return -1; // Error
}
*/

// ===================================================================================
// DLL ENTRY POINT
// ===================================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        {
            DisableThreadLibraryCalls(hModule);

            // Initialize configuration
            std::filesystem::path exeDir = GetExeDirectory();
            std::filesystem::path dllDir = GetCurrentDllDirectory();
            std::filesystem::path configPath = dllDir / "config.ini";

            g_config = new Config(configPath);

            // Initialize logger
            g_logger = new Logger();
            std::string logFile = g_config->Get("General.LogFile", "GFSDK_Aftermath_proxy.log");
            bool enableLogging = g_config->GetBool("General.EnableLogging", true);
            g_logger->Initialize((dllDir / logFile).string(), enableLogging);

            g_logger->Log("DLL_PROCESS_ATTACH");
            g_logger->LogFormat("Proxy DLL Module: %p", hModule);
            g_logger->Log("Executable Directory: " + exeDir.string());
            g_logger->Log("DLL Directory: " + dllDir.string());

            // Load original DLL (REQUIRED for dynamic hooking)
            bool loadOrig = g_config->GetBool("DLL.LoadOriginal", true);
            if (loadOrig) {
                if (!LoadOriginalDll()) {
                    g_logger->Log("CRITICAL: Original DLL not loaded! Hooks will fail!");
                }
                else {
                    g_logger->Log("Original DLL loaded successfully - dynamic hooks active");
                }
            }
            else {
                g_logger->Log("WARNING: Original DLL not loaded - dynamic hooks will NOT work!");
            }

            // Install TerminateProcess hook AFTER delay (so game can initialize first)
            // Use a separate thread to avoid blocking DLL initialization
            CreateThread(NULL, 0, [](LPVOID) -> DWORD {
                // Wait 2 seconds for game to initialize
                Sleep(2000);
                
                if (g_logger) {
                    g_logger->Log("Installing TerminateProcess hook (delayed)...");
                }
                
                InstallTerminateProcessHook();
                
                if (g_logger) {
                    g_logger->Log("TerminateProcess hook installed successfully");
                }
                
                return 0;
            }, NULL, 0, NULL);

            break;
        }

    case DLL_PROCESS_DETACH:
        if (g_logger) g_logger->Log("DLL_PROCESS_DETACH");

        if (g_origDll) {
            FreeLibrary(g_origDll);
            g_origDll = NULL;
        }

        if (g_logger) {
            delete g_logger;
            g_logger = nullptr;
        }

        if (g_config) {
            delete g_config;
            g_config = nullptr;
        }
        break;
    }
    return TRUE;
}

// ===================================================================================
//              UCRTBASE PROXY DLL WITH CONFIGURATION & LOGGING
// ===================================================================================
#include "pch.h"
#include <windows.h>
#include <shlwapi.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <filesystem>

#pragma comment(lib, "shlwapi.lib")

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
        settings["DLL.OriginalDLL"] = "orig_ucrtbase.dll";
        settings["DLL.LoadMethod"] = "1"; // System32
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

// ===================================================================================
// LOGGING SYSTEM
// ===================================================================================
class Logger {
private:
    std::ofstream logFile;
    bool enabled;
    CRITICAL_SECTION cs;

public:
    Logger() : enabled(false) {
        InitializeCriticalSection(&cs);
    }

    ~Logger() {
        if (logFile.is_open()) {
            logFile.close();
        }
        DeleteCriticalSection(&cs);
    }

    void Initialize(const std::string& filename, bool enable) {
        enabled = enable;
        if (enabled) {
            logFile.open(filename, std::ios::app);
            if (logFile.is_open()) {
                Log("=== UCRTBASE Proxy DLL Initialized ===");
            }
        }
    }

    void Log(const std::string& message) {
        if (!enabled) return;

        EnterCriticalSection(&cs);
        if (logFile.is_open()) {
            SYSTEMTIME st;
            GetLocalTime(&st);
            char timestamp[64];
            sprintf_s(timestamp, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

            logFile << timestamp << message << std::endl;
            logFile.flush();
        }
        LeaveCriticalSection(&cs);
    }

    template<typename... Args>
    void LogFormat(const char* format, Args... args) {
        char buffer[1024];
        sprintf_s(buffer, format, args...);
        Log(buffer);
    }
};

static Logger* g_logger = nullptr;

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
// ORIGINAL DLL LOADING (if needed for manual forwarding)
// ===================================================================================
static HMODULE g_origDll = NULL;

static bool LoadOriginalDll() {
    std::string dllName = g_config->Get("DLL.OriginalDLL", "orig_ucrtbase.dll");
    int loadMethod = g_config->GetInt("DLL.LoadMethod", 1);

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

    if (g_logger) g_logger->Log("Loading original ucrtbase DLL: " + dllPath.string());

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
        g_logger->LogFormat("Original ucrtbase DLL loaded successfully at: %p", g_origDll);
    }

    return true;
}

// ===================================================================================
// HOOK FUNCTIONS (Examples - add your own as needed)
// ===================================================================================

// Example: Hook malloc if you want to track memory allocations
// You would need to implement this manually and update the .def file
// to NOT forward malloc to orig_ucrtbase.dll

/*
extern "C" __declspec(dllexport) void* malloc(size_t size) {
    if (g_logger) {
        g_logger->LogFormat("malloc called: size=%zu", size);
    }

    // Get original malloc from loaded DLL
    typedef void* (*malloc_t)(size_t);
    static malloc_t orig_malloc = nullptr;

    if (!orig_malloc && g_origDll) {
        orig_malloc = (malloc_t)GetProcAddress(g_origDll, "malloc");
    }

    if (orig_malloc) {
        return orig_malloc(size);
    }

    return nullptr;
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
            std::string logFile = g_config->Get("General.LogFile", "ucrtbase_proxy.log");
            bool enableLogging = g_config->GetBool("General.EnableLogging", true);
            g_logger->Initialize((dllDir / logFile).string(), enableLogging);

            g_logger->Log("DLL_PROCESS_ATTACH");
            g_logger->LogFormat("Proxy DLL Module: %p", hModule);
            g_logger->Log("Executable Directory: " + exeDir.string());
            g_logger->Log("DLL Directory: " + dllDir.string());

            // Load original DLL (optional - only if you need manual forwarding)
            // The .def file handles forwarding automatically
            bool loadOrig = g_config->GetBool("DLL.LoadOriginal", false);
            if (loadOrig) {
                if (!LoadOriginalDll()) {
                    g_logger->Log("Note: Original DLL not loaded, using .def file forwarding");
                }
            }
            else {
                g_logger->Log("Using .def file forwarding (no manual DLL loading)");
            }

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

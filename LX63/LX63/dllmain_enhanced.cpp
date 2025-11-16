// ===================================================================================
//              ENHANCED PROXY DLL WITH CONFIGURATION & LAUNCHER
// ===================================================================================
#include "pch.h"
#include <windows.h>
#include <shlwapi.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>

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
            // Create default config
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
                    // Remove inline comments
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
        settings["DLL.OriginalDLL"] = "orig.dll";
        settings["Python.EnablePython"] = "1";
        settings["Python.RunAsync"] = "1";
        settings["Hooks.HookD3DCompile"] = "1";
        settings["Output.SaveShaders"] = "1";
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
                Log("=== Proxy DLL Initialized ===");
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
// PYTHON LAUNCHER
// ===================================================================================
namespace PythonLauncher
{
    static std::filesystem::path GetExeDirectory() {
        WCHAR exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        return std::filesystem::path(exePath).parent_path();
    }

    static void CallPython(const std::string& command, const void* data = nullptr, size_t dataSize = 0) {
        if (!g_config->GetBool("Python.EnablePython", true)) {
            return;
        }

        std::filesystem::path exeDir = GetExeDirectory();
        std::string scriptName = g_config->Get("Python.ScriptPath", "shader_extractor.py");
        std::filesystem::path scriptPath = exeDir / scriptName;

        if (!std::filesystem::exists(scriptPath)) {
            if (g_logger) g_logger->Log("Python script not found: " + scriptPath.string());
            return;
        }

        // Save data if provided
        if (data && dataSize > 0 && g_config->GetBool("Output.SaveShaders", true)) {
            std::filesystem::path tempData = exeDir / "temp_shader_data.bin";
            std::ofstream f(tempData, std::ios::binary);
            if (f) {
                f.write(static_cast<const char*>(data), dataSize);
                f.close();
                if (g_logger) g_logger->LogFormat("Saved shader data: %zu bytes", dataSize);
            }
        }

        // Build command
        std::string pythonExe = g_config->Get("Python.PythonExecutable", "python");
        std::string cmd = pythonExe + " \"" + scriptPath.string() + "\" " + command;

        if (g_logger) g_logger->Log("Executing: " + cmd);

        // Launch Python
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        bool async = g_config->GetBool("Python.RunAsync", true);

        if (CreateProcessA(NULL, const_cast<char*>(cmd.c_str()), NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {

            if (!async) {
                WaitForSingleObject(pi.hProcess, INFINITE);
            }

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
}

// ===================================================================================
// ORIGINAL DLL FORWARDING
// ===================================================================================
static HMODULE g_origDll = NULL;

typedef HRESULT(WINAPI* t_D3DCompile)(
    LPCVOID pSrcData, SIZE_T SrcDataSize, LPCSTR pSourceName,
    const void* pDefines, void* pInclude,
    LPCSTR pEntrypoint, LPCSTR pTarget, UINT Flags1, UINT Flags2,
    void** ppCode, void** ppErrorMsgs
);

static t_D3DCompile g_origCompile = NULL;

static bool LoadOriginalDll() {
    std::string dllName = g_config->Get("DLL.OriginalDLL", "orig.dll");
    int loadMethod = g_config->GetInt("DLL.LoadMethod", 0);

    std::filesystem::path dllPath;

    switch (loadMethod) {
    case 0: // Same directory
        dllPath = PythonLauncher::GetExeDirectory() / dllName;
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

    if (g_logger) g_logger->Log("Loading original DLL: " + dllPath.string());

    g_origDll = LoadLibraryW(dllPath.c_str());

    if (!g_origDll) {
        // Fallback to just the name
        g_origDll = LoadLibraryA(dllName.c_str());
    }

    if (!g_origDll) {
        if (g_logger) g_logger->LogFormat("Failed to load DLL. Error: %d", GetLastError());
        return false;
    }

    g_origCompile = (t_D3DCompile)GetProcAddress(g_origDll, "D3DCompile");

    if (g_logger) {
        g_logger->LogFormat("Original DLL loaded successfully. D3DCompile: %p", g_origCompile);
    }

    return (g_origCompile != NULL);
}

// ===================================================================================
// EXPORTED FUNCTIONS
// ===================================================================================
extern "C" __declspec(dllexport) HRESULT WINAPI D3DCompile(
    LPCVOID pSrcData, SIZE_T SrcDataSize, LPCSTR pSourceName,
    const void* pDefines, void* pInclude,
    LPCSTR pEntrypoint, LPCSTR pTarget, UINT Flags1, UINT Flags2,
    void** ppCode, void** ppErrorMsgs) {

    if (g_config && g_config->GetBool("Hooks.HookD3DCompile", true)) {
        if (g_logger) {
            g_logger->LogFormat("D3DCompile called: Size=%zu, Entry=%s, Target=%s",
                SrcDataSize, pEntrypoint ? pEntrypoint : "NULL", pTarget ? pTarget : "NULL");
        }

        // Extract shader via Python
        if (pSrcData && SrcDataSize > 0) {
            PythonLauncher::CallPython("extract_shader", pSrcData, SrcDataSize);
        }
    }

    // Forward to original DLL
    if (g_origCompile) {
        return g_origCompile(pSrcData, SrcDataSize, pSourceName, pDefines, pInclude,
            pEntrypoint, pTarget, Flags1, Flags2, ppCode, ppErrorMsgs);
    }

    if (g_logger) g_logger->Log("ERROR: Original D3DCompile not found!");
    return 0x80004005; // E_FAIL
}

// Stub exports
extern "C" __declspec(dllexport) HRESULT WINAPI D3DPreprocess(
    LPCVOID pSrcData, SIZE_T SrcDataSize, LPCSTR pSourceName,
    const void* pDefines, void* pInclude,
    void** ppCodeText, void** ppErrorMsgs) {
    if (g_logger) g_logger->Log("D3DPreprocess called (stub)");
    return 0x80004001; // E_NOTIMPL
}

extern "C" __declspec(dllexport) HRESULT WINAPI D3DDisassemble(
    LPCVOID pSrcData, SIZE_T SrcDataSize, UINT Flags,
    LPCSTR szComments, void** ppDisassembly) {
    if (g_logger) g_logger->Log("D3DDisassemble called (stub)");
    return 0x80004001; // E_NOTIMPL
}

extern "C" __declspec(dllexport) HRESULT WINAPI D3DCompileFromFile(
    LPCWSTR pFileName, const void* pDefines, void* pInclude,
    LPCSTR pEntrypoint, LPCSTR pTarget, UINT Flags1, UINT Flags2,
    void** ppCode, void** ppErrorMsgs) {
    if (g_logger) g_logger->Log("D3DCompileFromFile called (stub)");
    return 0x80004001; // E_NOTIMPL
}

// ===================================================================================
// DLL ENTRY POINT
// ===================================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        // Initialize configuration
        std::filesystem::path exeDir = PythonLauncher::GetExeDirectory();
        std::filesystem::path configPath = exeDir / "config.ini";
        g_config = new Config(configPath);

        // Initialize logger
        g_logger = new Logger();
        std::string logFile = g_config->Get("General.LogFile", "proxy_log.txt");
        bool enableLogging = g_config->GetBool("General.EnableLogging", true);
        g_logger->Initialize((exeDir / logFile).string(), enableLogging);

        g_logger->Log("DLL_PROCESS_ATTACH");
        g_logger->LogFormat("Module: %p", hModule);

        // Call Python initialization
        PythonLauncher::CallPython("initialize");

        // Load original DLL
        if (!LoadOriginalDll()) {
            g_logger->Log("WARNING: Failed to load original DLL");
        }
        break;

    case DLL_PROCESS_DETACH:
        if (g_logger) g_logger->Log("DLL_PROCESS_DETACH");

        if (g_origDll) {
            FreeLibrary(g_origDll);
            g_origDll = NULL;
            g_origCompile = NULL;
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

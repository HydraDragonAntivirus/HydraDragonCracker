// ===================================================================================
//              MINIMAL C++ PROXY DLL - CALLS PYTHON FOR EXTRACTION
// ===================================================================================
// File: proxy_dll.cpp
// Compile this as LX63.dll

#include "pch.h"
#include <windows.h>
#include <string>
#include <filesystem>
#include <fstream>

// ===================================================================================
// SECTION 1: PYTHON LAUNCHER
// ===================================================================================
namespace PythonLauncher
{
    static std::filesystem::path GetExeDirectory() {
        WCHAR exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        return std::filesystem::path(exePath).parent_path();
    }

    static void CallPython(const std::string& command, const void* data = nullptr, size_t dataSize = 0) {
        std::filesystem::path exeDir = GetExeDirectory();
        std::filesystem::path scriptPath = exeDir / "shader_extractor.py";

        // Check if Python script exists
        if (!std::filesystem::exists(scriptPath)) {
            return; // Silent fail
        }

        // Save shader data to temp file if provided
        if (data && dataSize > 0) {
            std::filesystem::path tempData = exeDir / "temp_shader_data.bin";
            std::ofstream f(tempData, std::ios::binary);
            if (f) {
                f.write(static_cast<const char*>(data), dataSize);
                f.close();
            }
        }

        // Build Python command
        std::string cmd = "python \"" + scriptPath.string() + "\" " + command;

        // Launch Python in background (don't wait)
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        if (CreateProcessA(NULL, const_cast<char*>(cmd.c_str()), NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
}

// ===================================================================================
// SECTION 2: ORIGINAL DLL FORWARDING
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
    std::filesystem::path exeDir = PythonLauncher::GetExeDirectory();
    std::filesystem::path origDllPath = exeDir / "orig.dll";

    g_origDll = LoadLibraryW(origDllPath.c_str());

    if (!g_origDll) {
        g_origDll = LoadLibraryW(L"orig.dll"); // Fallback
    }

    if (!g_origDll) {
        return false;
    }

    g_origCompile = (t_D3DCompile)GetProcAddress(g_origDll, "D3DCompile");
    return (g_origCompile != NULL);
}

// ===================================================================================
// SECTION 3: EXPORTED FUNCTIONS
// ===================================================================================
extern "C" __declspec(dllexport) HRESULT WINAPI D3DCompile(
    LPCVOID pSrcData, SIZE_T SrcDataSize, LPCSTR pSourceName,
    const void* pDefines, void* pInclude,
    LPCSTR pEntrypoint, LPCSTR pTarget, UINT Flags1, UINT Flags2,
    void** ppCode, void** ppErrorMsgs) {

    // Extract shader via Python (async, doesn't block)
    if (pSrcData && SrcDataSize > 0) {
        PythonLauncher::CallPython("extract_shader", pSrcData, SrcDataSize);
    }

    // Forward to original DLL
    if (g_origCompile) {
        return g_origCompile(pSrcData, SrcDataSize, pSourceName, pDefines, pInclude,
            pEntrypoint, pTarget, Flags1, Flags2, ppCode, ppErrorMsgs);
    }

    return 0x80004005; // E_FAIL
}

// Stub exports for completeness
extern "C" __declspec(dllexport) HRESULT WINAPI D3DPreprocess(
    LPCVOID pSrcData, SIZE_T SrcDataSize, LPCSTR pSourceName,
    const void* pDefines, void* pInclude,
    void** ppCodeText, void** ppErrorMsgs) {
    return 0x80004001; // E_NOTIMPL
}

extern "C" __declspec(dllexport) HRESULT WINAPI D3DDisassemble(
    LPCVOID pSrcData, SIZE_T SrcDataSize, UINT Flags,
    LPCSTR szComments, void** ppDisassembly) {
    return 0x80004001; // E_NOTIMPL
}

extern "C" __declspec(dllexport) HRESULT WINAPI D3DCompileFromFile(
    LPCWSTR pFileName, const void* pDefines, void* pInclude,
    LPCSTR pEntrypoint, LPCSTR pTarget, UINT Flags1, UINT Flags2,
    void** ppCode, void** ppErrorMsgs) {
    return 0x80004001; // E_NOTIMPL
}

// ===================================================================================
// SECTION 4: DLL ENTRY POINT
// ===================================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        // Call Python to initialize extraction
        PythonLauncher::CallPython("initialize");

        // Load original DLL
        LoadOriginalDll();
        break;

    case DLL_PROCESS_DETACH:
        if (g_origDll) {
            FreeLibrary(g_origDll);
            g_origDll = NULL;
            g_origCompile = NULL;
        }
        break;
    }
    return TRUE;
}

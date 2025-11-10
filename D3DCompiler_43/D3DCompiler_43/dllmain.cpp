// dllmain.cpp
// Improved proxy DLL for D3DCompile interception & logging.
// Build: Visual Studio (x64/x86) - no external deps.
// WARNING: Use only on software you are authorized to inspect.

#include <windows.h>
#include <stdint.h>
#include <tlhelp32.h>
#include <process.h>
#include <intsafe.h>
#include <strsafe.h>

#pragma comment(lib, "kernel32.lib")

// If you want a MessageBox on attach for debugging, uncomment:
// #define DEBUG_PROXY_DLL

// ----- Minimal forward declarations for D3D types (so we don't require d3d headers) -----
struct ID3DBlob;
struct D3D_SHADER_MACRO;
typedef long HRESULT;
typedef unsigned long SIZE_T;
typedef unsigned int UINT;
typedef const char* LPCSTR;
typedef const void* LPCVOID;

// Function pointer type for D3DCompile
typedef HRESULT(WINAPI* t_D3DCompile)(
    LPCVOID pSrcData, SIZE_T SrcDataSize, LPCSTR pSourceName,
    const D3D_SHADER_MACRO* pDefines, void* pInclude,
    LPCSTR pEntrypoint, LPCSTR pTarget, UINT Flags1, UINT Flags2,
    ID3DBlob** ppCode, ID3DBlob** ppErrorMsgs
    );

// Globals
static HMODULE g_hOriginal = NULL;
static t_D3DCompile g_pOrigD3DCompile = NULL;
static CRITICAL_SECTION g_logCs;
static bool g_initialized = false;

// Utility: get temp directory path
static void GetTempFilePathA(char* outPath, size_t outPathSize, const char* baseName) {
    if (!outPath || outPathSize == 0) return;
    char tempPath[MAX_PATH] = { 0 };
    DWORD len = GetTempPathA(MAX_PATH, tempPath);
    if (len == 0 || len > MAX_PATH) {
        // fallback to current dir
        StringCchCopyA(tempPath, MAX_PATH, ".\\");
    }
    // build file name: <temp>\<baseName>_PID_TID_YYYYMMDD_hhmmss.txt
    SYSTEMTIME st;
    GetLocalTime(&st);
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    StringCchPrintfA(outPath, (UINT)outPathSize, "%s%s_%04u%02u%02u_%02u%02u%02u_pid%u_tid%u.txt",
        tempPath, baseName,
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond,
        pid, tid);
}

// Utility: append text to a file (thread-safe)
static void AppendTextToFileThreadsafe(const char* filename, const char* text) {
    if (!filename || !text) return;
    EnterCriticalSection(&g_logCs);
    HANDLE h = CreateFileA(filename, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        DWORD toWrite = (DWORD)lstrlenA(text);
        WriteFile(h, text, toWrite, &written, NULL);
        CloseHandle(h);
    }
    LeaveCriticalSection(&g_logCs);
}

// Utility: write a buffer to a file (overwrite)
static bool WriteBufferToFile(const char* filename, const void* buff, size_t buffSize) {
    if (!filename || (!buff && buffSize != 0)) return false;
    HANDLE h = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL ok = WriteFile(h, buff, (DWORD)buffSize, &written, NULL);
    CloseHandle(h);
    return ok && written == (DWORD)buffSize;
}

// Utility: safe string cat for logs
static void SafeAppend(char* dest, size_t destSize, const char* src) {
    if (!dest || !src) return;
    size_t curLen = lstrlenA(dest);
    if (curLen >= destSize - 1) return;
    StringCchCatA(dest, (UINT)destSize, src);
}

// Utility: dump command line + cwd + env vars + list of modules into a string buffer
static void BuildRuntimeSnapshot(char* outBuf, size_t outBufSize) {
    if (!outBuf) return;
    outBuf[0] = '\0';
    SafeAppend(outBuf, outBufSize, "==== Runtime Snapshot ====\r\n");

    // timestamp, PID/TID
    SYSTEMTIME st;
    GetLocalTime(&st);
    char temp[256];
    StringCchPrintfA(temp, _countof(temp), "Time: %04u-%02u-%02u %02u:%02u:%02u\r\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    SafeAppend(outBuf, outBufSize, temp);

    StringCchPrintfA(temp, _countof(temp), "PID: %u  TID: %u\r\n", GetCurrentProcessId(), GetCurrentThreadId());
    SafeAppend(outBuf, outBufSize, temp);

    // command line
    LPWSTR cmdW = GetCommandLineW();
    if (cmdW) {
        // convert to UTF-8 (simple)
        int need = WideCharToMultiByte(CP_UTF8, 0, cmdW, -1, NULL, 0, NULL, NULL);
        if (need > 0 && need < 64 * 1024) {
            char* cmdA = (char*)HeapAlloc(GetProcessHeap(), 0, (size_t)need);
            if (cmdA) {
                WideCharToMultiByte(CP_UTF8, 0, cmdW, -1, cmdA, need, NULL, NULL);
                SafeAppend(outBuf, outBufSize, "CommandLine: ");
                SafeAppend(outBuf, outBufSize, cmdA);
                SafeAppend(outBuf, outBufSize, "\r\n");
                HeapFree(GetProcessHeap(), 0, cmdA);
            }
        }
    }

    // current directory
    WCHAR cwdW[MAX_PATH];
    if (GetCurrentDirectoryW(MAX_PATH, cwdW)) {
        int need = WideCharToMultiByte(CP_UTF8, 0, cwdW, -1, NULL, 0, NULL, NULL);
        if (need > 0 && need < 64 * 1024) {
            char* cwdA = (char*)HeapAlloc(GetProcessHeap(), 0, (size_t)need);
            if (cwdA) {
                WideCharToMultiByte(CP_UTF8, 0, cwdW, -1, cwdA, need, NULL, NULL);
                SafeAppend(outBuf, outBufSize, "CurrentDirectory: ");
                SafeAppend(outBuf, outBufSize, cwdA);
                SafeAppend(outBuf, outBufSize, "\r\n");
                HeapFree(GetProcessHeap(), 0, cwdA);
            }
        }
    }

    // environment variables (first N to avoid huge output)
    LPWCH env = GetEnvironmentStringsW();
    if (env) {
        SafeAppend(outBuf, outBufSize, "Environment Variables (truncated):\r\n");
        LPWCH cur = env;
        int count = 0;
        while (*cur && count < 200) {
            int need = WideCharToMultiByte(CP_UTF8, 0, cur, -1, NULL, 0, NULL, NULL);
            if (need > 0 && need < 4096) {
                char* envA = (char*)HeapAlloc(GetProcessHeap(), 0, (size_t)need);
                if (envA) {
                    WideCharToMultiByte(CP_UTF8, 0, cur, -1, envA, need, NULL, NULL);
                    SafeAppend(outBuf, outBufSize, envA);
                    SafeAppend(outBuf, outBufSize, "\r\n");
                    HeapFree(GetProcessHeap(), 0, envA);
                }
            }
            // advance
            while (*cur) ++cur;
            ++cur;
            ++count;
        }
        FreeEnvironmentStringsW(env);
    }

    // loaded modules snapshot
    SafeAppend(outBuf, outBufSize, "Loaded Modules:\r\n");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me;
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                // module base and path
                char pathA[MAX_PATH * 2] = { 0 };
                int need = WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, NULL, 0, NULL, NULL);
                if (need > 0 && need < (int)sizeof(pathA)) {
                    WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, pathA, need, NULL, NULL);
                }
                char line[512];
                StringCchPrintfA(line, _countof(line), "0x%p %s\r\n", me.modBaseAddr, pathA);
                SafeAppend(outBuf, outBufSize, line);
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    }
    SafeAppend(outBuf, outBufSize, "==== End Snapshot ====\r\n");
}

// Try to load the "original" D3D compiler DLL.
// Strategy:
//   1) Try LoadLibraryA("orig.dll") -- this is the common test-time rename approach.
//   2) Try a list of common real names (d3dcompiler_47.dll, d3dcompiler_43.dll, d3dcompiler_46.dll).
// Returns loaded module or NULL.
static HMODULE TryLoadRealD3DCompiler(void) {
    HMODULE h = NULL;
    // 1) orig.dll (user renames original to orig.dll)
    h = LoadLibraryA("orig.dll");
    if (h) return h;

    // 2) common real dll names
    const char* names[] = {
        "d3dcompiler_47.dll",
        "d3dcompiler_46.dll",
        "d3dcompiler_44.dll",
        "d3dcompiler_43.dll",
        "d3dcompiler_42.dll",
    };
    for (size_t i = 0; i < _countof(names); ++i) {
        h = LoadLibraryA(names[i]);
        if (h) return h;
    }
    return NULL;
}

// Worker thread to write a runtime snapshot file once after attach.
static unsigned __stdcall RuntimeSnapshotThread(void* /*arg*/) {
    // small delay to allow process initialization
    Sleep(2500);

    char snapshot[64 * 1024];
    BuildRuntimeSnapshot(snapshot, sizeof(snapshot));
    char outPath[MAX_PATH * 2];
    GetTempFilePathA(outPath, _countof(outPath), "D3D_RunSnapshot");
    AppendTextToFileThreadsafe(outPath, snapshot);
    return 0;
}

// Save shader source to file. If pSrcData is non-null, save its raw bytes as text (SrcDataSize).
// If pSourceName is provided, include it in file name. Returns path written to (outPath) on success.
static bool SaveShaderSource(const void* pSrcData, SIZE_T SrcDataSize, LPCSTR pSourceName, char* outPath, size_t outPathSize) {
    if (!outPath || outPathSize == 0) return false;
    // Build base name
    char baseName[128] = { 0 };
    if (pSourceName && pSourceName[0] != '\0') {
        // sanitize simple set (replace slashes)
        const char* src = pSourceName;
        size_t bi = 0;
        for (; *src && bi + 1 < sizeof(baseName); ++src) {
            char c = *src;
            if (c == '\\' || c == '/' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') {
                baseName[bi++] = '_';
            }
            else if ((unsigned char)c < 32) {
                baseName[bi++] = '_';
            }
            else {
                baseName[bi++] = c;
            }
        }
        baseName[bi] = '\0';
    }
    else {
        StringCchCopyA(baseName, _countof(baseName), "shader");
    }

    // Produce filename
    char tmpPath[MAX_PATH * 2];
    GetTempFilePathA(tmpPath, _countof(tmpPath), baseName);

    // If we have data, write it
    if (pSrcData && SrcDataSize > 0) {
        // ensure buffer is printable text - many app pass text shaders, so write as-is.
        if (!WriteBufferToFile(tmpPath, pSrcData, SrcDataSize)) {
            return false;
        }
    }
    else {
        // No data but maybe name provided; create a zero-length file with note
        const char* note = "// shader file saved: empty source buffer\r\n";
        if (!WriteBufferToFile(tmpPath, note, lstrlenA(note))) return false;
    }

    // copy out path
    StringCchCopyA(outPath, (UINT)outPathSize, tmpPath);
    return true;
}

// Exported proxy function for D3DCompile
extern "C" __declspec(dllexport) HRESULT WINAPI D3DCompile(
    LPCVOID pSrcData, SIZE_T SrcDataSize, LPCSTR pSourceName,
    const D3D_SHADER_MACRO* pDefines, void* pInclude,
    LPCSTR pEntrypoint, LPCSTR pTarget, UINT Flags1, UINT Flags2,
    ID3DBlob** ppCode, ID3DBlob** ppErrorMsgs)
{
    // Write a small call log (thread-safe)
    char callLog[1024];
    callLog[0] = '\0';
    StringCchPrintfA(callLog, _countof(callLog),
        "[D3DCompile] PID=%u TID=%u Entrypoint=%s Target=%s SrcName=%s SrcSize=%llu\r\n",
        GetCurrentProcessId(), GetCurrentThreadId(), pEntrypoint ? pEntrypoint : "<null>", pTarget ? pTarget : "<null>",
        pSourceName ? pSourceName : "<null>", (unsigned long long)SrcDataSize);
    // Append to main log file in temp
    char logPath[MAX_PATH * 2];
    GetTempFilePathA(logPath, _countof(logPath), "D3D_CallLog");
    AppendTextToFileThreadsafe(logPath, callLog);

    // Save shader source (if available) for later inspection.
    char savedPath[MAX_PATH * 2] = { 0 };
    if (pSrcData && SrcDataSize > 0) {
        if (SaveShaderSource(pSrcData, SrcDataSize, pSourceName, savedPath, _countof(savedPath))) {
            char info[512];
            StringCchPrintfA(info, _countof(info), "Saved shader input to: %s\r\n", savedPath);
            AppendTextToFileThreadsafe(logPath, info);
        }
    }
    else if (pSourceName && pSourceName[0] != '\0') {
        // Some applications pass source via file name; record the name
        char info[512];
        StringCchPrintfA(info, _countof(info), "D3DCompile called with source name only: %s\r\n", pSourceName);
        AppendTextToFileThreadsafe(logPath, info);
    }

    // Forward to original function if available
    if (g_pOrigD3DCompile) {
        return g_pOrigD3DCompile(pSrcData, SrcDataSize, pSourceName, pDefines, pInclude, pEntrypoint, pTarget, Flags1, Flags2, ppCode, ppErrorMsgs);
    }

    // If original not found, return a failure HRESULT
    return (HRESULT)0x80004005; // E_FAIL
}

// Standard DllMain
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)lpReserved;
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_logCs);
        g_initialized = true;
        DisableThreadLibraryCalls(hModule);

#ifdef DEBUG_PROXY_DLL
        MessageBoxA(NULL, "Proxy DLL attached (debug).", "ProxyDLL", MB_OK | MB_ICONINFORMATION);
#endif

        // Try to load the real D3D compiler
        g_hOriginal = TryLoadRealD3DCompiler();
        if (g_hOriginal) {
            // get D3DCompile forward
            FARPROC p = GetProcAddress(g_hOriginal, "D3DCompile");
            if (p) g_pOrigD3DCompile = (t_D3DCompile)p;
        }
        else {
            // log failure to load real dll
            char note[512];
            StringCchPrintfA(note, _countof(note), "Proxy DLL: could not locate original d3dcompiler DLL. PID=%u\r\n", GetCurrentProcessId());
            char path[MAX_PATH * 2];
            GetTempFilePathA(path, _countof(path), "D3D_Proxy_Log");
            AppendTextToFileThreadsafe(path, note);
        }

        // Start a small thread for the runtime snapshot
        unsigned tid;
        uintptr_t th = _beginthreadex(NULL, 0, &RuntimeSnapshotThread, NULL, 0, &tid);
        if (th) CloseHandle((HANDLE)th);
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        if (g_hOriginal) {
            FreeLibrary(g_hOriginal);
            g_hOriginal = NULL;
            g_pOrigD3DCompile = NULL;
        }
        if (g_initialized) {
            DeleteCriticalSection(&g_logCs);
            g_initialized = false;
        }
    }
    return TRUE;
}

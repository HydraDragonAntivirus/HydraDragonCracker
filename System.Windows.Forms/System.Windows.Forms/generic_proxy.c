/*
 * GENERIC DLL PROXY - Universal DLL Forwarder
 *
 * This creates a generic proxy that forwards ALL function calls to the original DLL.
 * Works for any DLL - just configure the ORIGINAL_DLL_NAME below.
 *
 * How it works:
 * 1. This DLL is loaded instead of the real DLL
 * 2. In DllMain, we load the original DLL (e.g., "orig.dll")
 * 3. Any call to an exported function gets forwarded automatically
 *
 * Build:
 *   Step 1: Generate exports from original DLL
 *     python generate_exports.py original.dll > exports.def
 *
 *   Step 2: Compile with exports
 *     gcc -shared -o proxy.dll generic_proxy.c exports.def -Wl,--enable-stdcall-fixup
 */

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

// Configuration - Change these for your DLL
#define ORIGINAL_DLL_NAME "orig.dll"
#define LOG_FILE "generic_proxy.log"

// Globals
static HMODULE g_hOriginalDll = NULL;
static FILE* g_logFile = NULL;
static CRITICAL_SECTION g_logLock;

// Initialize logging
void InitLog() {
    InitializeCriticalSection(&g_logLock);

    EnterCriticalSection(&g_logLock);
    g_logFile = fopen(LOG_FILE, "w");
    if (g_logFile) {
        fprintf(g_logFile, "================================================================================\n");
        fprintf(g_logFile, "           GENERIC DLL PROXY - Universal Function Forwarder\n");
        fprintf(g_logFile, "================================================================================\n");
        fprintf(g_logFile, "Target: %s\n", ORIGINAL_DLL_NAME);
        fprintf(g_logFile, "Time: %lu ms\n\n", GetTickCount());
        fflush(g_logFile);
    }
    LeaveCriticalSection(&g_logLock);
}

// Thread-safe logging
void Log(const char* format, ...) {
    if (!g_logFile) return;

    EnterCriticalSection(&g_logLock);
    va_list args;
    va_start(args, format);
    vfprintf(g_logFile, format, args);
    va_end(args);
    fprintf(g_logFile, "\n");
    fflush(g_logFile);
    LeaveCriticalSection(&g_logLock);
}

// Get full path to DLL in same directory
void GetOriginalDllPath(HINSTANCE hinstDLL, char* outPath, size_t maxLen) {
    char thisPath[MAX_PATH];
    GetModuleFileNameA(hinstDLL, thisPath, MAX_PATH);

    // Get directory
    char* lastSlash = strrchr(thisPath, '\\');
    if (lastSlash) {
        *lastSlash = '\0';
        snprintf(outPath, maxLen, "%s\\%s", thisPath, ORIGINAL_DLL_NAME);
    } else {
        snprintf(outPath, maxLen, "%s", ORIGINAL_DLL_NAME);
    }
}

// DLL Entry Point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    char originalPath[MAX_PATH];

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            InitLog();
            Log("[ATTACH] Proxy DLL loaded");

            GetOriginalDllPath(hinstDLL, originalPath, MAX_PATH);
            Log("[LOAD] Loading original DLL: %s", originalPath);

            g_hOriginalDll = LoadLibraryA(originalPath);

            if (g_hOriginalDll) {
                Log("[SUCCESS] Original DLL loaded at 0x%p", (void*)g_hOriginalDll);
            } else {
                DWORD err = GetLastError();
                Log("[FATAL] Failed to load original DLL! Error: %lu", err);
                return FALSE;
            }
            break;

        case DLL_PROCESS_DETACH:
            Log("[DETACH] Proxy DLL unloading");
            if (g_hOriginalDll) {
                FreeLibrary(g_hOriginalDll);
                g_hOriginalDll = NULL;
            }
            if (g_logFile) {
                fclose(g_logFile);
                g_logFile = NULL;
            }
            DeleteCriticalSection(&g_logLock);
            break;
    }

    return TRUE;
}

// Generic function forwarder
// This is called by the trampolines generated in exports.def
void* __stdcall GetOriginalFunction(const char* name) {
    if (!g_hOriginalDll) {
        Log("[ERROR] GetOriginalFunction(%s): Original DLL not loaded!", name);
        return NULL;
    }

    void* func = GetProcAddress(g_hOriginalDll, name);

    if (func) {
        Log("[FORWARD] %s -> 0x%p", name, func);
    } else {
        Log("[WARNING] Function not found: %s (Error: %lu)", name, GetLastError());
    }

    return func;
}

// Export for manual forwarding
__declspec(dllexport) void* ProxyGetProcAddress(const char* name) {
    return GetOriginalFunction(name);
}

// Common .NET DLL exports - forward these explicitly
__declspec(dllexport) void _CorDllMain(void) {
    Log("[CALL] _CorDllMain");
    if (g_hOriginalDll) {
        typedef void (*FuncType)(void);
        FuncType func = (FuncType)GetProcAddress(g_hOriginalDll, "_CorDllMain");
        if (func) func();
    }
}

__declspec(dllexport) void _CorExeMain(void) {
    Log("[CALL] _CorExeMain");
    if (g_hOriginalDll) {
        typedef void (*FuncType)(void);
        FuncType func = (FuncType)GetProcAddress(g_hOriginalDll, "_CorExeMain");
        if (func) func();
    }
}

__declspec(dllexport) void _CorImageUnloading(void* imageBase) {
    Log("[CALL] _CorImageUnloading(0x%p)", imageBase);
    if (g_hOriginalDll) {
        typedef void (*FuncType)(void*);
        FuncType func = (FuncType)GetProcAddress(g_hOriginalDll, "_CorImageUnloading");
        if (func) func(imageBase);
    }
}

__declspec(dllexport) int _CorValidateImage(void* imageBase, const char* fileName) {
    Log("[CALL] _CorValidateImage(0x%p, %s)", imageBase, fileName ? fileName : "NULL");
    if (g_hOriginalDll) {
        typedef int (*FuncType)(void*, const char*);
        FuncType func = (FuncType)GetProcAddress(g_hOriginalDll, "_CorValidateImage");
        if (func) return func(imageBase, fileName);
    }
    return 0;
}

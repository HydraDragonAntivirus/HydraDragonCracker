/*
 * System.Windows.Forms.dll Native Proxy
 *
 * This is a native C DLL that acts as a transparent proxy, forwarding all calls
 * to the original .NET System.Windows.Forms.dll while allowing you to intercept
 * and log function calls.
 *
 * Build with MinGW:
 *   gcc -shared -o System.Windows.Forms.dll proxy_dll.c -Wl,--enable-stdcall-fixup
 */

#include <windows.h>
#include <stdio.h>

// Global handle to the original DLL
static HMODULE hOriginalDll = NULL;
static FILE* logFile = NULL;

// Initialize logging
void InitLog() {
    if (!logFile) {
        logFile = fopen("proxy_intercept.log", "a");
        if (logFile) {
            fprintf(logFile, "\n=== System.Windows.Forms Proxy DLL Loaded ===\n");
            fprintf(logFile, "Timestamp: %lu\n\n", GetTickCount());
            fflush(logFile);
        }
    }
}

// Log function calls
void LogCall(const char* funcName) {
    if (logFile) {
        fprintf(logFile, "[CALL] %s\n", funcName);
        fflush(logFile);
    }
}

// DLL Entry Point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    char originalPath[MAX_PATH];

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            InitLog();

            // Load the original DLL (renamed to orig.dll)
            GetModuleFileNameA(hinstDLL, originalPath, MAX_PATH);

            // Get directory of current DLL
            char* lastSlash = strrchr(originalPath, '\\');
            if (lastSlash) {
                *(lastSlash + 1) = '\0';
                strcat(originalPath, "orig.dll");
            }

            hOriginalDll = LoadLibraryA(originalPath);

            if (logFile) {
                if (hOriginalDll) {
                    fprintf(logFile, "[INIT] Successfully loaded original DLL: %s\n", originalPath);
                    fprintf(logFile, "[INIT] Original DLL handle: 0x%p\n", hOriginalDll);
                } else {
                    fprintf(logFile, "[ERROR] Failed to load original DLL: %s (Error: %lu)\n",
                            originalPath, GetLastError());
                }
                fflush(logFile);
            }
            break;

        case DLL_PROCESS_DETACH:
            if (logFile) {
                fprintf(logFile, "\n=== Proxy DLL Unloading ===\n");
                fclose(logFile);
                logFile = NULL;
            }
            if (hOriginalDll) {
                FreeLibrary(hOriginalDll);
                hOriginalDll = NULL;
            }
            break;
    }

    return TRUE;
}

// Generic forwarding function
// This allows any exported function to be forwarded to the original DLL
__declspec(dllexport) void* GetOriginalFunction(const char* funcName) {
    if (!hOriginalDll) {
        return NULL;
    }

    void* func = GetProcAddress(hOriginalDll, funcName);

    if (logFile && func) {
        fprintf(logFile, "[FORWARD] %s -> 0x%p\n", funcName, func);
        fflush(logFile);
    }

    return func;
}

// For .NET DLLs, we need to export specific metadata functions
// These are the minimum exports needed for a .NET assembly

__declspec(dllexport) void _CorDllMain() {
    LogCall("_CorDllMain");
    if (hOriginalDll) {
        void* func = GetProcAddress(hOriginalDll, "_CorDllMain");
        if (func) {
            ((void(*)())func)();
        }
    }
}

__declspec(dllexport) void _CorExeMain() {
    LogCall("_CorExeMain");
    if (hOriginalDll) {
        void* func = GetProcAddress(hOriginalDll, "_CorExeMain");
        if (func) {
            ((void(*)())func)();
        }
    }
}

__declspec(dllexport) void _CorValidateImage() {
    LogCall("_CorValidateImage");
    if (hOriginalDll) {
        void* func = GetProcAddress(hOriginalDll, "_CorValidateImage");
        if (func) {
            ((void(*)())func)();
        }
    }
}

// Export the mscoree imports that .NET DLLs typically have
__declspec(dllexport) void _CorImageUnloading() {
    LogCall("_CorImageUnloading");
    if (hOriginalDll) {
        void* func = GetProcAddress(hOriginalDll, "_CorImageUnloading");
        if (func) {
            ((void(*)())func)();
        }
    }
}

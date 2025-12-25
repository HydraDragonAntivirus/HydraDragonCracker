/*
 * System.Windows.Forms.dll Native Proxy
 *
 * This native C DLL masquerades as System.Windows.Forms.dll and forwards
 * all calls to the original .NET assembly (renamed to orig.dll).
 *
 * This bypasses .NET strong-name verification because the CLR sees this as
 * a native DLL first, and we manually load/forward to the real .NET DLL.
 *
 * Build with MinGW or MSVC:
 *   gcc -shared -o System.Windows.Forms.dll System.Windows.Forms_proxy.c -Wl,--enable-stdcall-fixup
 */

#include <windows.h>
#include <stdio.h>

// Global handle to the original .NET DLL
static HMODULE hOriginalDll = NULL;
static FILE* logFile = NULL;

// Function pointer types for .NET entry points
typedef void (WINAPI *CorDllMainFunc)(void);
typedef void (WINAPI *CorExeMainFunc)(void);

// Initialize logging
void InitLog() {
    if (!logFile) {
        logFile = fopen("native_proxy.log", "a");
        if (logFile) {
            fprintf(logFile, "\n================================================================================\n");
            fprintf(logFile, "       NATIVE PROXY DLL LOADED - System.Windows.Forms Interceptor\n");
            fprintf(logFile, "================================================================================\n");
            fprintf(logFile, "Timestamp: %lu ms\n\n", GetTickCount());
            fflush(logFile);
        }
    }
}

// Log messages
void LogMessage(const char* format, ...) {
    if (logFile) {
        va_list args;
        va_start(args, format);
        vfprintf(logFile, format, args);
        va_end(args);
        fprintf(logFile, "\n");
        fflush(logFile);
    }
}

// DLL Entry Point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    char originalPath[MAX_PATH];
    char currentDir[MAX_PATH];

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            InitLog();
            LogMessage("[ATTACH] Native proxy DLL loaded");

            // Get the directory where this DLL is located
            GetModuleFileNameA(hinstDLL, originalPath, MAX_PATH);

            // Extract directory
            char* lastSlash = strrchr(originalPath, '\\');
            if (lastSlash) {
                strncpy(currentDir, originalPath, lastSlash - originalPath);
                currentDir[lastSlash - originalPath] = '\0';
            } else {
                GetCurrentDirectoryA(MAX_PATH, currentDir);
            }

            LogMessage("[INFO] Proxy DLL directory: %s", currentDir);

            // Build path to original .NET DLL
            snprintf(originalPath, MAX_PATH, "%s\\orig.dll", currentDir);

            LogMessage("[LOAD] Attempting to load original DLL: %s", originalPath);

            // Load the original .NET assembly
            hOriginalDll = LoadLibraryA(originalPath);

            if (hOriginalDll) {
                LogMessage("[SUCCESS] Original DLL loaded at: 0x%p", (void*)hOriginalDll);
            } else {
                DWORD error = GetLastError();
                LogMessage("[ERROR] Failed to load original DLL!");
                LogMessage("[ERROR] Error code: %lu", error);
                LogMessage("[ERROR] Make sure orig.dll exists in the same directory!");
                return FALSE; // Fail the load
            }
            break;

        case DLL_PROCESS_DETACH:
            LogMessage("\n[DETACH] Proxy DLL unloading");
            if (hOriginalDll) {
                FreeLibrary(hOriginalDll);
                hOriginalDll = NULL;
            }
            if (logFile) {
                fclose(logFile);
                logFile = NULL;
            }
            break;
    }

    return TRUE;
}

// Export the .NET CLR entry points
// These are required for .NET assemblies

__declspec(dllexport) void WINAPI _CorDllMain(void) {
    LogMessage("[CALL] _CorDllMain() - Forwarding to original");

    if (hOriginalDll) {
        CorDllMainFunc origFunc = (CorDllMainFunc)GetProcAddress(hOriginalDll, "_CorDllMain");
        if (origFunc) {
            LogMessage("[FORWARD] Calling original _CorDllMain at 0x%p", (void*)origFunc);
            origFunc();
        } else {
            LogMessage("[WARNING] _CorDllMain not found in original DLL (Error: %lu)", GetLastError());
        }
    } else {
        LogMessage("[ERROR] Original DLL not loaded!");
    }
}

__declspec(dllexport) void WINAPI _CorExeMain(void) {
    LogMessage("[CALL] _CorExeMain() - Forwarding to original");

    if (hOriginalDll) {
        CorExeMainFunc origFunc = (CorExeMainFunc)GetProcAddress(hOriginalDll, "_CorExeMain");
        if (origFunc) {
            LogMessage("[FORWARD] Calling original _CorExeMain at 0x%p", (void*)origFunc);
            origFunc();
        } else {
            LogMessage("[WARNING] _CorExeMain not found in original DLL");
        }
    }
}

__declspec(dllexport) void WINAPI _CorImageUnloading(void* imageBase) {
    LogMessage("[CALL] _CorImageUnloading(0x%p)", imageBase);

    if (hOriginalDll) {
        typedef void (WINAPI *CorImageUnloadingFunc)(void*);
        CorImageUnloadingFunc origFunc = (CorImageUnloadingFunc)GetProcAddress(hOriginalDll, "_CorImageUnloading");
        if (origFunc) {
            origFunc(imageBase);
        }
    }
}

__declspec(dllexport) HRESULT WINAPI _CorValidateImage(void* imageBase, const char* fileName) {
    LogMessage("[CALL] _CorValidateImage(0x%p, %s)", imageBase, fileName ? fileName : "NULL");

    if (hOriginalDll) {
        typedef HRESULT (WINAPI *CorValidateImageFunc)(void*, const char*);
        CorValidateImageFunc origFunc = (CorValidateImageFunc)GetProcAddress(hOriginalDll, "_CorValidateImage");
        if (origFunc) {
            return origFunc(imageBase, fileName);
        }
    }

    return S_OK; // Return success if we can't forward
}

// Generic export forwarder
// This allows any function to be forwarded dynamically
__declspec(dllexport) void* GetOriginalProcAddress(const char* procName) {
    if (!hOriginalDll) {
        LogMessage("[ERROR] GetOriginalProcAddress: Original DLL not loaded!");
        return NULL;
    }

    void* proc = GetProcAddress(hOriginalDll, procName);
    if (proc) {
        LogMessage("[FORWARD] %s -> 0x%p", procName, proc);
    } else {
        LogMessage("[WARNING] Function not found: %s", procName);
    }

    return proc;
}

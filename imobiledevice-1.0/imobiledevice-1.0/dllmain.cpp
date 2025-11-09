#include "pch.h"
#include <stdio.h>

#define EXPORT_FUNC extern "C" __declspec(dllexport)

// Define types for the functions you want to spy on
typedef long HRESULT;
typedef struct lockdownd_client_private* lockdownd_client_t;

// Globals for logging
FILE* g_logFile = NULL;
CRITICAL_SECTION g_logCs;

void LogToFile(const char* format, ...) {
    EnterCriticalSection(&g_logCs);
    va_list args;
    va_start(args, format);
    vfprintf(g_logFile, format, args);
    va_end(args);
    fflush(g_logFile);
    LeaveCriticalSection(&g_logCs);
}

HMODULE hOriginalDll = NULL;

// Pointers for ONLY the functions you spy on
typedef HRESULT(*t_lockdown_get_device_name)(lockdownd_client_t client, char** device_name);
t_lockdown_get_device_name p_lockdown_get_device_name = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_logCs);
        fopen_s(&g_logFile, "log.txt", "w");
        LogToFile("=========================================================\n");
        LogToFile("FINAL Spy Wrapper Injected. This one will work.\n");
        LogToFile("=========================================================\n\n");

        hOriginalDll = LoadLibraryA("orig.dll");
        if (!hOriginalDll) {
            MessageBoxA(NULL, "FATAL ERROR: Could not load orig.dll!", "Wrapper Error", MB_OK);
            return FALSE;
        }

        p_lockdown_get_device_name = (t_lockdown_get_device_name)GetProcAddress(hOriginalDll, "lockdown_get_device_name");
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        if (g_logFile) fclose(g_logFile);
        DeleteCriticalSection(&g_logCs);
        if (hOriginalDll) FreeLibrary(hOriginalDll);
    }
    return TRUE;
}

// Your spy function
EXPORT_FUNC HRESULT lockdown_get_device_name(lockdownd_client_t client, char** device_name) {
    LogToFile("[SPY] Intercepted lockdown_get_device_name()\n");
    MessageBoxA(NULL, "Intercepted a call to lockdown_get_device_name()!", "Spy Alert!", MB_OK);

    if (p_lockdown_get_device_name) {
        HRESULT result = p_lockdown_get_device_name(client, device_name);
        LogToFile("  [SPY-RETURN] Device Name: \"%s\"\n", (device_name && *device_name ? *device_name : "NULL"));
        return result;
    }
    return -1; // Or some other error
}

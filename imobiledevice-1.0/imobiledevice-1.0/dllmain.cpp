#include "pch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ====================================================================================
// SETUP, LOGGING, and DEFINITIONS
// ====================================================================================

#define EXPORT_FUNC extern "C" __declspec(dllexport)

// --- Define types to make the code readable ---
typedef struct idevice_private* idevice_t;
typedef struct lockdownd_client_private* lockdownd_client_t;
typedef struct property_list_private* plist_t;
typedef long HRESULT;

const HRESULT IDEVICE_E_SUCCESS = 0;
const HRESULT LOCKDOWN_E_SUCCESS = 0;

// --- Globals for logging and the original DLL ---
FILE* g_logFile = NULL;
CRITICAL_SECTION g_logCs;
HMODULE hOriginalDll = NULL;

void LogToFile(const char* format, ...) {
    EnterCriticalSection(&g_logCs);
    va_list args;
    va_start(args, format);
    vfprintf(g_logFile, format, args);
    va_end(args);
    fflush(g_logFile);
    LeaveCriticalSection(&g_logCs);
}

// --- Pointers for the REAL functions we need to call ---
typedef plist_t(*t_plist_new_string)(const char* val);
t_plist_new_string p_plist_new_string = NULL;

// ====================================================================================
// DLLMAIN
// ====================================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_logCs);
        fopen_s(&g_logFile, "log.txt", "w");
        LogToFile("=========================================================\n");
        LogToFile("SERVER FORGERY ENGINE INJECTED. Faking activation status...\n");
        LogToFile("=========================================================\n\n");

        hOriginalDll = LoadLibraryA("orig.dll");
        if (!hOriginalDll) {
            MessageBoxA(NULL, "FATAL ERROR: Could not load orig.dll!", "Wrapper Error", MB_OK);
            return FALSE;
        }

        // We need to call a REAL function from the DLL to create our fake response.
        // So, we must get its address.
        p_plist_new_string = (t_plist_new_string)GetProcAddress(hOriginalDll, "plist_new_string");
        if (!p_plist_new_string) {
            MessageBoxA(NULL, "FATAL ERROR: Could not get address for plist_new_string!", "Wrapper Error", MB_OK);
            return FALSE;
        }
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        if (g_logFile) fclose(g_logFile);
        DeleteCriticalSection(&g_logCs);
        if (hOriginalDll) FreeLibrary(hOriginalDll);
    }
    return TRUE;
}

// ====================================================================================
// FAKE FUNCTIONS
// ====================================================================================

// --- THE FINAL FAKE: Intercept the check for "ActivationState" ---
EXPORT_FUNC HRESULT lockdownd_get_value(lockdownd_client_t client, const char* domain, const char* key, plist_t* pvalue)
{
    LogToFile("[FINAL FAKE] Intercepted lockdownd_get_value(domain: %s, key: %s)\n", (domain ? domain : "NULL"), (key ? key : "NULL"));

    // Check if the application is asking for the activation status.
    if (key && strcmp(key, "ActivationState") == 0)
    {
        LogToFile("  --> App is asking for ActivationState. LYING!\n");
        MessageBoxA(NULL, "App is asking for activation status... We're going to lie and say 'Activated'!", "Final Deception", MB_OK);

        // We will create a fake response that says "Activated".
        // To do this, we must call a REAL function from the original DLL to create a valid plist object.
        *pvalue = p_plist_new_string("Activated");

        LogToFile("  [FAKE-RETURN] Returning SUCCESS with a fake plist containing 'Activated'.\n");
        return LOCKDOWN_E_SUCCESS;
    }

    // If the app asks for any other key, we can just say we didn't find it.
    LogToFile("  --> App is asking for something else. Returning NOT_FOUND.\n");
    *pvalue = NULL;
    // Returning a "not found" error is safer than crashing.
    const HRESULT LOCKDOWN_E_NO_SUCH_KEY = -4;
    return LOCKDOWN_E_NO_SUCH_KEY;
}


// --- Previous fakes are still needed to get to this stage! ---

EXPORT_FUNC HRESULT idevice_get_device_list(char*** devices, int* count) {
    LogToFile("[FAKE] Intercepted idevice_get_device_list(). Giving the app a FAKE device!\n");
    const char* fake_udid = "f1d2d3d4d5d6d7d8d9d0d1d2d3d4d5d6d7d8d9d0";
    char** device_list = (char**)malloc(sizeof(char*) * 2);
    device_list[0] = (char*)malloc(strlen(fake_udid) + 1);
    strcpy_s(device_list[0], strlen(fake_udid) + 1, fake_udid);
    device_list[1] = NULL;
    *devices = device_list;
    *count = 1;
    LogToFile("  [FAKE-RETURN] Returning SUCCESS with 1 fake device.\n");
    return IDEVICE_E_SUCCESS;
}

EXPORT_FUNC HRESULT idevice_device_list_free(char** devices) {
    LogToFile("[FAKE] Intercepted idevice_device_list_free(). Cleaning up fake list.\n");
    if (devices) {
        if (devices[0]) free(devices[0]);
        free(devices);
    }
    return IDEVICE_E_SUCCESS;
}

EXPORT_FUNC HRESULT idevice_new(idevice_t* device, const char* udid) {
    LogToFile("[FAKE] Intercepted idevice_new().\n");
    *device = (idevice_t)0xDEADBEEF;
    return IDEVICE_E_SUCCESS;
}

EXPORT_FUNC HRESULT lockdownd_client_new_with_handshake(idevice_t device, lockdownd_client_t* client, const char* label) {
    LogToFile("[FAKE] Intercepted lockdownd_client_new_with_handshake().\n");
    *client = (lockdownd_client_t)0xCAFEF00D;
    return LOCKDOWN_E_SUCCESS;
}

EXPORT_FUNC HRESULT lockdownd_pair(lockdownd_client_t client, plist_t* pair_record) {
    LogToFile("[FAKE] Intercepted lockdownd_pair().\n");
    return LOCKDOWN_E_SUCCESS;
}

EXPORT_FUNC HRESULT idevice_free(idevice_t device) {
    LogToFile("[FAKE] Intercepted idevice_free().\n");
    return IDEVICE_E_SUCCESS;
}

EXPORT_FUNC HRESULT lockdownd_client_free(lockdownd_client_t client) {
    LogToFile("[FAKE] Intercepted lockdownd_client_free().\n");
    return LOCKDOWN_E_SUCCESS;
}

// We also need to fake the cleanup for the plist we created.
EXPORT_FUNC void plist_free(plist_t plist) {
    LogToFile("[FAKE] Intercepted plist_free() for our fake 'Activated' response. Doing nothing.\n");
    // We don't call the real function because our handle is fake.
}

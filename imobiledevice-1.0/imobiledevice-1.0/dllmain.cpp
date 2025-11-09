#include "pch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPORT_FUNC extern "C" __declspec(dllexport)

// --- Define types to make the code readable ---
typedef struct idevice_private* idevice_t;
typedef struct lockdownd_client_private* lockdownd_client_t;
typedef struct property_list_private* plist_t;
typedef long HRESULT;

const HRESULT IDEVICE_E_SUCCESS = 0;
const HRESULT LOCKDOWN_E_SUCCESS = 0;

// --- Globals ---
FILE* g_logFile = NULL;
CRITICAL_SECTION g_logCs;
HMODULE hOriginalDll = NULL;
HMODULE hJsonDll = NULL; // A handle for the SEPARATE JSON library

void LogToFile(const char* format, ...) {
    EnterCriticalSection(&g_logCs);
    va_list args;
    va_start(args, format);
    vfprintf(g_logFile, format, args);
    va_end(args);
    fflush(g_logFile);
    LeaveCriticalSection(&g_logCs);
}

// --- Pointers for the REAL JSON functions we need to call ---
// These will be loaded from the correct DLL.
typedef plist_t(*t_json_object_new_object)();
typedef int (*t_json_object_object_add)(plist_t obj, const char* key, plist_t val);
typedef plist_t(*t_json_object_new_string)(const char* s);

t_json_object_new_object p_json_object_new_object = NULL;
t_json_object_object_add p_json_object_object_add = NULL;
t_json_object_new_string p_json_object_new_string = NULL;

// ====================================================================================
// DLLMAIN
// ====================================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_logCs);
        fopen_s(&g_logFile, "log.txt", "w");
        LogToFile("=========================================================\n");
        LogToFile("FINAL Corrected Spy Engine Injected.\n");
        LogToFile("=========================================================\n\n");

        // --- Load the ORIGINAL imobiledevice DLL ---
        hOriginalDll = LoadLibraryA("orig.dll");
        if (!hOriginalDll) {
            MessageBoxA(NULL, "FATAL ERROR: Could not load orig.dll!", "Wrapper Error", MB_OK);
            return FALSE;
        }
        LogToFile("Successfully loaded original imobiledevice DLL: orig.dll\n");

        // --- Find the JSON DLL that the main application has already loaded ---
        // Common names are libjson-c.dll, json-c.dll, or similar. We will try a few.
        hJsonDll = GetModuleHandleA("libjson-c.dll");
        if (!hJsonDll) hJsonDll = GetModuleHandleA("json-c-5.dll"); // Another common name
        if (!hJsonDll) hJsonDll = GetModuleHandleA("json-c.dll");
        // Add more names if needed by inspecting the app with Process Explorer.

        if (!hJsonDll) {
            MessageBoxA(NULL, "FATAL ERROR: Could not find the JSON library loaded by the application!", "Wrapper Error", MB_OK);
            return FALSE;
        }
        LogToFile("Successfully found the application's JSON DLL handle.\n\n");

        // --- Get the addresses of the REAL JSON functions from the correct library ---
        p_json_object_new_object = (t_json_object_new_object)GetProcAddress(hJsonDll, "json_object_new_object");
        p_json_object_object_add = (t_json_object_object_add)GetProcAddress(hJsonDll, "json_object_object_add");
        p_json_object_new_string = (t_json_object_new_string)GetProcAddress(hJsonDll, "json_object_new_string");

        if (!p_json_object_new_object || !p_json_object_object_add || !p_json_object_new_string) {
            MessageBoxA(NULL, "FATAL ERROR: Could not get addresses for JSON helper functions from its DLL!", "Wrapper Error", MB_OK);
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

// --- THE FINAL FAKE: Intercept the query for device info and inject our own info ---
EXPORT_FUNC HRESULT diagnostics_relay_query_mobilegestalt(lockdownd_client_t client, plist_t keys, plist_t* result)
{
    LogToFile("[FINAL FAKE] Intercepted diagnostics_relay_query_mobilegestalt().\n");
    MessageBoxA(NULL, "App is asking for device info... Faking the response now!", "Final Deception", MB_OK);

    plist_t fake_response = p_json_object_new_object();
    if (!fake_response) {
        return -1; // Error
    }

    plist_t activated_value = p_json_object_new_string("Activated");
    p_json_object_object_add(fake_response, "ActivationState", activated_value);

    *result = fake_response;

    LogToFile("  [FAKE-RETURN] Returning SUCCESS with a custom-built plist containing 'Activated'.\n");
    return LOCKDOWN_E_SUCCESS;
}

// --- All previous fakes are still needed to get to this stage! ---

EXPORT_FUNC HRESULT idevice_get_device_list(char*** devices, int* count) {
    LogToFile("[FAKE] Intercepted idevice_get_device_list().\n");
    const char* fake_udid = "f1d2d3d4d5d6d7d8d9d0d1d2d3d4d5d6d7d8d9d0";
    char** device_list = (char**)malloc(sizeof(char*) * 2);
    device_list[0] = (char*)malloc(strlen(fake_udid) + 1);
    strcpy_s(device_list[0], strlen(fake_udid) + 1, fake_udid);
    device_list[1] = NULL;
    *devices = device_list;
    *count = 1;
    return IDEVICE_E_SUCCESS;
}

EXPORT_FUNC HRESULT idevice_device_list_free(char** devices) {
    LogToFile("[FAKE] Intercepted idevice_device_list_free().\n");
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

// Intercept the cleanup function for the JSON objects, but do nothing.
EXPORT_FUNC void json_object_put(plist_t obj) {
    LogToFile("[FAKE] Intercepted json_object_put() (cleanup for our fake plist). Doing nothing to prevent crash.\n");
}

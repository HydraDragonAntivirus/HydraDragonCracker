#include "pch.h"
#include <stdio.h>
#include <stdlib.h> // for malloc
#include <string.h> // for strcpy

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

// ====================================================================================
// DLLMAIN
// ====================================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_logCs);
        fopen_s(&g_logFile, "log.txt", "w");
        LogToFile("=========================================================\n");
        LogToFile("MASTER DECEPTION ENGINE INJECTED. Faking device list...\n");
        LogToFile("=========================================================\n\n");

        hOriginalDll = LoadLibraryA("orig.dll");
        if (!hOriginalDll) {
            MessageBoxA(NULL, "FATAL ERROR: Could not load orig.dll!", "Wrapper Error", MB_OK);
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
// FAKE FUNCTIONS - This is where we lie to the application
// ====================================================================================

// --- FAKE #1: The most important one! Pretend a device is connected. ---
EXPORT_FUNC HRESULT idevice_get_device_list(char*** devices, int* count) {
    LogToFile("[MASTER FAKE] Intercepted idevice_get_device_list(). Giving the app a FAKE device!\n");

    // 1. Create a fake UDID. It must be a 40-character hex string.
    const char* fake_udid = "f1d2d3d4d5d6d7d8d9d0d1d2d3d4d5d6d7d8d9d0";

    // 2. Allocate memory for the list of devices. We need space for one device + a NULL terminator.
    char** device_list = (char**)malloc(sizeof(char*) * 2);

    // 3. Allocate memory for our fake UDID string and copy it.
    device_list[0] = (char*)malloc(strlen(fake_udid) + 1);
    strcpy_s(device_list[0], strlen(fake_udid) + 1, fake_udid);

    // 4. The list must end with a NULL pointer.
    device_list[1] = NULL;

    // 5. Give the fake list and count back to the application.
    *devices = device_list;
    *count = 1;

    LogToFile("  [FAKE-RETURN] Returning SUCCESS with 1 fake device (UDID: %s)\n", fake_udid);
    return IDEVICE_E_SUCCESS; // Return 0 for success
}

// --- FAKE #2: Safely handle the cleanup of our fake device list. ---
EXPORT_FUNC HRESULT idevice_device_list_free(char** devices) {
    LogToFile("[FAKE] Intercepted idevice_device_list_free(). Cleaning up our fake list.\n");

    // We must free the memory we allocated in our fake idevice_get_device_list.
    if (devices) {
        if (devices[0]) {
            LogToFile("  - Freeing fake UDID string.\n");
            free(devices[0]);
        }
        LogToFile("  - Freeing fake device list array.\n");
        free(devices);
    }
    return IDEVICE_E_SUCCESS;
}

// --- FAKE #3: Pretend we can connect to the fake device. ---
EXPORT_FUNC HRESULT idevice_new(idevice_t* device, const char* udid) {
    LogToFile("[FAKE] Intercepted idevice_new(). App is trying to connect to our fake device: %s\n", udid);
    *device = (idevice_t)0xDEADBEEF; // Give it a fake handle.
    LogToFile("  [FAKE-RETURN] Returning SUCCESS and fake device handle 0x%p\n", *device);
    return IDEVICE_E_SUCCESS;
}

// --- FAKE #4: Pretend the secure connection always works. ---
EXPORT_FUNC HRESULT lockdownd_client_new_with_handshake(idevice_t device, lockdownd_client_t* client, const char* label) {
    LogToFile("[FAKE] Intercepted lockdownd_client_new_with_handshake(). Faking the handshake!\n");
    *client = (lockdownd_client_t)0xCAFEF00D;
    LogToFile("  [FAKE-RETURN] Returning SUCCESS and fake client handle 0x%p\n", *client);
    return LOCKDOWN_E_SUCCESS;
}

// --- FAKE #5: Pretend the device is always paired. ---
EXPORT_FUNC HRESULT lockdownd_pair(lockdownd_client_t client, plist_t* pair_record) {
    LogToFile("[FAKE] Intercepted lockdownd_pair(). Saying the device is already paired!\n");
    LogToFile("  [FAKE-RETURN] Returning SUCCESS.\n");
    return LOCKDOWN_E_SUCCESS;
}

// --- FAKE #6: Handle cleanup of our other fake handles. ---
EXPORT_FUNC HRESULT idevice_free(idevice_t device) {
    LogToFile("[FAKE] Intercepted idevice_free(). Cleaning up fake device handle (0x%p).\n", device);
    return IDEVICE_E_SUCCESS;
}

EXPORT_FUNC HRESULT lockdownd_client_free(lockdownd_client_t client) {
    LogToFile("[FAKE] Intercepted lockdownd_client_free(). Cleaning up fake client handle (0x%p).\n", client);
    return LOCKDOWN_E_SUCCESS;
}

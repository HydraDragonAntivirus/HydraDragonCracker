#include "pch.h"
#include <stdio.h>
#include <string.h>

// ====================================================================================
// SETUP & LOGGING
// ====================================================================================
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

// ====================================================================================
// THE HIJACK - Our Fake MessageBoxA
// ====================================================================================
typedef int (WINAPI* t_MessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
t_MessageBoxA p_OriginalMessageBoxA = NULL;

int WINAPI Hooked_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    LogToFile("[IAT HIJACK] Intercepted a call to MessageBoxA!\n");
    LogToFile("  --> Caption: %s\n", lpCaption);
    LogToFile("  --> Text: %s\n", lpText);

    // Check if the application is trying to show the error message.
    if (lpText && strstr(lpText, "Server unavailable or invalid response"))
    {
        LogToFile("  --> DETECTED SERVER ERROR! Faking success...\n");

        // Instead of showing the error, we call the REAL MessageBoxA with our success message.
        return p_OriginalMessageBoxA(NULL,
            "[+] Device Successfully Activated!\n\n(Bypassed by God Mode Wrapper)",
            "Success!",
            MB_OK | MB_ICONINFORMATION);
    }

    // If it's not the error message, let the original function run.
    return p_OriginalMessageBoxA(hWnd, lpText, lpCaption, uType);
}

// ====================================================================================
// THE SURGICAL ENGINE - IAT Patcher
// ====================================================================================
void Perform_IAT_Hook()
{
    HMODULE hAppBase = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hAppBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hAppBase + pDosHeader->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hAppBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    LogToFile("Starting IAT scan on main application...\n");

    while (pImportDesc->Name)
    {
        char* dllName = (char*)((BYTE*)hAppBase + pImportDesc->Name);
        if (_stricmp(dllName, "user32.dll") == 0)
        {
            LogToFile("  - Found user32.dll imports.\n");
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hAppBase + pImportDesc->FirstThunk);
            PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)((BYTE*)hAppBase + pImportDesc->OriginalFirstThunk);

            while (pOrigThunk->u1.AddressOfData)
            {
                PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hAppBase + pOrigThunk->u1.AddressOfData);
                if (strcmp(pImportByName->Name, "MessageBoxA") == 0)
                {
                    LogToFile("    --> Found MessageBoxA entry. Patching now...\n");
                    DWORD oldProtect;
                    VirtualProtect(&pThunk->u1.Function, sizeof(uintptr_t), PAGE_READWRITE, &oldProtect);
                    p_OriginalMessageBoxA = (t_MessageBoxA)pThunk->u1.Function;
                    pThunk->u1.Function = (uintptr_t)Hooked_MessageBoxA;
                    VirtualProtect(&pThunk->u1.Function, sizeof(uintptr_t), oldProtect, &oldProtect);
                    LogToFile("IAT Hook successful!\n");
                    return;
                }
                pOrigThunk++;
                pThunk++;
            }
        }
        pImportDesc++;
    }
}

// ====================================================================================
// DLLMAIN
// ====================================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // This DllMain belongs to our wrapper, "imobiledevice-1.0.dll"
        InitializeCriticalSection(&g_logCs);
        fopen_s(&g_logFile, "log.txt", "w");
        LogToFile("=========================================================\n");
        LogToFile("God Mode Wrapper Injected. All functions forwarded.\n");
        LogToFile("Now performing surgical strike on the main application...\n");
        LogToFile("=========================================================\n\n");

        // The .def file is already handling the redirection of the 312 functions.
        // Our only job here is to perform the IAT hook.
        Perform_IAT_Hook();
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        if (g_logFile) fclose(g_logFile);
        DeleteCriticalSection(&g_logCs);
    }
    return TRUE;
}

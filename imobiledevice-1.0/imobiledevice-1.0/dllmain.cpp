#include "pch.h"
#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")

// ====================================================================================
// GLOBAL STATE
// ====================================================================================
FILE* g_logFile = NULL;
HINTERNET g_fakeSession = (HINTERNET)0xDEADBEEF;
HINTERNET g_fakeConnection = (HINTERNET)0xCAFEBABE;
HINTERNET g_fakeRequest = (HINTERNET)0xBAADF00D;

void LogToFile(const char* format, ...) {
    if (!g_logFile) {
        fopen_s(&g_logFile, "C:\\bypass_log.txt", "a");
    }
    if (g_logFile) {
        va_list args;
        va_start(args, format);
        vfprintf(g_logFile, format, args);
        va_end(args);
        fflush(g_logFile);
    }
}

// ====================================================================================
// FAKE HANDLES TRACKING
// ====================================================================================
bool IsFakeHandle(HINTERNET h) {
    return (h == g_fakeSession || h == g_fakeConnection || h == g_fakeRequest);
}

// ====================================================================================
// ORIGINAL FUNCTION POINTERS
// ====================================================================================
typedef HINTERNET(WINAPI* pInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET(WINAPI* pInternetConnectA)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET(WINAPI* pHttpOpenRequestA)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* pHttpSendRequestA)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL(WINAPI* pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* pInternetCloseHandle)(HINTERNET);
typedef BOOL(WINAPI* pHttpQueryInfoA)(HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD);

pInternetOpenA Real_InternetOpenA = NULL;
pInternetConnectA Real_InternetConnectA = NULL;
pHttpOpenRequestA Real_HttpOpenRequestA = NULL;
pHttpSendRequestA Real_HttpSendRequestA = NULL;
pInternetReadFile Real_InternetReadFile = NULL;
pInternetCloseHandle Real_InternetCloseHandle = NULL;
pHttpQueryInfoA Real_HttpQueryInfoA = NULL;

// ====================================================================================
// HOOKED FUNCTIONS - Complete fake implementation
// ====================================================================================
HINTERNET WINAPI Hook_InternetOpenA(
    LPCSTR lpszAgent,
    DWORD dwAccessType,
    LPCSTR lpszProxy,
    LPCSTR lpszProxyBypass,
    DWORD dwFlags
) {
    LogToFile("[HOOK] InternetOpenA\n");
    LogToFile("  Agent: %s\n", lpszAgent ? lpszAgent : "NULL");
    LogToFile("  --> Returning fake session handle: 0x%p\n", g_fakeSession);
    return g_fakeSession;
}

HINTERNET WINAPI Hook_InternetConnectA(
    HINTERNET hInternet,
    LPCSTR lpszServerName,
    INTERNET_PORT nServerPort,
    LPCSTR lpszUserName,
    LPCSTR lpszPassword,
    DWORD dwService,
    DWORD dwFlags,
    DWORD_PTR dwContext
) {
    LogToFile("[HOOK] InternetConnectA\n");
    LogToFile("  Server: %s:%d\n", lpszServerName ? lpszServerName : "NULL", nServerPort);

    if (IsFakeHandle(hInternet)) {
        LogToFile("  --> Returning fake connection handle: 0x%p\n", g_fakeConnection);
        return g_fakeConnection;
    }

    return Real_InternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

HINTERNET WINAPI Hook_HttpOpenRequestA(
    HINTERNET hConnect,
    LPCSTR lpszVerb,
    LPCSTR lpszObjectName,
    LPCSTR lpszVersion,
    LPCSTR lpszReferrer,
    LPCSTR* lplpszAcceptTypes,
    DWORD dwFlags,
    DWORD_PTR dwContext
) {
    LogToFile("[HOOK] HttpOpenRequestA\n");
    LogToFile("  Verb: %s\n", lpszVerb ? lpszVerb : "NULL");
    LogToFile("  Object: %s\n", lpszObjectName ? lpszObjectName : "NULL");

    if (IsFakeHandle(hConnect)) {
        LogToFile("  --> Returning fake request handle: 0x%p\n", g_fakeRequest);
        return g_fakeRequest;
    }

    return Real_HttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
}

BOOL WINAPI Hook_HttpSendRequestA(
    HINTERNET hRequest,
    LPCSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength
) {
    LogToFile("[HOOK] HttpSendRequestA\n");

    if (IsFakeHandle(hRequest)) {
        LogToFile("  --> Fake request detected, returning SUCCESS\n");
        SetLastError(ERROR_SUCCESS);
        return TRUE;
    }

    return Real_HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}

BOOL WINAPI Hook_InternetReadFile(
    HINTERNET hFile,
    LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead,
    LPDWORD lpdwNumberOfBytesRead
) {
    LogToFile("[HOOK] InternetReadFile\n");

    if (IsFakeHandle(hFile)) {
        // Return successful activation response
        const char* response =
            "{\"success\":true,\"activated\":true,\"status\":\"active\",\"message\":\"Device activated successfully\"}";

        size_t len = strlen(response);
        if (len <= dwNumberOfBytesToRead) {
            memcpy(lpBuffer, response, len);
            *lpdwNumberOfBytesRead = (DWORD)len;
            LogToFile("  --> Returned fake SUCCESS response (%d bytes)\n", len);
            SetLastError(ERROR_SUCCESS);
            return TRUE;
        }
    }

    return Real_InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
}

BOOL WINAPI Hook_InternetCloseHandle(HINTERNET hInternet) {
    LogToFile("[HOOK] InternetCloseHandle (0x%p)\n", hInternet);

    if (IsFakeHandle(hInternet)) {
        LogToFile("  --> Fake handle closed successfully\n");
        return TRUE;
    }

    return Real_InternetCloseHandle(hInternet);
}

BOOL WINAPI Hook_HttpQueryInfoA(
    HINTERNET hRequest,
    DWORD dwInfoLevel,
    LPVOID lpBuffer,
    LPDWORD lpdwBufferLength,
    LPDWORD lpdwIndex
) {
    LogToFile("[HOOK] HttpQueryInfoA (InfoLevel: 0x%X)\n", dwInfoLevel);

    if (IsFakeHandle(hRequest)) {
        // Return HTTP 200 OK status
        if (dwInfoLevel == HTTP_QUERY_STATUS_CODE) {
            const char* statusCode = "200";
            size_t len = strlen(statusCode);

            if (*lpdwBufferLength >= len + 1) {
                strcpy_s((char*)lpBuffer, *lpdwBufferLength, statusCode);
                *lpdwBufferLength = (DWORD)len;
                LogToFile("  --> Returned status code: 200\n");
                return TRUE;
            }
        }
        return TRUE;
    }

    return Real_HttpQueryInfoA(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex);
}

// ====================================================================================
// INLINE HOOKING ENGINE
// ====================================================================================
bool HookFunction(const char* dllName, const char* funcName, void* hookFunc, void** originalFunc) {
    HMODULE hDll = GetModuleHandleA(dllName);
    if (!hDll) {
        hDll = LoadLibraryA(dllName);
        if (!hDll) {
            LogToFile("  [!] Failed to load %s\n", dllName);
            return false;
        }
    }

    void* targetFunc = GetProcAddress(hDll, funcName);
    if (!targetFunc) {
        LogToFile("  [!] Failed to find %s in %s\n", funcName, dllName);
        return false;
    }

    DWORD oldProtect;
    if (!VirtualProtect(targetFunc, 14, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        LogToFile("  [!] VirtualProtect failed for %s\n", funcName);
        return false;
    }

    // Save original bytes
    BYTE* trampoline = (BYTE*)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) {
        LogToFile("  [!] Failed to allocate trampoline for %s\n", funcName);
        return false;
    }

    memcpy(trampoline, targetFunc, 14);
    trampoline[14] = 0xFF;
    trampoline[15] = 0x25;
    *(DWORD*)(trampoline + 16) = 0;
    *(UINT64*)(trampoline + 20) = (UINT64)targetFunc + 14;

    *originalFunc = trampoline;

    // Install hook
    BYTE jump[14];
    jump[0] = 0xFF;
    jump[1] = 0x25;
    *(DWORD*)(jump + 2) = 0;
    *(UINT64*)(jump + 6) = (UINT64)hookFunc;

    memcpy(targetFunc, jump, 14);
    VirtualProtect(targetFunc, 14, oldProtect, &oldProtect);

    LogToFile("  [+] Hooked %s successfully\n", funcName);
    return true;
}

// ====================================================================================
// INSTALL ALL HOOKS
// ====================================================================================
void InstallAllHooks() {
    LogToFile("\n========================================\n");
    LogToFile("INSTALLING COMPREHENSIVE HOOKS\n");
    LogToFile("========================================\n\n");

    HookFunction("wininet.dll", "InternetOpenA", Hook_InternetOpenA, (void**)&Real_InternetOpenA);
    HookFunction("wininet.dll", "InternetConnectA", Hook_InternetConnectA, (void**)&Real_InternetConnectA);
    HookFunction("wininet.dll", "HttpOpenRequestA", Hook_HttpOpenRequestA, (void**)&Real_HttpOpenRequestA);
    HookFunction("wininet.dll", "HttpSendRequestA", Hook_HttpSendRequestA, (void**)&Real_HttpSendRequestA);
    HookFunction("wininet.dll", "InternetReadFile", Hook_InternetReadFile, (void**)&Real_InternetReadFile);
    HookFunction("wininet.dll", "InternetCloseHandle", Hook_InternetCloseHandle, (void**)&Real_InternetCloseHandle);
    HookFunction("wininet.dll", "HttpQueryInfoA", Hook_HttpQueryInfoA, (void**)&Real_HttpQueryInfoA);

    LogToFile("\n========================================\n");
    LogToFile("ALL HOOKS INSTALLED SUCCESSFULLY\n");
    LogToFile("========================================\n\n");
}

// ====================================================================================
// DLL ENTRY
// ====================================================================================
DWORD WINAPI InitThread(LPVOID lpParam) {
    Sleep(50);

    LogToFile("\n*** ACTIVATION BYPASS LOADED ***\n\n");
    InstallAllHooks();
    LogToFile("\n[*] Ready to intercept network calls\n\n");

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, InitThread, NULL, 0, NULL);
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        if (g_logFile) {
            fclose(g_logFile);
        }
    }

    return TRUE;
}

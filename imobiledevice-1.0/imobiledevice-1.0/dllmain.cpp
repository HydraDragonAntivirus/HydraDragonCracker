#include "pch.h"
#include <stdio.h>

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
// OUR NEW FAKE FUNCTION - This is what the app will run INSTEAD of its error function
// ====================================================================================

// This function has the same "signature" (calling convention, arguments) as a standard
// function that shows a message. We are guessing it takes some arguments, but we will ignore them.
void __cdecl Hooked_ShowSuccessMessage()
{
    LogToFile("[SURGERY] The application tried to show an error, but we hijacked it!\n");

    // Instead of showing the error, we show the success message.
    MessageBoxA(NULL,
        "[+] Device Successfully Activated!\n\n(Bypassed by Runtime Patcher)",
        "Success!",
        MB_OK | MB_ICONINFORMATION);

    LogToFile("  --> Displayed 'Device Successfully Activated!' message instead.\n");

    // In a more complex patch, you might need to clean up the stack or jump back.
    // For just showing a message and stopping, this is often enough.
    // To be safe, we can exit the thread or process.
    // ExitProcess(0); // Uncomment this to close the app immediately after showing success.
}


// ====================================================================================
// THE PATCHING ENGINE
// ====================================================================================

void PlaceHook(void* targetAddress, void* hookFunction)
{
    DWORD oldProtect;
    // 1. We need to get the memory address of the main .exe file.
    HMODULE appBase = GetModuleHandle(NULL);
    // 2. Calculate the real-time address of our target function.
    // The address from the debugger is a "relative" address (RVA).
    void* absoluteTargetAddress = (char*)appBase + (uintptr_t)targetAddress;

    LogToFile("Attempting to patch memory...\n");
    LogToFile("  - Application Base Address: 0x%p\n", appBase);
    LogToFile("  - Target Function RVA: 0x%p\n", targetAddress);
    LogToFile("  - Absolute Target Address: 0x%p\n", absoluteTargetAddress);
    LogToFile("  - Our Hook Function Address: 0x%p\n", hookFunction);

    // 3. Make the memory writable. By default, code sections are read-only.
    if (!VirtualProtect(absoluteTargetAddress, 14, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        LogToFile("  --> FATAL: VirtualProtect failed! Error: %d\n", GetLastError());
        return;
    }

    // 4. Construct the 64-bit absolute jump instruction.
    // This is the machine code for: JMP [address]
    // FF 25 00 00 00 00 -> JMP QWORD PTR [RIP+0]
    // Then the 8-byte address of our hook function.
    unsigned char patch[14];
    patch[0] = 0xFF;
    patch[1] = 0x25;
    patch[2] = 0x00;
    patch[3] = 0x00;
    patch[4] = 0x00;
    patch[5] = 0x00;
    *(uintptr_t*)&patch[6] = (uintptr_t)hookFunction;

    // 5. Write our patch into the application's memory, overwriting the original function's start.
    memcpy(absoluteTargetAddress, patch, sizeof(patch));

    // 6. Restore the original memory protections.
    VirtualProtect(absoluteTargetAddress, 14, oldProtect, &oldProtect);

    LogToFile("  --> SUCCESS! Patch has been written to memory.\n");
}


// ====================================================================================
// DLLMAIN
// ====================================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_logCs);
        fopen_s(&g_logFile, "log.txt", "w");
        LogToFile("=========================================================\n");
        LogToFile("SURGICAL PATCHER INJECTED.\n");
        LogToFile("=========================================================\n\n");

        // *****************************************************************
        // This is where you put the address you found in the debugger!
        // For example, if x64dbg showed you the function starts at 1400D4A0,
        // you would use the offset 0xD4A0.
        // *****************************************************************
        void* targetFunctionRVA = (void*)0xD4A0; // <-- CHANGE THIS ADDRESS!

        // Perform the surgery.
        PlaceHook(targetFunctionRVA, Hooked_ShowSuccessMessage);
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        if (g_logFile) fclose(g_logFile);
        DeleteCriticalSection(&g_logCs);
    }
    return TRUE;
}

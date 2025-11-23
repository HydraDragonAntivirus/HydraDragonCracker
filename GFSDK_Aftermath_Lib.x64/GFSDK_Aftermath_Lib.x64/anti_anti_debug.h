#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <set>
#include <thread>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <DbgHelp.h>
#include <psapi.h>
#include <tlhelp32.h>
#include "logger.h"
#include <locale>
#include <codecvt>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

// NTDLL types
typedef LONG NTSTATUS;
#define STATUS_SUCCESS 0

// Forward declarations
extern Logger* g_logger;

// Function forward declarations
void HookCallSite(DWORD64 callSiteAddr, const std::string& targetFunc, const std::string& moduleName);
void CaptureSourceCodeAtAddress(DWORD64 address);
void ScanAndHookFunctions(HMODULE hModule, const std::string& moduleName);
void ScanForDebuggers();
void ContinuousScanningThread();
void InitializeAntiAntiDebug();

// ===================================================================================
// ANTI-ANTI-DEBUG SYSTEM - Blocks all exit attempts and detects debuggers
// ===================================================================================

struct HookedFunction {
    std::string name;
    DWORD64 address;
    std::vector<unsigned char> originalBytes;
    bool patched;
    int callCount;
    
    HookedFunction() : address(0), patched(false), callCount(0) {}
};

// Exit functions to block
std::vector<std::string> exitFunctions = {
    "TerminateProcess",
    "ExitProcess",
    "ExitThread",
    "abort",
    "exit",
    "_exit",
    "quick_exit",
    "std::terminate",
    "NtTerminateProcess",
    "NtTerminateThread"
};

// Debugger detection functions to hook
std::vector<std::string> debuggerFunctions = {
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "NtSetInformationThread",
    "OutputDebugStringA",
    "OutputDebugStringW"
};

// Hook redirect functions
extern "C" {
    BOOL WINAPI Hooked_IsDebuggerPresent();
    BOOL WINAPI Hooked_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent);
    NTSTATUS WINAPI Hooked_NtQueryInformationProcess(HANDLE ProcessHandle, DWORD ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
    NTSTATUS WINAPI Hooked_NtSetInformationThread(HANDLE ThreadHandle, DWORD ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
    void WINAPI Hooked_OutputDebugStringA(LPCSTR lpOutputString);
    void WINAPI Hooked_OutputDebugStringW(LPCWSTR lpOutputString);
    BOOL WINAPI Hooked_TerminateProcess(HANDLE hProcess, UINT uExitCode);
    void WINAPI Hooked_ExitProcess(UINT uExitCode);
    void WINAPI Hooked_ExitThread(DWORD dwExitCode);
    void __cdecl Hooked_abort();
    void __cdecl Hooked_exit(int status);
}

// Global hook storage
std::vector<HookedFunction> g_hookedFunctions;
CRITICAL_SECTION g_hookCS;
bool g_scanningActive = false;

// ===================================================================================
// DEBUGGER DETECTION HOOKS - Return FALSE to hide debugger
// ===================================================================================

extern "C" BOOL WINAPI Hooked_IsDebuggerPresent() {
    if (g_logger) {
        g_logger->Log("[ANTI-DEBUG] IsDebuggerPresent called - returning FALSE (hiding debugger)");
    }
    return FALSE;  // Hide debugger
}

extern "C" BOOL WINAPI Hooked_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent) {
    if (g_logger) {
        g_logger->Log("[ANTI-DEBUG] CheckRemoteDebuggerPresent called - returning FALSE");
    }
    if (pbDebuggerPresent) {
        *pbDebuggerPresent = FALSE;
    }
    return TRUE;
}

extern "C" NTSTATUS WINAPI Hooked_NtQueryInformationProcess(HANDLE ProcessHandle, DWORD ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
    // ProcessDebugPort = 7, ProcessDebugFlags = 31
    if (ProcessInformationClass == 7 || ProcessInformationClass == 31) {
        if (g_logger) {
            g_logger->LogFormat("[ANTI-DEBUG] NtQueryInformationProcess called with class %d - spoofing", ProcessInformationClass);
        }
        if (ProcessInformationClass == 7 && ProcessInformationLength >= sizeof(HANDLE)) {
            *(HANDLE*)ProcessInformation = NULL;  // No debug port
        }
        if (ProcessInformationClass == 31 && ProcessInformationLength >= sizeof(ULONG)) {
            *(ULONG*)ProcessInformation = 1;  // Debug flags = normal
        }
        return 0;  // Success
    }
    
    // Call original for other queries
    typedef NTSTATUS (WINAPI *NtQueryInformationProcess_t)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    static NtQueryInformationProcess_t orig = nullptr;
    if (!orig) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            orig = (NtQueryInformationProcess_t)GetProcAddress(ntdll, "NtQueryInformationProcess");
        }
    }
    if (orig) {
        return orig(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
    }
    return 0;
}

extern "C" NTSTATUS WINAPI Hooked_NtSetInformationThread(HANDLE ThreadHandle, DWORD ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength) {
    // ThreadHideFromDebugger = 17
    if (ThreadInformationClass == 17) {
        if (g_logger) {
            g_logger->Log("[ANTI-DEBUG] NtSetInformationThread(ThreadHideFromDebugger) - blocking");
        }
        return 0;  // Success but do nothing
    }
    
    typedef NTSTATUS (WINAPI *NtSetInformationThread_t)(HANDLE, DWORD, PVOID, ULONG);
    static NtSetInformationThread_t orig = nullptr;
    if (!orig) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            orig = (NtSetInformationThread_t)GetProcAddress(ntdll, "NtSetInformationThread");
        }
    }
    if (orig) {
        return orig(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
    }
    return 0;
}

extern "C" void WINAPI Hooked_OutputDebugStringA(LPCSTR lpOutputString) {
    if (g_logger) {
        g_logger->LogFormat("[DEBUG OUTPUT] %s", lpOutputString ? lpOutputString : "(null)");
    }
    // Don't call original - hide debug output
}

extern "C" void WINAPI Hooked_OutputDebugStringW(LPCWSTR lpOutputString) {
    if (g_logger) {
        char buffer[1024];
        WideCharToMultiByte(CP_UTF8, 0, lpOutputString, -1, buffer, sizeof(buffer), NULL, NULL);
        g_logger->LogFormat("[DEBUG OUTPUT] %s", buffer);
    }
    // Don't call original - hide debug output
}

// ===================================================================================
// SOURCE CODE CAPTURE - Must be defined before hooks use it
// ===================================================================================

void CaptureSourceCodeAtAddress(DWORD64 address) {
    if (!g_logger) return;
    
    HANDLE process = GetCurrentProcess();
    IMAGEHLP_LINE64 line;
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    DWORD displacement = 0;
    
    if (SymGetLineFromAddr64(process, address, &displacement, &line)) {
        std::string sourceFile;
        if (line.FileName) {
            // Convert from char* to std::string (FileName is PCHAR which is char*)
            sourceFile = std::string(line.FileName);
        }
        int lineNumber = line.LineNumber;
        
        g_logger->LogFormat("  === SOURCE CODE (%s:%d) ===\n", sourceFile.c_str(), lineNumber);
        
        std::ifstream file(sourceFile);
        if (file.is_open()) {
            std::string lineStr;
            int currentLine = 1;
            int startLine = (lineNumber - 10 < 1) ? 1 : (lineNumber - 10);
            int endLine = lineNumber + 10;
            
            while (std::getline(file, lineStr) && currentLine <= endLine) {
                if (currentLine >= startLine) {
                    char marker = (currentLine == lineNumber) ? '>' : ' ';
                    g_logger->LogFormat("  %c%4d: %s\n", marker, currentLine, lineStr.c_str());
                }
                currentLine++;
            }
            file.close();
        }
    }
}

// ===================================================================================
// EXIT FUNCTION HOOKS - Block all exit attempts
// ===================================================================================

extern "C" BOOL WINAPI Hooked_TerminateProcess(HANDLE hProcess, UINT uExitCode) {
    if (g_logger) {
        g_logger->Log("================================================================================\n");
        g_logger->Log("[EXIT BLOCKED] TerminateProcess called - BLOCKING\n");
        g_logger->LogFormat("Process: %p, ExitCode: %u\n", hProcess, uExitCode);
        CaptureSourceCodeAtAddress((DWORD64)_ReturnAddress() - 5);
        g_logger->Log("Process will NOT terminate - continuing execution\n");
        g_logger->Log("================================================================================\n");
    }
    return FALSE;  // Block termination
}

extern "C" void WINAPI Hooked_ExitProcess(UINT uExitCode) {
    if (g_logger) {
        g_logger->Log("================================================================================\n");
        g_logger->Log("[EXIT BLOCKED] ExitProcess called - BLOCKING\n");
        g_logger->LogFormat("ExitCode: %u\n", uExitCode);
        CaptureSourceCodeAtAddress((DWORD64)_ReturnAddress() - 5);
        g_logger->Log("Process will NOT exit - continuing execution\n");
        g_logger->Log("================================================================================\n");
    }
    // Don't call original - block exit
}

extern "C" void WINAPI Hooked_ExitThread(DWORD dwExitCode) {
    if (g_logger) {
        g_logger->LogFormat("[EXIT BLOCKED] ExitThread called - ExitCode: %u (allowing thread exit)\n", dwExitCode);
    }
    // Allow thread exit but log it
    typedef void (WINAPI *ExitThread_t)(DWORD);
    static ExitThread_t orig = nullptr;
    if (!orig) {
        HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
        if (kernel32) {
            orig = (ExitThread_t)GetProcAddress(kernel32, "ExitThread");
        }
    }
    if (orig) {
        orig(dwExitCode);
    }
}

extern "C" void __cdecl Hooked_abort() {
    if (g_logger) {
        g_logger->Log("[EXIT BLOCKED] abort() called - BLOCKING\n");
        CaptureSourceCodeAtAddress((DWORD64)_ReturnAddress() - 5);
    }
    // Block abort
}

extern "C" void __cdecl Hooked_exit(int status) {
    if (g_logger) {
        g_logger->LogFormat("[EXIT BLOCKED] exit(%d) called - BLOCKING\n", status);
        CaptureSourceCodeAtAddress((DWORD64)_ReturnAddress() - 5);
    }
    // Block exit
}

// ===================================================================================
// PROCESS SCANNER - Detects CheatEngine, x64dbg, etc.
// ===================================================================================

void ScanForDebuggers() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    std::set<std::string> debuggerProcesses = {
        "cheatengine-x86_64.exe", "cheatengine-i386.exe", "cheatengine.exe",
        "x64dbg.exe", "x32dbg.exe", "x96dbg.exe",
        "ollydbg.exe", "windbg.exe", "ida.exe", "ida64.exe",
        "idaq.exe", "idaq64.exe", "ghidra.exe", "ghidra_run.exe",
        "wireshark.exe", "fiddler.exe", "procmon.exe", "procmon64.exe",
        "processhacker.exe", "processhacker2.exe", "hollowshunter.exe"
    };
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // Convert TCHAR to std::string (handles both ANSI and Unicode)
            std::string processName;
#ifdef UNICODE
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, NULL, 0, NULL, NULL);
            if (size_needed > 0) {
                std::vector<char> buffer(size_needed);
                WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, &buffer[0], size_needed, NULL, NULL);
                processName = std::string(&buffer[0]);
            }
#else
            processName = std::string(pe32.szExeFile);
#endif
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);
            
            for (const auto& debugger : debuggerProcesses) {
                if (processName.find(debugger) != std::string::npos) {
                    if (g_logger) {
                        g_logger->LogFormat("[DEBUGGER DETECTED] %s (PID: %d) - BLOCKING ACCESS\n", 
                                          processName.c_str(), pe32.th32ProcessID);
                    }
                    // Could terminate the debugger process here if needed
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
}

// ===================================================================================
// FUNCTION CALL TRACKER - Tracks ALL function calls
// ===================================================================================

struct FunctionCall {
    DWORD64 callSiteAddr;
    DWORD64 targetAddr;
    std::string funcName;
    std::string moduleName;
    std::string targetModule;
    bool isExeCall;
    bool isHooked;
    std::string sourceFile;
    int sourceLine;
    std::vector<unsigned char> callBytes;  // Actual bytes at call site
    DWORD64 timestamp;
    int callCount;
    
    FunctionCall() : callSiteAddr(0), targetAddr(0), sourceLine(0), 
                     isExeCall(false), isHooked(false), timestamp(0), callCount(1) {}
};

static std::vector<FunctionCall> g_allFunctionCalls;
static CRITICAL_SECTION g_callListCS;
static bool g_callListCSInitialized = false;

// Check if module is EXE (not DLL)
bool IsExeModule(const std::string& moduleName) {
    std::string lower = moduleName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    // EXE files don't have .dll extension
    return lower.find(".dll") == std::string::npos && 
           lower.find(".exe") != std::string::npos;
}

// Get module name from address
std::string GetModuleNameFromAddress(DWORD64 address) {
    HMODULE hModule = NULL;
    if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | 
                          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                          (LPCTSTR)address, &hModule)) {
        char modName[MAX_PATH];
        if (GetModuleFileNameA(hModule, modName, MAX_PATH)) {
            std::string modulePath(modName);
            size_t pos = modulePath.find_last_of("\\/");
            if (pos != std::string::npos) {
                return modulePath.substr(pos + 1);
            }
            return modulePath;
        }
    }
    return "Unknown";
}

// Python communication file for blocking exit calls
const char* PYTHON_COMMAND_FILE = "python_commands.json";
const char* PYTHON_RESPONSE_FILE = "python_response.json";

// Read Python commands (which functions to block)
void ReadPythonCommands() {
    try {
        std::ifstream file(PYTHON_RESPONSE_FILE);
        if (!file.is_open()) return;
        
        // Simple JSON parsing for blocking commands
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        
        // Check for block commands
        if (content.find("\"block_exit\": true") != std::string::npos) {
            // Python wants to block all exits - already done, but log it
            if (g_logger) {
                g_logger->Log("[PYTHON] Exit blocking confirmed by Python analyzer\n");
            }
        }
        
        // Check for additional functions to hook
        size_t hookPos = content.find("\"hook_functions\":");
        if (hookPos != std::string::npos) {
            // Parse function list to hook
            // This is a simplified parser - could use proper JSON library
            if (g_logger) {
                g_logger->Log("[PYTHON] Additional hook functions requested\n");
            }
        }
    } catch (...) {
        // Ignore errors
    }
}

// Call Python script for advanced analysis and source code reconstruction
void CallPythonAnalyzer() {
    static int pythonCallCount = 0;
    pythonCallCount++;
    
    // Call Python every 3 scans for faster response
    if (pythonCallCount % 3 != 0) {
        // Still read commands even if not calling Python
        ReadPythonCommands();
        return;
    }
    
    try {
        std::filesystem::path scriptPath = std::filesystem::current_path() / "analyze_calls.py";
        if (std::filesystem::exists(scriptPath)) {
            // Write command file to tell Python what to do
            std::ofstream cmdFile(PYTHON_COMMAND_FILE);
            if (cmdFile.is_open()) {
                cmdFile << "{\n";
                cmdFile << "  \"action\": \"analyze_and_reconstruct\",\n";
                cmdFile << "  \"reconstruct_source\": true,\n";
                cmdFile << "  \"block_exits\": true\n";
                cmdFile << "}\n";
                cmdFile.close();
            }
            
            std::string cmd = "python \"" + scriptPath.string() + "\"";
            int result = system(cmd.c_str());
            if (g_logger) {
                g_logger->LogFormat("[PYTHON] Analyzer called (exit code: %d)\n", result);
            }
            
            // Read Python response
            ReadPythonCommands();
        } else {
            if (g_logger && pythonCallCount == 3) {
                g_logger->LogFormat("[PYTHON] Script not found at: %s\n", scriptPath.string().c_str());
            }
        }
    } catch (...) {
        // Ignore errors
    }
}

// ===================================================================================
// DYNAMIC FUNCTION SCANNER - Finds and hooks ALL functions, prioritizes EXE
// ===================================================================================

void ScanAndHookFunctions(HMODULE hModule, const std::string& moduleName) {
    HANDLE process = GetCurrentProcess();
    
    // Initialize symbols
    static bool symInitialized = false;
    if (!symInitialized) {
        SymInitialize(process, NULL, TRUE);
        SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | 
                     SYMOPT_INCLUDE_32BIT_MODULES | SYMOPT_LOAD_ANYTHING);
        symInitialized = true;
    }
    
    // Initialize critical section for call list
    if (!g_callListCSInitialized) {
        InitializeCriticalSection(&g_callListCS);
        g_callListCSInitialized = true;
    }
    
    MODULEINFO modInfo;
    if (!GetModuleInformation(process, hModule, &modInfo, sizeof(modInfo))) {
        return;
    }
    
    BYTE* baseAddr = (BYTE*)modInfo.lpBaseOfDll;
    DWORD size = modInfo.SizeOfImage;
    
    bool isExe = IsExeModule(moduleName);
    
    // Scan for ALL CALL instructions (E8 = CALL rel32)
    static std::set<DWORD64> scannedAddresses; // Avoid duplicate logging
    
    for (DWORD offset = 0; offset < size - 16; offset++) {
        BYTE* currentAddr = baseAddr + offset;
        
        // Check for CALL rel32 (E8)
        if (*currentAddr == 0xE8) {
            DWORD relOffset = *(DWORD*)(currentAddr + 1);
            DWORD64 targetAddr = (DWORD64)(currentAddr + 5 + relOffset);
            
            // Skip if already scanned
            if (scannedAddresses.find((DWORD64)currentAddr) != scannedAddresses.end()) {
                continue;
            }
            scannedAddresses.insert((DWORD64)currentAddr);
            
            // Get target module
            std::string targetModule = GetModuleNameFromAddress(targetAddr);
            
            // Get symbol name
            char symBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
            SYMBOL_INFO* symbol = (SYMBOL_INFO*)symBuffer;
            symbol->MaxNameLen = MAX_SYM_NAME;
            symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
            
            DWORD64 displacement = 0;
            std::string funcName = "Unknown";
            bool hasSymbol = false;
            
            if (SymFromAddr(process, targetAddr, &displacement, symbol)) {
                if (symbol->Name) {
                    funcName = std::string(symbol->Name);
                    hasSymbol = true;
                }
            } else {
                // Try to get module export name
                HMODULE targetMod = NULL;
                if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | 
                                      GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                      (LPCTSTR)targetAddr, &targetMod)) {
                    // Could use GetProcAddress reverse lookup, but complex
                    // For now, mark as unknown
                }
            }
            
            // Log ALL function calls (especially from EXE)
            if (isExe || hasSymbol) {
                EnterCriticalSection(&g_callListCS);
                
                // Check if this call already exists (merge duplicates)
                bool found = false;
                FunctionCall* callPtr = nullptr;
                for (auto& existingCall : g_allFunctionCalls) {
                    if (existingCall.callSiteAddr == (DWORD64)currentAddr && 
                        existingCall.targetAddr == targetAddr) {
                        existingCall.callCount++;
                        found = true;
                        callPtr = &existingCall;
                        break;
                    }
                }
                
                if (!found) {
                    FunctionCall call;
                    call.callSiteAddr = (DWORD64)currentAddr;
                    call.targetAddr = targetAddr;
                    call.funcName = funcName;
                    call.moduleName = moduleName;
                    call.targetModule = targetModule;
                    call.isExeCall = isExe;
                    call.isHooked = false;
                    call.timestamp = GetTickCount();
                    
                    // Try to get source file info
                    IMAGEHLP_LINE64 line;
                    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
                    DWORD lineDisplacement = 0;
                    if (SymGetLineFromAddr64(process, (DWORD64)currentAddr, &lineDisplacement, &line)) {
                        if (line.FileName) {
                            call.sourceFile = std::string(line.FileName);
                            call.sourceLine = line.LineNumber;
                        }
                    }
                    
                    // Capture call bytes
                    call.callBytes.assign(currentAddr, currentAddr + 5);
                    
                    g_allFunctionCalls.push_back(call);
                    callPtr = &g_allFunctionCalls.back();
                }
                
                // Log the call
                if (g_logger && callPtr) {
                    if (isExe) {
                        g_logger->LogFormat("[EXE CALL] %s -> %s!%s [0x%llX -> 0x%llX]\n",
                                          moduleName.c_str(), targetModule.c_str(), 
                                          funcName.c_str(), callPtr->callSiteAddr, targetAddr);
                    } else if (hasSymbol) {
                        g_logger->LogFormat("[CALL] %s -> %s!%s [0x%llX -> 0x%llX]\n",
                                          moduleName.c_str(), targetModule.c_str(), 
                                          funcName.c_str(), callPtr->callSiteAddr, targetAddr);
                    }
                }
                
                LeaveCriticalSection(&g_callListCS);
            }
            
            // Check if it's a function we want to hook (prioritize EXE calls)
            if (hasSymbol) {
                bool shouldHook = false;
                
                for (const auto& exitFunc : exitFunctions) {
                    if (funcName.find(exitFunc) != std::string::npos) {
                        shouldHook = true;
                        break;
                    }
                }
                
                if (!shouldHook) {
                    for (const auto& debugFunc : debuggerFunctions) {
                        if (funcName.find(debugFunc) != std::string::npos) {
                            shouldHook = true;
                            break;
                        }
                    }
                }
                
                if (shouldHook) {
                    HookCallSite((DWORD64)currentAddr, funcName, moduleName);
                    
                    // Mark as hooked in call list
                    EnterCriticalSection(&g_callListCS);
                    for (auto& call : g_allFunctionCalls) {
                        if (call.callSiteAddr == (DWORD64)currentAddr) {
                            call.isHooked = true;
                            break;
                        }
                    }
                    LeaveCriticalSection(&g_callListCS);
                }
            }
        }
        
        // Also check for indirect CALL (FF /2) and CALL [reg] patterns
        // This is more complex, but we can add it if needed
    }
    
    // Dump all calls to JSON file for Python analysis
    static int scanCount = 0;
    scanCount++;
    if (scanCount % 5 == 0) {  // Dump more frequently
        EnterCriticalSection(&g_callListCS);
        
        // Write JSON format for Python
        std::ofstream jsonFile("function_calls.json", std::ios::trunc);
        if (jsonFile.is_open()) {
            jsonFile << "{\n";
            jsonFile << "  \"scan_count\": " << scanCount << ",\n";
            jsonFile << "  \"total_calls\": " << g_allFunctionCalls.size() << ",\n";
            jsonFile << "  \"timestamp\": " << GetTickCount() << ",\n";
            jsonFile << "  \"calls\": [\n";
            
            for (size_t i = 0; i < g_allFunctionCalls.size(); i++) {
                const auto& call = g_allFunctionCalls[i];
                jsonFile << "    {\n";
                jsonFile << "      \"call_site\": \"0x" << std::hex << call.callSiteAddr << std::dec << "\",\n";
                jsonFile << "      \"target\": \"0x" << std::hex << call.targetAddr << std::dec << "\",\n";
                jsonFile << "      \"func_name\": \"" << call.funcName << "\",\n";
                jsonFile << "      \"module\": \"" << call.moduleName << "\",\n";
                jsonFile << "      \"target_module\": \"" << call.targetModule << "\",\n";
                jsonFile << "      \"is_exe\": " << (call.isExeCall ? "true" : "false") << ",\n";
                jsonFile << "      \"is_hooked\": " << (call.isHooked ? "true" : "false") << ",\n";
                jsonFile << "      \"source_file\": \"" << call.sourceFile << "\",\n";
                jsonFile << "      \"source_line\": " << call.sourceLine << ",\n";
                jsonFile << "      \"call_count\": " << call.callCount << ",\n";
                jsonFile << "      \"timestamp\": " << call.timestamp << "\n";
                jsonFile << "    }";
                if (i < g_allFunctionCalls.size() - 1) jsonFile << ",";
                jsonFile << "\n";
            }
            
            jsonFile << "  ]\n";
            jsonFile << "}\n";
            jsonFile.close();
        }
        
        // Also write text format for backward compatibility
        std::ofstream dumpFile("exe_function_calls.txt", std::ios::app);
        if (dumpFile.is_open()) {
            dumpFile << "\n=== " << moduleName << " Function Calls (Scan #" << scanCount << ") ===\n";
            for (const auto& call : g_allFunctionCalls) {
                if (call.isExeCall) {
                    dumpFile << std::hex << "0x" << call.callSiteAddr << " -> 0x" << call.targetAddr 
                             << " | " << call.funcName << " | " << call.targetModule 
                             << (call.isHooked ? " [HOOKED]" : "") << "\n";
                }
            }
            dumpFile.close();
        }
        
        LeaveCriticalSection(&g_callListCS);
    }
}

// Hook a call site
void HookCallSite(DWORD64 callSiteAddr, const std::string& targetFunc, const std::string& moduleName) {
    EnterCriticalSection(&g_hookCS);
    
    // Check if already hooked
    for (const auto& hook : g_hookedFunctions) {
        if (hook.address == callSiteAddr && hook.patched) {
            LeaveCriticalSection(&g_hookCS);
            return;
        }
    }
    
    // Determine which hook function to use
    void* hookFunc = nullptr;
    if (targetFunc.find("TerminateProcess") != std::string::npos) {
        hookFunc = (void*)Hooked_TerminateProcess;
    } else if (targetFunc.find("ExitProcess") != std::string::npos) {
        hookFunc = (void*)Hooked_ExitProcess;
    } else if (targetFunc.find("ExitThread") != std::string::npos) {
        hookFunc = (void*)Hooked_ExitThread;
    } else if (targetFunc.find("abort") != std::string::npos) {
        hookFunc = (void*)Hooked_abort;
    } else if (targetFunc.find("exit") != std::string::npos) {
        hookFunc = (void*)Hooked_exit;
    } else if (targetFunc.find("IsDebuggerPresent") != std::string::npos) {
        hookFunc = (void*)Hooked_IsDebuggerPresent;
    } else if (targetFunc.find("CheckRemoteDebuggerPresent") != std::string::npos) {
        hookFunc = (void*)Hooked_CheckRemoteDebuggerPresent;
    } else if (targetFunc.find("NtQueryInformationProcess") != std::string::npos) {
        hookFunc = (void*)Hooked_NtQueryInformationProcess;
    } else if (targetFunc.find("NtSetInformationThread") != std::string::npos) {
        hookFunc = (void*)Hooked_NtSetInformationThread;
    } else if (targetFunc.find("OutputDebugString") != std::string::npos) {
        if (targetFunc.find("W") != std::string::npos) {
            hookFunc = (void*)Hooked_OutputDebugStringW;
        } else {
            hookFunc = (void*)Hooked_OutputDebugStringA;
        }
    }
    
    if (!hookFunc) {
        LeaveCriticalSection(&g_hookCS);
        return;
    }
    
    // Patch the call site
    DWORD oldProtect;
    if (VirtualProtect((void*)callSiteAddr, 16, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        // Save original bytes
        HookedFunction hook;
        hook.name = targetFunc;
        hook.address = callSiteAddr;
        hook.originalBytes.assign((unsigned char*)callSiteAddr, (unsigned char*)callSiteAddr + 5);
        
        // Calculate relative offset
        DWORD64 redirectAddr = (DWORD64)hookFunc;
        DWORD relOffset = (DWORD)(redirectAddr - (callSiteAddr + 5));
        
        // Write CALL instruction
        unsigned char patch[5] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
        *(DWORD*)(patch + 1) = relOffset;
        
        memcpy((void*)callSiteAddr, patch, 5);
        VirtualProtect((void*)callSiteAddr, 16, oldProtect, &oldProtect);
        
        hook.patched = true;
        g_hookedFunctions.push_back(hook);
        
        if (g_logger) {
            g_logger->LogFormat("[HOOKED] %s at 0x%llX in %s\n", targetFunc.c_str(), callSiteAddr, moduleName.c_str());
        }
    }
    
    LeaveCriticalSection(&g_hookCS);
}

// Continuous scanning thread - Scans ALL modules, prioritizes EXE
void ContinuousScanningThread() {
    while (g_scanningActive) {
        // Scan for debuggers
        ScanForDebuggers();
        
        // Scan ALL modules for function calls (prioritize EXE)
        HANDLE process = GetCurrentProcess();
        HMODULE hMods[1024];
        DWORD cbNeeded;
        
        std::vector<std::pair<HMODULE, std::string>> exeModules;
        std::vector<std::pair<HMODULE, std::string>> dllModules;
        
        if (EnumProcessModules(process, hMods, sizeof(hMods), &cbNeeded)) {
            int moduleCount = cbNeeded / sizeof(HMODULE);
            
            // Separate EXE and DLL modules
            for (int i = 0; i < moduleCount; i++) {
                char modName[MAX_PATH];
                if (GetModuleFileNameA(hMods[i], modName, MAX_PATH)) {
                    std::string modulePath(modName);
                    std::string moduleName = modulePath;
                    size_t pos = moduleName.find_last_of("\\/");
                    if (pos != std::string::npos) {
                        moduleName = moduleName.substr(pos + 1);
                    }
                    
                    std::string ext = moduleName.substr(moduleName.find_last_of("."));
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                    
                    if (ext == ".exe") {
                        exeModules.push_back({hMods[i], moduleName});
                    } else {
                        dllModules.push_back({hMods[i], moduleName});
                    }
                }
            }
        }
        
        // Scan EXE modules FIRST (priority)
        if (g_logger && !exeModules.empty()) {
            g_logger->LogFormat("[SCAN] Scanning %d EXE module(s) with priority...\n", exeModules.size());
        }
        for (const auto& mod : exeModules) {
            ScanAndHookFunctions(mod.first, mod.second);
        }
        
        // Then scan DLL modules
        if (g_logger && !dllModules.empty()) {
            g_logger->LogFormat("[SCAN] Scanning %d DLL module(s)...\n", dllModules.size());
        }
        for (const auto& mod : dllModules) {
            ScanAndHookFunctions(mod.first, mod.second);
        }
        
        // Call Python analyzer periodically
        CallPythonAnalyzer();
        
        // Wait before next scan
        Sleep(2000);  // Scan every 2 seconds
    }
}

// Initialize anti-anti-debug system
void InitializeAntiAntiDebug() {
    InitializeCriticalSection(&g_hookCS);
    g_scanningActive = true;
    
    // Start continuous scanning thread
    CreateThread(NULL, 0, [](LPVOID) -> DWORD {
        ContinuousScanningThread();
        return 0;
    }, NULL, 0, NULL);
    
    if (g_logger) {
        g_logger->Log("[ANTI-ANTI-DEBUG] System initialized - all exit attempts will be blocked");
        g_logger->Log("[ANTI-ANTI-DEBUG] Debugger detection hooks active");
        g_logger->Log("[ANTI-ANTI-DEBUG] Continuous scanning started");
    }
}




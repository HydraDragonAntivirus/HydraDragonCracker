#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <DbgHelp.h>
#include <psapi.h>
#include "logger.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

// Forward declarations
extern Logger* g_logger;

// ===================================================================================
// MONKEY PATCHING - Find and patch TerminateProcess calls in source code
// ===================================================================================

struct PatchedCallSite {
    DWORD64 address;
    std::string moduleName;
    std::string functionName;
    std::string sourceFile;
    int lineNumber;
    std::vector<unsigned char> originalBytes;
    bool patched;
    
    PatchedCallSite() : address(0), lineNumber(0), patched(false) {}
};

// Our redirect function - matches TerminateProcess signature
extern "C" BOOL WINAPI Redirected_TerminateProcess_Call(HANDLE hProcess, UINT uExitCode);

// Find all TerminateProcess call sites in the EXE
std::vector<PatchedCallSite> FindTerminateProcessCalls();
void PatchTerminateProcessCalls(const std::vector<PatchedCallSite>& callSites);
void CaptureSourceCodeAtAddress(DWORD64 address);

// Monkey patch implementation
extern "C" BOOL WINAPI Redirected_TerminateProcess_Call(HANDLE hProcess, UINT uExitCode) {
    if (!g_logger) {
        // Logger not ready, call original
        HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
        if (kernel32) {
            typedef BOOL (WINAPI *TerminateProcess_t)(HANDLE hProcess, UINT uExitCode);
            TerminateProcess_t origTerminate = (TerminateProcess_t)GetProcAddress(kernel32, "TerminateProcess");
            if (origTerminate) {
                return origTerminate(hProcess, uExitCode);
            }
        }
        return FALSE;
    }
    
    // Get return address from stack
    void* returnAddr = _ReturnAddress();
    DWORD64 callSiteAddr = (DWORD64)returnAddr - 5;  // CALL instruction is 5 bytes
    
    g_logger->Log("================================================================================\n");
    g_logger->Log("[TERMINATE PROCESS CALL DETECTED] - Monkey patched call site\n");
    g_logger->LogFormat("Call site address: 0x%llX\n", callSiteAddr);
    
    // Capture source code at this call site
    CaptureSourceCodeAtAddress(callSiteAddr);
    
    // Parameters are already passed correctly (WINAPI calling convention)
    g_logger->LogFormat("Redirected call: TerminateProcess(hProcess=%p, uExitCode=%u)\n", hProcess, uExitCode);
    
    // Get original TerminateProcess and call it
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (kernel32) {
        typedef BOOL (WINAPI *TerminateProcess_t)(HANDLE hProcess, UINT uExitCode);
        TerminateProcess_t origTerminate = (TerminateProcess_t)GetProcAddress(kernel32, "TerminateProcess");
        
        if (origTerminate) {
            // Call original with same parameters
            BOOL result = origTerminate(hProcess, uExitCode);
            return result;
        }
    }
    
    return FALSE;
}

// Find TerminateProcess call sites by scanning code
std::vector<PatchedCallSite> FindTerminateProcessCalls() {
    std::vector<PatchedCallSite> callSites;
    
    HANDLE process = GetCurrentProcess();
    static bool symInitialized = false;
    if (!symInitialized) {
        SymInitialize(process, NULL, TRUE);
        SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
        symInitialized = true;
    }
    
    // Get all modules
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(process, hMods, sizeof(hMods), &cbNeeded)) {
        int moduleCount = cbNeeded / sizeof(HMODULE);
        
        for (int i = 0; i < moduleCount; i++) {
            char modName[MAX_PATH];
            if (GetModuleFileNameA(hMods[i], modName, MAX_PATH)) {
                std::string modulePath = modName;
                std::string moduleName = modulePath;
                size_t pos = moduleName.find_last_of("\\/");
                if (pos != std::string::npos) {
                    moduleName = moduleName.substr(pos + 1);
                }
                
                // Only scan EXE modules
                std::string ext = moduleName.substr(moduleName.find_last_of("."));
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext != ".exe") continue;
                
                // Get module info
                MODULEINFO modInfo;
                if (GetModuleInformation(process, hMods[i], &modInfo, sizeof(modInfo))) {
                    BYTE* baseAddr = (BYTE*)modInfo.lpBaseOfDll;
                    DWORD size = modInfo.SizeOfImage;
                    
                    // Scan for CALL instructions to TerminateProcess
                    // Pattern: E8 [rel32] = CALL rel32
                    // Or: FF 15/25 [addr] = CALL [addr]
                    // Or: 48 FF 15/25 [addr] = CALL [addr] (x64)
                    
                    for (DWORD offset = 0; offset < size - 16; offset++) {
                        BYTE* currentAddr = baseAddr + offset;
                        
                        // Check for CALL rel32 (E8)
                        if (*currentAddr == 0xE8) {
                            // This is a CALL instruction
                            // Calculate target address
                            DWORD relOffset = *(DWORD*)(currentAddr + 1);
                            DWORD64 targetAddr = (DWORD64)(currentAddr + 5 + relOffset);
                            
                            // Check if target is TerminateProcess
                            char symBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
                            SYMBOL_INFO* symbol = (SYMBOL_INFO*)symBuffer;
                            symbol->MaxNameLen = MAX_SYM_NAME;
                            symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
                            
                            DWORD64 displacement = 0;
                            if (SymFromAddr(process, targetAddr, &displacement, symbol)) {
                                if (strstr(symbol->Name, "TerminateProcess") != NULL) {
                                    // Found a call to TerminateProcess!
                                    PatchedCallSite site;
                                    site.address = (DWORD64)currentAddr;
                                    site.moduleName = moduleName;
                                    
                                    // Get function name containing this call
                                    if (SymFromAddr(process, (DWORD64)currentAddr, &displacement, symbol)) {
                                        site.functionName = symbol->Name;
                                    }
                                    
                                    // Get source file and line
                                    IMAGEHLP_LINE64 line;
                                    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
                                    DWORD lineDisplacement = 0;
                                    if (SymGetLineFromAddr64(process, (DWORD64)currentAddr, &lineDisplacement, &line)) {
                                        site.sourceFile = line.FileName;
                                        site.lineNumber = line.LineNumber;
                                    }
                                    
                                    // Save original bytes (5 bytes for CALL rel32)
                                    site.originalBytes.assign(currentAddr, currentAddr + 5);
                                    
                                    callSites.push_back(site);
                                    
                                    if (g_logger) {
                                        g_logger->LogFormat("Found TerminateProcess call at 0x%llX in %s!%s (%s:%d)\n",
                                            site.address, moduleName.c_str(), site.functionName.c_str(),
                                            site.sourceFile.c_str(), site.lineNumber);
                                    }
                                }
                            }
                        }
                        
                        // Check for CALL [addr] patterns (FF 15/25 or 48 FF 15/25)
                        if ((*currentAddr == 0xFF && (*(currentAddr + 1) == 0x15 || *(currentAddr + 1) == 0x25)) ||
                            (*currentAddr == 0x48 && *(currentAddr + 1) == 0xFF && 
                             (*(currentAddr + 2) == 0x15 || *(currentAddr + 2) == 0x25))) {
                            // Indirect call - would need to resolve at runtime
                            // Skip for now, focus on direct calls
                        }
                    }
                }
            }
        }
    }
    
    return callSites;
}

// Patch the call sites to redirect to our function
void PatchTerminateProcessCalls(const std::vector<PatchedCallSite>& callSites) {
    for (const auto& site : callSites) {
        if (site.patched) continue;
        
        DWORD oldProtect;
        if (VirtualProtect((void*)site.address, 16, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            // Calculate relative offset to our redirect function
            DWORD64 redirectAddr = (DWORD64)Redirected_TerminateProcess_Call;
            DWORD64 callSiteAddr = site.address;
            DWORD relOffset = (DWORD)(redirectAddr - (callSiteAddr + 5));
            
            // Write CALL instruction: E8 [rel32]
            unsigned char patch[5] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
            *(DWORD*)(patch + 1) = relOffset;
            
            memcpy((void*)site.address, patch, 5);
            VirtualProtect((void*)site.address, 16, oldProtect, &oldProtect);
            
            if (g_logger) {
                g_logger->LogFormat("Patched call site at 0x%llX to redirect to our handler\n", site.address);
            }
        }
    }
}

// Capture source code at a specific address
void CaptureSourceCodeAtAddress(DWORD64 address) {
    if (!g_logger) return;
    
    HANDLE process = GetCurrentProcess();
    IMAGEHLP_LINE64 line;
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    DWORD displacement = 0;
    
    if (SymGetLineFromAddr64(process, address, &displacement, &line)) {
        std::string sourceFile = line.FileName;
        int lineNumber = line.LineNumber;
        
        g_logger->LogFormat("  === FULL SOURCE CODE CONTEXT (%s) ===\n", sourceFile.c_str());
        
        // Read source file and show context
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


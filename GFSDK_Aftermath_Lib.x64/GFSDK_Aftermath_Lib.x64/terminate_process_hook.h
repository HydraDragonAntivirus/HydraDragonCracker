#pragma once
#include <windows.h>
// Undefine Windows macros that conflict with std::max/min
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif
#include <string>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include "logger.h"

// Forward declarations
extern Logger* g_logger;

// TerminateProcess function type
typedef BOOL (WINAPI *TerminateProcess_t)(HANDLE hProcess, UINT uExitCode);
extern TerminateProcess_t g_origTerminateProcess;

// ===================================================================================
// TERMINATE PROCESS HOOK - Prevents termination and captures source code
// ===================================================================================

// Hook implementation
extern "C" BOOL WINAPI Hooked_TerminateProcess(HANDLE hProcess, UINT uExitCode) {
    // If logger not ready yet, allow the call (game initialization)
    if (!g_logger) {
        if (!g_origTerminateProcess) {
            HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
            if (kernel32) {
                g_origTerminateProcess = (TerminateProcess_t)GetProcAddress(kernel32, "TerminateProcess");
            }
        }
        if (g_origTerminateProcess) {
            return g_origTerminateProcess(hProcess, uExitCode);
        }
        return FALSE;
    }
    
    // Check if this is during game initialization (first few seconds)
    static DWORD initTime = GetTickCount();
    DWORD currentTime = GetTickCount();
    if (currentTime - initTime < 5000) {  // First 5 seconds - allow termination (game init)
        if (g_origTerminateProcess) {
            return g_origTerminateProcess(hProcess, uExitCode);
        }
    }
    
    // CAPTURE FULL SOURCE CODE OF CALLER
    g_logger->Log("================================================================================\n");
    g_logger->Log("[TERMINATE PROCESS BLOCKED] - Capturing full source code of caller\n");
    g_logger->LogFormat("Process Handle: %p, Exit Code: %u\n", hProcess, uExitCode);
    
    // Capture full call stack with source code
    void* stack[64];
    USHORT frames = CaptureStackBackTrace(0, 64, stack, NULL);
    
    HANDLE process = GetCurrentProcess();
    static bool symInitialized = false;
    if (!symInitialized) {
        // Initialize symbols with more aggressive options
        SymInitialize(process, NULL, TRUE);
        SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | 
                     SYMOPT_INCLUDE_32BIT_MODULES | SYMOPT_LOAD_ANYTHING);
        symInitialized = true;
        
        // Give symbols time to load
        Sleep(100);
    }
    
    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    SYMBOL_INFO* symbol = (SYMBOL_INFO*)buffer;
    symbol->MaxNameLen = MAX_SYM_NAME;
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    
    IMAGEHLP_LINE64 line;
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    
    // Capture FULL source code context for each frame
    for (USHORT i = 0; i < frames && i < 20; i++) {
        DWORD64 address = (DWORD64)stack[i];
        DWORD displacement = 0;
        
        std::string funcName = "Unknown";
        std::string moduleName = "Unknown";
        std::string sourceFile = "";
        int lineNumber = 0;
        
        if (SymFromAddr(process, address, 0, symbol)) {
            funcName = symbol->Name;
        }
        
        HMODULE hModule = NULL;
        if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | 
                              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                              (LPCTSTR)address, &hModule)) {
            char modName[MAX_PATH];
            if (GetModuleFileNameA(hModule, modName, MAX_PATH)) {
                moduleName = modName;
                size_t pos = moduleName.find_last_of("\\/");
                if (pos != std::string::npos) {
                    moduleName = moduleName.substr(pos + 1);
                }
            }
        }
        
        if (SymGetLineFromAddr64(process, address, &displacement, &line)) {
            sourceFile = line.FileName;
            lineNumber = line.LineNumber;
        }
        
        // Log frame info
        char frameInfo[1024];
        if (!sourceFile.empty()) {
            sprintf_s(frameInfo, "[%d] %s!%s (%s:%d) [0x%llX]", 
                      i, moduleName.c_str(), funcName.c_str(), 
                      sourceFile.c_str(), lineNumber, address);
        } else {
            sprintf_s(frameInfo, "[%d] %s!%s [0x%llX]", 
                      i, moduleName.c_str(), funcName.c_str(), address);
        }
        g_logger->Log(frameInfo);
        
        // CAPTURE FULL SOURCE CODE CONTEXT (multiple lines around the call)
        if (!sourceFile.empty() && lineNumber > 0) {
            g_logger->LogFormat("  === FULL SOURCE CODE CONTEXT (%s) ===\n", sourceFile.c_str());
            
            // Read source file and show context (10 lines before, 10 lines after)
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
            } else {
                // Try alternative paths
                std::filesystem::path currentPath = std::filesystem::current_path();
                std::vector<std::string> searchPaths = {
                    sourceFile,
                    (currentPath / sourceFile).string(),
                };
                
                size_t pos = sourceFile.find_last_of("\\/");
                if (pos != std::string::npos) {
                    std::string fileName = sourceFile.substr(pos + 1);
                    searchPaths.push_back(fileName);
                    searchPaths.push_back((currentPath / fileName).string());
                }
                
                for (const auto& path : searchPaths) {
                    std::ifstream altFile(path);
                    if (altFile.is_open()) {
                        std::string lineStr;
                        int currentLine = 1;
                        int startLine = (lineNumber - 10 < 1) ? 1 : (lineNumber - 10);
                        int endLine = lineNumber + 10;
                        
                        while (std::getline(altFile, lineStr) && currentLine <= endLine) {
                            if (currentLine >= startLine) {
                                char marker = (currentLine == lineNumber) ? '>' : ' ';
                                g_logger->LogFormat("  %c%4d: %s\n", marker, currentLine, lineStr.c_str());
                            }
                            currentLine++;
                        }
                        altFile.close();
                        break;
                    }
                }
            }
        }
        
        // Stop at first EXE module (the actual caller)
        if (!moduleName.empty()) {
            std::string ext = moduleName.substr(moduleName.find_last_of("."));
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext == ".exe") {
                g_logger->Log("  [STOPPED AT EXE CALLER]\n");
                break;
            }
        }
    }
    
    g_logger->Log("================================================================================\n");
    g_logger->Log("[TERMINATE PROCESS BLOCKED] - Call prevented, redirecting to else block\n");
    g_logger->Log("Process will NOT be terminated. Execution continues normally.\n");
    
    // BLOCK THE CALL - Return FALSE to prevent termination
    // This acts as an "else" block - the process continues instead of terminating
    return FALSE;  // FALSE = process NOT terminated
}


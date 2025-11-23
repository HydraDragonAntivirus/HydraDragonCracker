#pragma once
#include <windows.h>
#include <fstream>
#include <string>
#include <DbgHelp.h>

#pragma comment(lib, "dbghelp.lib")

// ===================================================================================
// LOGGING SYSTEM
// ===================================================================================
class Logger {
private:
    std::ofstream logFile;
    bool enabled;
    CRITICAL_SECTION cs;

public:
    Logger() : enabled(false) {
        InitializeCriticalSection(&cs);
    }

    ~Logger() {
        if (logFile.is_open()) {
            logFile.close();
        }
        DeleteCriticalSection(&cs);
    }

    void Initialize(const std::string& filename, bool enable) {
        enabled = enable;
        if (enabled) {
            logFile.open(filename, std::ios::app);
            if (logFile.is_open()) {
                Log("=== GFSDK_Aftermath_Lib.x64 Proxy DLL Initialized ===");
            }
        }
    }

    void Log(const std::string& message) {
        if (!enabled) return;

        EnterCriticalSection(&cs);
        if (logFile.is_open()) {
            SYSTEMTIME st;
            GetLocalTime(&st);
            char timestamp[64];
            sprintf_s(timestamp, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

            logFile << timestamp << message << std::endl;
            logFile.flush();
        }
        LeaveCriticalSection(&cs);
    }

    template<typename... Args>
    void LogFormat(const char* format, Args... args) {
        char buffer[1024];
        sprintf_s(buffer, format, args...);
        Log(buffer);
    }

    // Log with call stack information
    void LogWithCallStack(const std::string& message, int skipFrames = 1) {
        if (!enabled) return;

        // Log the main message
        Log(message);

        // Capture call stack
        void* stack[32];
        USHORT frames = CaptureStackBackTrace(skipFrames, 32, stack, NULL);

        if (frames > 0) {
            HANDLE process = GetCurrentProcess();

            // Initialize symbol handler (do this once)
            static bool symInitialized = false;
            if (!symInitialized) {
                SymInitialize(process, NULL, TRUE);
                SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);
                symInitialized = true;
            }

            // Allocate symbol info buffer
            char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
            SYMBOL_INFO* symbol = (SYMBOL_INFO*)buffer;
            symbol->MaxNameLen = MAX_SYM_NAME;
            symbol->SizeOfStruct = sizeof(SYMBOL_INFO);

            // Line info
            IMAGEHLP_LINE64 line;
            line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
            DWORD displacement = 0;

            // Log call stack
            for (USHORT i = 0; i < frames && i < 5; i++) {  // Show top 5 callers
                DWORD64 address = (DWORD64)stack[i];

                // Get symbol name
                std::string symbolName = "Unknown";
                std::string moduleName = "Unknown";
                std::string sourceFile = "";
                int lineNumber = 0;

                if (SymFromAddr(process, address, 0, symbol)) {
                    symbolName = symbol->Name;
                }

                // Get module name
                HMODULE hModule = NULL;
                if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    (LPCTSTR)address, &hModule)) {
                    char modName[MAX_PATH];
                    if (GetModuleFileNameA(hModule, modName, MAX_PATH)) {
                        moduleName = modName;
                        // Extract just the filename
                        size_t pos = moduleName.find_last_of("\\/");
                        if (pos != std::string::npos) {
                            moduleName = moduleName.substr(pos + 1);
                        }
                    }
                }

                // Get source file and line number
                if (SymGetLineFromAddr64(process, address, &displacement, &line)) {
                    sourceFile = line.FileName;
                    lineNumber = line.LineNumber;
                    // Extract just the filename
                    size_t pos = sourceFile.find_last_of("\\/");
                    if (pos != std::string::npos) {
                        sourceFile = sourceFile.substr(pos + 1);
                    }
                }

                // Format the stack frame
                char stackFrame[1024];
                if (!sourceFile.empty()) {
                    sprintf_s(stackFrame, "    [%d] %s!%s (%s:%d) [0x%llX]",
                        i, moduleName.c_str(), symbolName.c_str(), sourceFile.c_str(), lineNumber, address);
                } else {
                    sprintf_s(stackFrame, "    [%d] %s!%s [0x%llX]",
                        i, moduleName.c_str(), symbolName.c_str(), address);
                }

                Log(stackFrame);
            }
        }
    }
};

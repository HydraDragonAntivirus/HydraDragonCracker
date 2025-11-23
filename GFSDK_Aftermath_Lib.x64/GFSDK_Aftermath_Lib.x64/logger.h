#pragma once
#include <windows.h>
#include <fstream>
#include <string>
#include <DbgHelp.h>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <intrin.h>

#pragma comment(lib, "dbghelp.lib")

// Forward declaration for RtlCaptureContext
extern "C" {
    void WINAPI RtlCaptureContext(PCONTEXT Context);
}

// ===================================================================================
// EXE FUNCTION MAPPING STRUCTURES
// ===================================================================================
struct SourceCodeLine {
    std::string filePath;
    std::string fileName;
    int lineNumber;
    std::string sourceCode;  // Actual source code line
    DWORD64 address;
    
    SourceCodeLine() : lineNumber(0), address(0) {}
};

struct CodeDump {
    DWORD64 address;
    std::vector<unsigned char> bytes;
    std::string assembly;  // Disassembled code
    std::vector<SourceCodeLine> sourceLines;  // Actual source code lines from PDB
    size_t size;
    bool hasSourceCode;
    
    CodeDump() : address(0), size(0), hasSourceCode(false) {}
};

struct RegisterState {
    DWORD64 rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    DWORD64 r8, r9, r10, r11, r12, r13, r14, r15;
    DWORD64 rip;  // Instruction pointer
    DWORD64 flags;
    
    RegisterState() : rax(0), rbx(0), rcx(0), rdx(0), rsi(0), rdi(0), rbp(0), rsp(0),
                     r8(0), r9(0), r10(0), r11(0), r12(0), r13(0), r14(0), r15(0),
                     rip(0), flags(0) {}
};

struct ExeFunctionInfo {
    std::string name;
    std::string moduleName;
    DWORD64 address;
    DWORD64 moduleBase;
    DWORD64 offset;
    std::string sourceFile;
    int lineNumber;
    std::set<std::string> calledGFSDKFunctions;  // Which GFSDK functions this calls
    std::set<std::string> callers;               // Which EXE functions call this
    std::set<std::string> callees;               // Which EXE functions this calls
    int callCount;
    
    // Actual code capture
    CodeDump codeDump;           // Function's actual code bytes and assembly
    std::vector<RegisterState> registerSnapshots;  // Register states when called
    std::vector<std::vector<unsigned char>> stackSnapshots;  // Stack data
    bool codeCaptured;
    
    ExeFunctionInfo() : address(0), moduleBase(0), offset(0), lineNumber(0), 
                       callCount(0), codeCaptured(false) {}
};

struct CallRelationship {
    std::string fromFunction;
    std::string toFunction;
    std::string viaGFSDK;  // Which GFSDK function connects them
    int count;
    
    CallRelationship() : count(0) {}
};

// ===================================================================================
// LOGGING SYSTEM WITH EXE MAPPING
// ===================================================================================
class Logger {
private:
    std::ofstream logFile;
    bool enabled;
    CRITICAL_SECTION cs;
    
    // EXE Source Code Mapping
    std::map<DWORD64, ExeFunctionInfo> exeFunctions;  // Address -> Function Info
    std::map<std::string, ExeFunctionInfo> exeFunctionsByName;  // Name -> Function Info
    std::vector<CallRelationship> callGraph;
    std::set<std::string> exeModules;  // All EXE modules discovered
    std::map<std::string, DWORD64> moduleBases;  // Module name -> base address

public:
    Logger() : enabled(false) {
        InitializeCriticalSection(&cs);
    }

    ~Logger() {
        if (enabled) {
            DumpExeSourceMap();
        }
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

            // Extract GFSDK function name from message
            std::string gfsdkFunc = "";
            size_t callPos = message.find("[CALL] ");
            if (callPos != std::string::npos) {
                gfsdkFunc = message.substr(callPos + 7);
                // Remove any trailing whitespace
                size_t end = gfsdkFunc.find_last_not_of(" \t\r\n");
                if (end != std::string::npos) {
                    gfsdkFunc = gfsdkFunc.substr(0, end + 1);
                }
            }
            
            std::vector<std::string> callStackNames;
            
            // Log call stack and map EXE functions
            for (USHORT i = 0; i < frames && i < 32; i++) {  // Capture all frames for mapping
                DWORD64 address = (DWORD64)stack[i];

                // Get symbol name
                std::string symbolName = "Unknown";
                std::string moduleName = "Unknown";
                std::string fullModulePath = "";
                std::string sourceFile = "";
                int lineNumber = 0;
                DWORD64 moduleBase = 0;

                if (SymFromAddr(process, address, 0, symbol)) {
                    symbolName = symbol->Name;
                }

                // Get module name and base
                HMODULE hModule = NULL;
                if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    (LPCTSTR)address, &hModule)) {
                    moduleBase = (DWORD64)hModule;
                    char modName[MAX_PATH];
                    if (GetModuleFileNameA(hModule, modName, MAX_PATH)) {
                        fullModulePath = modName;
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

                // Only map EXE functions (not DLLs)
                bool isExeModule = false;
                if (!fullModulePath.empty()) {
                    std::string ext = fullModulePath.substr(fullModulePath.find_last_of("."));
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                    isExeModule = (ext == ".exe");
                    
                    if (isExeModule) {
                        exeModules.insert(moduleName);
                        moduleBases[moduleName] = moduleBase;
                        
                        // Map this EXE function
                        DWORD64 offset = address - moduleBase;
                        MapExeFunction(symbolName, moduleName, address, sourceFile, lineNumber, gfsdkFunc);
                        callStackNames.push_back(moduleName + "!" + symbolName);
                        
                        // Capture actual code at this function address
                        auto& func = exeFunctions[address];
                        if (!func.codeCaptured) {
                            func.codeDump = CaptureFunctionCode(address, 256);
                            func.codeCaptured = true;
                        }
                        
                        // Note: Register capture happens in hook context, not EXE context
                        // But we can still capture the code bytes which is the main goal
                    }
                }

                // Log top 5 frames for readability
                if (i < 5) {
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
            
            // Build call graph from captured stack
            if (!callStackNames.empty()) {
                BuildCallGraph(callStackNames, gfsdkFunc);
            }
        }
    }
    
private:
    // ===================================================================================
    // CODE CAPTURE FUNCTIONS (Inline definitions)
    // ===================================================================================
    
    // Read memory from process
    inline bool ReadMemory(DWORD64 address, void* buffer, size_t size) {
        // We're in the same process, so we can read directly
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
            return false;
        }
        
        // Check if memory is readable
        if (!(mbi.Protect & PAGE_READONLY) && 
            !(mbi.Protect & PAGE_READWRITE) && 
            !(mbi.Protect & PAGE_EXECUTE_READ) &&
            !(mbi.Protect & PAGE_EXECUTE_READWRITE)) {
            return false;
        }
        
        // Copy memory
        memcpy(buffer, (const void*)address, size);
        return true;
    }
    
    // Capture function code bytes - AGGRESSIVE WITH SOURCE CODE EXTRACTION
    inline CodeDump CaptureFunctionCode(DWORD64 address, size_t maxSize) {
        CodeDump dump;
        dump.address = address;
        dump.size = 0;
        dump.hasSourceCode = false;
        
        HANDLE process = GetCurrentProcess();
        
        // Get function size from symbols
        DWORD64 funcEndAddr = address + maxSize;
        char symBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
        SYMBOL_INFO* symbol = (SYMBOL_INFO*)symBuffer;
        symbol->MaxNameLen = MAX_SYM_NAME;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        
        DWORD64 displacement = 0;
        if (SymFromAddr(process, address, &displacement, symbol)) {
            if (symbol->Size > 0 && symbol->Size < maxSize) {
                funcEndAddr = address + symbol->Size;
            }
        }
        
        // Read memory
        unsigned char* buffer = new unsigned char[maxSize];
        if (ReadMemory(address, buffer, maxSize)) {
            dump.bytes.assign(buffer, buffer + maxSize);
            dump.size = maxSize;
            
            // Disassemble
            dump.assembly = DisassembleCode(buffer, maxSize, address);
            
            // AGGRESSIVE: Extract ACTUAL SOURCE CODE from PDB files
            dump.sourceLines = ExtractSourceCodeLines(address, funcEndAddr);
            dump.hasSourceCode = !dump.sourceLines.empty();
        }
        delete[] buffer;
        
        return dump;
    }
    
    // AGGRESSIVE: Extract source code lines from PDB - reads actual .cpp/.h files
    inline std::vector<SourceCodeLine> ExtractSourceCodeLines(DWORD64 startAddr, DWORD64 endAddr) {
        std::vector<SourceCodeLine> sourceLines;
        HANDLE process = GetCurrentProcess();
        
        static bool symInitialized = false;
        if (!symInitialized) {
            SymInitialize(process, NULL, TRUE);
            SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_INCLUDE_32BIT_MODULES);
            symInitialized = true;
        }
        
        IMAGEHLP_LINE64 line;
        line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
        DWORD displacement = 0;
        
        DWORD64 currentAddr = startAddr;
        std::set<std::pair<std::string, int>> seenLines;
        
        // Walk through every address in function range
        while (currentAddr < endAddr && currentAddr < startAddr + 512) {
            if (SymGetLineFromAddr64(process, currentAddr, &displacement, &line)) {
                std::string filePath = line.FileName;
                int lineNum = line.LineNumber;
                
                auto key = std::make_pair(filePath, lineNum);
                if (seenLines.find(key) == seenLines.end()) {
                    seenLines.insert(key);
                    
                    SourceCodeLine srcLine;
                    srcLine.filePath = filePath;
                    srcLine.lineNumber = lineNum;
                    srcLine.address = line.Address;
                    
                    size_t pos = filePath.find_last_of("\\/");
                    if (pos != std::string::npos) {
                        srcLine.fileName = filePath.substr(pos + 1);
                    } else {
                        srcLine.fileName = filePath;
                    }
                    
                    // AGGRESSIVE: Read ACTUAL source code line from file
                    srcLine.sourceCode = ReadSourceFileLine(filePath, lineNum);
                    
                    sourceLines.push_back(srcLine);
                }
                
                currentAddr += 1;
            } else {
                currentAddr += 1;
            }
            
            if (currentAddr - startAddr > 512) break;
        }
        
        return sourceLines;
    }
    
    // AGGRESSIVE: Read actual source code line from .cpp/.h file
    inline std::string ReadSourceFileLine(const std::string& filePath, int lineNumber) {
        std::string sourceLine = "";
        if (filePath.empty() || lineNumber <= 0) return sourceLine;
        
        // Try multiple paths
        std::vector<std::string> searchPaths;
        searchPaths.push_back(filePath);
        
        // Try relative to current directory
        std::filesystem::path currentPath = std::filesystem::current_path();
        searchPaths.push_back((currentPath / filePath).string());
        
        // Try just filename
        size_t pos = filePath.find_last_of("\\/");
        if (pos != std::string::npos) {
            std::string fileName = filePath.substr(pos + 1);
            searchPaths.push_back(fileName);
            searchPaths.push_back((currentPath / fileName).string());
        }
        
        // Try parent directories
        for (int i = 0; i < 5; i++) {
            std::filesystem::path parentPath = currentPath;
            for (int j = 0; j < i; j++) {
                parentPath = parentPath.parent_path();
            }
            searchPaths.push_back((parentPath / filePath).string());
            if (pos != std::string::npos) {
                searchPaths.push_back((parentPath / filePath.substr(pos + 1)).string());
            }
        }
        
        // Try reading from each path
        for (const auto& path : searchPaths) {
            std::ifstream file(path);
            if (file.is_open()) {
                std::string line;
                int currentLine = 1;
                
                while (std::getline(file, line) && currentLine <= lineNumber + 10) {
                    if (currentLine == lineNumber) {
                        // Trim
                        size_t start = line.find_first_not_of(" \t\r\n");
                        size_t end = line.find_last_not_of(" \t\r\n");
                        if (start != std::string::npos && end != std::string::npos) {
                            sourceLine = line.substr(start, end - start + 1);
                        } else {
                            sourceLine = line;
                        }
                        file.close();
                        return sourceLine;
                    }
                    currentLine++;
                }
                file.close();
            }
        }
        
        return sourceLine;
    }
    
    // Capture register state using context capture
    inline RegisterState CaptureRegisters() {
        RegisterState regs;
        
        #ifdef _WIN64
        // Capture context using CONTEXT structure
        CONTEXT ctx;
        RtlCaptureContext(&ctx);
        
        regs.rax = ctx.Rax;
        regs.rbx = ctx.Rbx;
        regs.rcx = ctx.Rcx;
        regs.rdx = ctx.Rdx;
        regs.rsi = ctx.Rsi;
        regs.rdi = ctx.Rdi;
        regs.rbp = ctx.Rbp;
        regs.rsp = ctx.Rsp;
        regs.r8 = ctx.R8;
        regs.r9 = ctx.R9;
        regs.r10 = ctx.R10;
        regs.r11 = ctx.R11;
        regs.r12 = ctx.R12;
        regs.r13 = ctx.R13;
        regs.r14 = ctx.R14;
        regs.r15 = ctx.R15;
        regs.rip = ctx.Rip;
        regs.flags = ctx.EFlags;
        #endif
        
        return regs;
    }
    
    // Capture stack memory
    inline std::vector<unsigned char> CaptureStack(DWORD64 rsp, size_t size) {
        std::vector<unsigned char> stackData(size, 0);
        
        if (rsp != 0 && ReadMemory(rsp, stackData.data(), size)) {
            return stackData;
        }
        
        return std::vector<unsigned char>();
    }
    
    // Simple disassembler - decode x64 instructions
    inline std::string DisassembleCode(const unsigned char* code, size_t size, DWORD64 baseAddr) {
        std::string result;
        size_t offset = 0;
        
        // Simple instruction decoder for common x64 instructions
        // This is a basic implementation - for full disassembly, use Capstone or similar
        while (offset < size && offset < 64) {  // Limit to first 64 bytes
            char line[256];
            DWORD64 addr = baseAddr + offset;
            
            unsigned char opcode = code[offset];
            
            // Common instruction patterns
            if (opcode == 0x48) {  // REX.W prefix
                if (offset + 1 < size) {
                    unsigned char next = code[offset + 1];
                    if (next == 0x89) {  // MOV
                        sprintf_s(line, "0x%llX: %02X %02X ... mov [reg], [reg]\n", addr, opcode, next);
                        offset += 2;
                    } else if (next == 0x8B) {  // MOV
                        sprintf_s(line, "0x%llX: %02X %02X ... mov [reg], [reg]\n", addr, opcode, next);
                        offset += 2;
                    } else if (next == 0x83) {  // ADD/SUB/CMP immediate
                        sprintf_s(line, "0x%llX: %02X %02X ... add/sub/cmp [reg], imm8\n", addr, opcode, next);
                        offset += 3;
                    } else if (next == 0xFF) {  // CALL/JMP
                        sprintf_s(line, "0x%llX: %02X %02X ... call/jmp [reg]\n", addr, opcode, next);
                        offset += 2;
                    } else {
                        sprintf_s(line, "0x%llX: %02X %02X ... (unknown)\n", addr, opcode, next);
                        offset += 2;
                    }
                } else {
                    sprintf_s(line, "0x%llX: %02X (incomplete)\n", addr, opcode);
                    offset++;
                }
            } else if (opcode == 0xE8) {  // CALL rel32
                sprintf_s(line, "0x%llX: %02X ... call rel32\n", addr, opcode);
                offset += 5;
            } else if (opcode == 0xE9) {  // JMP rel32
                sprintf_s(line, "0x%llX: %02X ... jmp rel32\n", addr, opcode);
                offset += 5;
            } else if (opcode == 0xC3) {  // RET
                sprintf_s(line, "0x%llX: %02X ret\n", addr, opcode);
                offset++;
                break;  // End of function likely
            } else if (opcode == 0x55) {  // PUSH RBP
                sprintf_s(line, "0x%llX: %02X push rbp\n", addr, opcode);
                offset++;
            } else if (opcode == 0x5D) {  // POP RBP
                sprintf_s(line, "0x%llX: %02X pop rbp\n", addr, opcode);
                offset++;
            } else if (opcode >= 0x50 && opcode <= 0x57) {  // PUSH reg
                sprintf_s(line, "0x%llX: %02X push r%cx\n", addr, opcode, 'a' + (opcode - 0x50));
                offset++;
            } else if (opcode >= 0x58 && opcode <= 0x5F) {  // POP reg
                sprintf_s(line, "0x%llX: %02X pop r%cx\n", addr, opcode, 'a' + (opcode - 0x58));
                offset++;
            } else {
                // Unknown opcode - dump hex
                sprintf_s(line, "0x%llX: %02X (unknown)\n", addr, opcode);
                offset++;
            }
            
            result += line;
            
            // Safety limit
            if (offset >= size) break;
        }
        
        return result;
    }
    
    inline void MapExeFunction(const std::string& funcName, const std::string& moduleName, 
                       DWORD64 address, const std::string& sourceFile, int lineNum,
                       const std::string& currentGFSDKCall) {
        EnterCriticalSection(&cs);
        
        auto& func = exeFunctions[address];
        if (func.name.empty()) {
            func.name = funcName;
            func.moduleName = moduleName;
            func.address = address;
            func.sourceFile = sourceFile;
            func.lineNumber = lineNum;
            
            auto it = moduleBases.find(moduleName);
            if (it != moduleBases.end()) {
                func.moduleBase = it->second;
                func.offset = address - it->second;
            }
        }
        
        func.calledGFSDKFunctions.insert(currentGFSDKCall);
        func.callCount++;
        
        exeFunctionsByName[moduleName + "!" + funcName] = func;
        
        LeaveCriticalSection(&cs);
    }
    
    inline void BuildCallGraph(const std::vector<std::string>& callStack, const std::string& gfsdkFunc) {
        if (callStack.size() < 2) return;
        
        EnterCriticalSection(&cs);
        
        // Build relationships: each function calls the next one in the stack
        for (size_t i = 0; i < callStack.size() - 1; i++) {
            std::string from = callStack[i];
            std::string to = callStack[i + 1];
            
            // Update callees/callers
            auto& fromFunc = exeFunctionsByName[from];
            auto& toFunc = exeFunctionsByName[to];
            
            if (!fromFunc.name.empty()) {
                fromFunc.callees.insert(to);
            }
            if (!toFunc.name.empty()) {
                toFunc.callers.insert(from);
            }
            
            // Add to call graph
            CallRelationship rel;
            rel.fromFunction = from;
            rel.toFunction = to;
            rel.viaGFSDK = gfsdkFunc;
            rel.count = 1;
            
            // Check if relationship already exists
            bool found = false;
            for (auto& existing : callGraph) {
                if (existing.fromFunction == from && existing.toFunction == to) {
                    existing.count++;
                    found = true;
                    break;
                }
            }
            if (!found) {
                callGraph.push_back(rel);
            }
        }
        
        LeaveCriticalSection(&cs);
    }
    
    inline void DumpExeSourceMap() {
        if (exeFunctions.empty()) return;
        
        // Create map file in same directory as log file
        std::filesystem::path mapFile = "EXE_SOURCE_CODE_MAP.txt";
        
        std::ofstream mapStream(mapFile);
        if (!mapStream.is_open()) return;
        
        mapStream << "================================================================================\n";
        mapStream << "           EXE SOURCE CODE MAP - Complete Function Mapping\n";
        mapStream << "================================================================================\n\n";
        
        mapStream << "Total EXE Functions Discovered: " << exeFunctions.size() << "\n";
        mapStream << "Total EXE Modules: " << exeModules.size() << "\n\n";
        
        // Module Information
        mapStream << "=== MODULES ===\n";
        for (const auto& mod : exeModules) {
            auto it = moduleBases.find(mod);
            if (it != moduleBases.end()) {
                mapStream << "  " << mod << " [Base: 0x" << std::hex << it->second << std::dec << "]\n";
            }
        }
        mapStream << "\n";
        
        // Functions by Module
        mapStream << "=== FUNCTIONS BY MODULE ===\n\n";
        for (const auto& mod : exeModules) {
            mapStream << "--- " << mod << " ---\n";
            
            std::vector<ExeFunctionInfo> modFunctions;
            for (const auto& pair : exeFunctions) {
                if (pair.second.moduleName == mod) {
                    modFunctions.push_back(pair.second);
                }
            }
            
            // Sort by address
            std::sort(modFunctions.begin(), modFunctions.end(), 
                [](const ExeFunctionInfo& a, const ExeFunctionInfo& b) {
                    return a.address < b.address;
                });
            
            for (const auto& func : modFunctions) {
                mapStream << "\n  Function: " << func.name << "\n";
                mapStream << "    Address: 0x" << std::hex << func.address << std::dec << "\n";
                mapStream << "    Offset: 0x" << std::hex << func.offset << std::dec << "\n";
                if (!func.sourceFile.empty()) {
                    mapStream << "    Source: " << func.sourceFile << ":" << func.lineNumber << "\n";
                }
                mapStream << "    Call Count: " << func.callCount << "\n";
                
                if (!func.calledGFSDKFunctions.empty()) {
                    mapStream << "    Calls GFSDK Functions:\n";
                    for (const auto& gfsdk : func.calledGFSDKFunctions) {
                        mapStream << "      - " << gfsdk << "\n";
                    }
                }
                
                if (!func.callers.empty()) {
                    mapStream << "    Called By:\n";
                    for (const auto& caller : func.callers) {
                        mapStream << "      - " << caller << "\n";
                    }
                }
                
                if (!func.callees.empty()) {
                    mapStream << "    Calls:\n";
                    for (const auto& callee : func.callees) {
                        mapStream << "      - " << callee << "\n";
                    }
                }
                
                // Dump actual code
                if (func.codeCaptured && !func.codeDump.bytes.empty()) {
                    // AGGRESSIVE: Dump ACTUAL SOURCE CODE from PDB files
                    if (func.codeDump.hasSourceCode && !func.codeDump.sourceLines.empty()) {
                        mapStream << "\n    === ACTUAL C++ SOURCE CODE (from PDB) ===\n";
                        for (const auto& srcLine : func.codeDump.sourceLines) {
                            mapStream << "    " << srcLine.fileName << ":" << srcLine.lineNumber 
                                      << " [0x" << std::hex << srcLine.address << std::dec << "]\n";
                            if (!srcLine.sourceCode.empty()) {
                                mapStream << "      " << srcLine.sourceCode << "\n";
                            } else {
                                mapStream << "      (source line not found in file)\n";
                            }
                        }
                    }
                    
                    mapStream << "\n    === DISASSEMBLY (Assembly Code) ===\n";
                    mapStream << func.codeDump.assembly;
                    
                    mapStream << "\n    === CODE BYTES (Hex Dump) ===\n";
                    mapStream << "    Address: 0x" << std::hex << func.codeDump.address << std::dec << "\n";
                    mapStream << "    Size: " << func.codeDump.size << " bytes\n";
                    mapStream << "    Hex: ";
                    for (size_t i = 0; i < func.codeDump.bytes.size() && i < 64; i++) {
                        mapStream << std::hex << std::setfill('0') << std::setw(2) 
                                  << (unsigned int)func.codeDump.bytes[i] << " ";
                        if ((i + 1) % 16 == 0) {
                            mapStream << "\n           ";
                        }
                    }
                    mapStream << std::dec << "\n";
                }
                
                // Dump register states
                if (!func.registerSnapshots.empty()) {
                    mapStream << "\n    === REGISTER STATES ===\n";
                    for (size_t i = 0; i < func.registerSnapshots.size() && i < 3; i++) {
                        const auto& regs = func.registerSnapshots[i];
                        mapStream << "    Snapshot #" << (i + 1) << ":\n";
                        mapStream << "      RAX=0x" << std::hex << regs.rax << std::dec << "  ";
                        mapStream << "RBX=0x" << std::hex << regs.rbx << std::dec << "  ";
                        mapStream << "RCX=0x" << std::hex << regs.rcx << std::dec << "  ";
                        mapStream << "RDX=0x" << std::hex << regs.rdx << std::dec << "\n";
                        mapStream << "      RSI=0x" << std::hex << regs.rsi << std::dec << "  ";
                        mapStream << "RDI=0x" << std::hex << regs.rdi << std::dec << "  ";
                        mapStream << "RBP=0x" << std::hex << regs.rbp << std::dec << "  ";
                        mapStream << "RSP=0x" << std::hex << regs.rsp << std::dec << "\n";
                        mapStream << "      R8=0x" << std::hex << regs.r8 << std::dec << "  ";
                        mapStream << "R9=0x" << std::hex << regs.r9 << std::dec << "  ";
                        mapStream << "R10=0x" << std::hex << regs.r10 << std::dec << "  ";
                        mapStream << "R11=0x" << std::hex << regs.r11 << std::dec << "\n";
                        mapStream << "      R12=0x" << std::hex << regs.r12 << std::dec << "  ";
                        mapStream << "R13=0x" << std::hex << regs.r13 << std::dec << "  ";
                        mapStream << "R14=0x" << std::hex << regs.r14 << std::dec << "  ";
                        mapStream << "R15=0x" << std::hex << regs.r15 << std::dec << "\n";
                        mapStream << "      RIP=0x" << std::hex << regs.rip << std::dec << "  ";
                        mapStream << "FLAGS=0x" << std::hex << regs.flags << std::dec << "\n";
                    }
                }
                
                // Dump stack snapshots
                if (!func.stackSnapshots.empty()) {
                    mapStream << "\n    === STACK SNAPSHOTS ===\n";
                    for (size_t i = 0; i < func.stackSnapshots.size() && i < 2; i++) {
                        const auto& stack = func.stackSnapshots[i];
                        mapStream << "    Stack #" << (i + 1) << " (" << stack.size() << " bytes):\n";
                        mapStream << "      ";
                        for (size_t j = 0; j < stack.size() && j < 64; j++) {
                            mapStream << std::hex << std::setfill('0') << std::setw(2) 
                                      << (unsigned int)stack[j] << " ";
                            if ((j + 1) % 16 == 0) {
                                mapStream << "\n      ";
                            }
                        }
                        mapStream << std::dec << "\n";
                    }
                }
            }
            mapStream << "\n";
        }
        
        // Call Graph
        mapStream << "=== CALL GRAPH ===\n";
        mapStream << "Total Relationships: " << callGraph.size() << "\n\n";
        
        std::map<std::string, int> funcCallCounts;
        for (const auto& rel : callGraph) {
            funcCallCounts[rel.fromFunction + " -> " + rel.toFunction] += rel.count;
        }
        
        // Sort by count
        std::vector<std::pair<std::string, int>> sortedCalls(funcCallCounts.begin(), funcCallCounts.end());
        std::sort(sortedCalls.begin(), sortedCalls.end(),
            [](const std::pair<std::string, int>& a, const std::pair<std::string, int>& b) {
                return a.second > b.second;
            });
        
        for (const auto& pair : sortedCalls) {
            mapStream << "  " << pair.first << " [" << pair.second << "x]\n";
        }
        
        mapStream << "\n================================================================================\n";
        mapStream << "End of EXE Source Code Map\n";
        mapStream << "================================================================================\n";
        
        mapStream.close();
        Log("EXE Source Code Map saved to: EXE_SOURCE_CODE_MAP.txt");
    }
};

# Complete C++ Code Reference - What The Proxy Sees

## 🔍 Every Data Point Captured By The Code

### 1. Process Initialization Data (dllmain.cpp)

```cpp
// Line 201-239 in dllmain.cpp
case DLL_PROCESS_ATTACH:
{
    // CAPTURED: Proxy DLL module handle
    HMODULE hModule  // Address: e.g., 0x00007FF874E60000

    // CAPTURED: Executable directory path
    std::filesystem::path exeDir = GetExeDirectory();
    // Example: "D:\Program Files (x86)\Steam\steamapps\common\Age of Mythology Retold"

    // CAPTURED: DLL directory path
    std::filesystem::path dllDir = GetCurrentDllDirectory();
    // Example: Same as exe dir (when DLL is in game folder)

    // CAPTURED: Config file path
    std::filesystem::path configPath = dllDir / "config.ini";

    // CAPTURED: Original DLL handle and path
    g_origDll  // Address: e.g., 0x00007FFFD0D20000
}
```

### 2. Function Call Interception (all_hooks.cpp)

Every hooked function captures:

```cpp
// Example from GFSDK_Aftermath_EnableGpuCrashDumps (lines 145-157)
extern "C" __declspec(dllexport) void* GFSDK_Aftermath_EnableGpuCrashDumps(...) {
    // ===== CAPTURE POINT 1: Function Entry =====
    // Timestamp: Automatic (in LogWithCallStack)
    // Function Name: "GFSDK_Aftermath_EnableGpuCrashDumps"
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_EnableGpuCrashDumps", 2);

    // ===== CAPTURE POINT 2: Function Address =====
    if (!orig_GFSDK_Aftermath_EnableGpuCrashDumps && g_origDll) {
        orig_GFSDK_Aftermath_EnableGpuCrashDumps =
            (GFSDK_Aftermath_EnableGpuCrashDumps_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_EnableGpuCrashDumps");
        // Captures: Address of real function in original DLL
    }

    // ===== CAPTURE POINT 3: Function Execution =====
    void* result = orig_GFSDK_Aftermath_EnableGpuCrashDumps();
    // All parameters are forwarded automatically via ... (variadic)

    // ===== CAPTURE POINT 4: Return Value =====
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_EnableGpuCrashDumps -> %p", result);
    // Captures: Return value (pointer or status code)

    return result;
}
```

### 3. Call Stack Extraction (logger.h)

```cpp
// Lines 66-151 in logger.h
void LogWithCallStack(const std::string& message, int skipFrames = 1) {
    // ===== CAPTURE POINT 1: Raw Stack Addresses =====
    void* stack[32];  // Array to hold up to 32 return addresses
    USHORT frames = CaptureStackBackTrace(skipFrames, 32, stack, NULL);
    // skipFrames = 2 means skip:
    //   [0] LogWithCallStack itself
    //   [1] The hook function (e.g., GFSDK_Aftermath_EnableGpuCrashDumps)
    // Start from [2] = the caller in the target application

    // Returns: Number of frames captured
    // stack[] now contains: [0x7FF6A1B34520, 0x7FF6A1B35100, ...]

    // ===== CAPTURE POINT 2: Symbol Initialization =====
    HANDLE process = GetCurrentProcess();
    static bool symInitialized = false;
    if (!symInitialized) {
        SymInitialize(process, NULL, TRUE);
        // TRUE = load symbols for ALL modules in process
        // This includes: .exe, all .dlls, system libraries

        SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);
        // SYMOPT_LOAD_LINES = enable line number lookup
        // SYMOPT_UNDNAME = demangle C++ names
        symInitialized = true;
    }

    // ===== CAPTURE POINT 3: Symbol Information Buffer =====
    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    SYMBOL_INFO* symbol = (SYMBOL_INFO*)buffer;
    symbol->MaxNameLen = MAX_SYM_NAME;  // 2000 characters max
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);

    // ===== CAPTURE POINT 4: Line Information =====
    IMAGEHLP_LINE64 line;
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    DWORD displacement = 0;  // Offset from start of line

    // ===== ITERATE THROUGH STACK FRAMES =====
    for (USHORT i = 0; i < frames && i < 5; i++) {
        DWORD64 address = (DWORD64)stack[i];

        // === SUB-CAPTURE 1: Function Name ===
        std::string symbolName = "Unknown";
        if (SymFromAddr(process, address, 0, symbol)) {
            symbolName = symbol->Name;
            // EXTRACTED DATA:
            //   - Function name (from export table OR PDB)
            //   - Decorated C++ name (can be undecorated)
            //   - Symbol->Address = actual function start address
            //   - Symbol->Size = function size in bytes
        }

        // === SUB-CAPTURE 2: Module Name ===
        std::string moduleName = "Unknown";
        HMODULE hModule = NULL;
        if (GetModuleHandleEx(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCTSTR)address, &hModule)) {

            char modName[MAX_PATH];
            if (GetModuleFileNameA(hModule, modName, MAX_PATH)) {
                moduleName = modName;
                // EXTRACTED DATA:
                //   - Full path: "D:\...\AoMRetold.exe"
                //   - Module base address: hModule

                // Extract just filename
                size_t pos = moduleName.find_last_of("\\/");
                if (pos != std::string::npos) {
                    moduleName = moduleName.substr(pos + 1);
                    // Result: "AoMRetold.exe"
                }
            }
        }

        // === SUB-CAPTURE 3: Source File & Line Number ===
        std::string sourceFile = "";
        int lineNumber = 0;
        if (SymGetLineFromAddr64(process, address, &displacement, &line)) {
            sourceFile = line.FileName;  // Full path
            lineNumber = line.LineNumber;
            // EXTRACTED DATA (requires PDB):
            //   - Source file path
            //   - Line number
            //   - Displacement (bytes from line start)

            // Extract just filename
            size_t pos = sourceFile.find_last_of("\\/");
            if (pos != std::string::npos) {
                sourceFile = sourceFile.substr(pos + 1);
            }
        }

        // === FINAL OUTPUT ===
        char stackFrame[1024];
        if (!sourceFile.empty()) {
            sprintf_s(stackFrame, "    [%d] %s!%s (%s:%d) [0x%llX]",
                i,              // Frame number
                moduleName.c_str(),     // "AoMRetold.exe"
                symbolName.c_str(),     // "GraphicsInit"
                sourceFile.c_str(),     // "renderer.cpp"
                lineNumber,             // 234
                address                 // 0x7FF6A1B34520
            );
        } else {
            sprintf_s(stackFrame, "    [%d] %s!%s [0x%llX]",
                i,
                moduleName.c_str(),
                symbolName.c_str(),
                address
            );
        }

        Log(stackFrame);
    }
}
```

---

## 📊 Data Structures Exposed

### SYMBOL_INFO Structure
```cpp
typedef struct _SYMBOL_INFO {
    ULONG   SizeOfStruct;     // Size of this structure
    ULONG   TypeIndex;        // Type index of symbol
    ULONG64 Reserved[2];
    ULONG   Index;            // Index of symbol
    ULONG   Size;             // Size of symbol in bytes
    ULONG64 ModBase;          // Base address of module
    ULONG   Flags;            // Symbol flags
    ULONG64 Value;            // Value of symbol (address)
    ULONG64 Address;          // Address of symbol
    ULONG   Register;         // Register holding value
    ULONG   Scope;            // Scope of symbol
    ULONG   Tag;              // Symbol tag (function, data, etc.)
    ULONG   NameLen;          // Length of name
    ULONG   MaxNameLen;       // Max length for name buffer
    CHAR    Name[1];          // Name of symbol (variable length)
} SYMBOL_INFO;
```

**What You Extract:**
- `Address`: Function start address
- `Size`: Function size (can calculate end address)
- `ModBase`: Module base address
- `Name`: Function name (demangled)
- `Flags`: Properties (local/global, etc.)

### IMAGEHLP_LINE64 Structure
```cpp
typedef struct _IMAGEHLP_LINE64 {
    DWORD   SizeOfStruct;     // Size of structure
    PVOID   Key;              // Internal use
    DWORD   LineNumber;       // Line number in source
    PCHAR   FileName;         // Full path to source file
    DWORD64 Address;          // Address of line
} IMAGEHLP_LINE64;
```

**What You Extract:**
- `LineNumber`: Exact line in source code
- `FileName`: Full path to .cpp/.c/.h file
- `Address`: Memory address of that line

---

## 🎯 Memory Addresses - What They Tell You

### Example Address: 0x7FF6A1B34520

#### Breaking Down the Address:
```
0x7FF6A1B34520
  ^^            = High bytes indicate 64-bit user-space address
    ^^^^^^      = Module base + offset
          ^^^^  = Function offset within module
```

### Calculating Offsets:
```cpp
// If you know:
DWORD64 functionAddress = 0x7FF6A1B34520;
HMODULE moduleBase = 0x7FF6A1B00000;  // From GetModuleHandleEx

// Calculate offset:
DWORD64 offset = functionAddress - (DWORD64)moduleBase;
// Result: 0x34520

// This offset is FIXED across runs (without ASLR on DLL)
// Can use in IDA/Ghidra: BaseAddress + 0x34520 = GraphicsInit
```

---

## 🔬 Function Signature Extraction

Even without PDB, you can extract function signatures:

### 1. From Decorated Names
```cpp
// Captured from SymFromAddr:
"?InitGraphics@Engine@@QEAAXPEAX@Z"

// Undecorate using undname.exe or SymUnDName:
"public: void __cdecl Engine::InitGraphics(void *)"

// Extracted information:
// - Class: Engine
// - Method: InitGraphics
// - Return type: void
// - Calling convention: __cdecl
// - Parameters: (void *)
```

### 2. From Export Tables
```cpp
// If function is exported, you get:
// - Function name
// - Export ordinal
// - RVA (Relative Virtual Address)
```

---

## 💾 Complete Memory Layout

### What You Can Map:

```
Process Memory Map (extracted from logs):

0x7FF6A1A00000 - 0x7FF6A1FFFFFF  AoMRetold.exe (60 MB)
  0x7FF6A1A12340  WinMain
  0x7FF6A1B20000  EngineStart
  0x7FF6A1B34520  GraphicsInit
  0x7FF6A1B35100  D3D12Initialize
  0x7FF6A1C20000  HandleGpuCrash
  0x7FF6A1D10000  CompileShader

0x7FF874E60000 - 0x7FF874EFFFFF  GFSDK_Aftermath_Lib.x64.dll (Proxy)
0x7FFFD0D20000 - 0x7FFFD0DFFFFF  orig_GFSDK_Aftermath_Lib.x64.dll
0x7FFFD2A00000 - 0x7FFFD2AFFFFF  KERNEL32.DLL
...
```

---

## 🛠️ Extraction Techniques

### 1. Finding All Functions in a Module

```bash
# Parse log file for all functions from AoMRetold.exe
grep "AoMRetold.exe!" GFSDK_Aftermath_proxy.log | \
  cut -d'!' -f2 | \
  cut -d' ' -f1 | \
  sort | uniq > aom_functions.txt
```

### 2. Building Call Graphs

```python
import re

def extract_call_graph(log_file):
    call_graph = {}
    current_function = None

    with open(log_file) as f:
        for line in f:
            # Find function calls
            if '[CALL]' in line:
                current_function = line.split('[CALL]')[1].strip()
                call_graph[current_function] = []

            # Find callers in stack
            elif current_function and '[0]' in line:
                match = re.search(r'(\w+\.exe)!(\w+)', line)
                if match:
                    module, function = match.groups()
                    call_graph[current_function].append(f"{module}::{function}")

    return call_graph
```

### 3. Memory Address Database

```python
def build_address_database(log_file):
    addresses = {}

    with open(log_file) as f:
        for line in f:
            # Extract: Module!Function [Address]
            match = re.search(r'(\w+\.exe)!(\w+).*\[(0x[0-9A-F]+)\]', line)
            if match:
                module, function, address = match.groups()
                addresses[address] = {
                    'module': module,
                    'function': function
                }

    return addresses
```

---

## 🎮 Age of Mythology Retold - Specific Discoveries

### From Your Sample Log

```
[CALL] GFSDK_Aftermath_EnableGpuCrashDumps
[RETURN] -> 00000000BAD00001
```

#### Analyzing Return Value: 0xBAD00001

```cpp
// NVIDIA Aftermath return codes (from their SDK):
#define GFSDK_Aftermath_Result_Success              0x1
#define GFSDK_Aftermath_Result_NotAvailable         0xBAD00001
#define GFSDK_Aftermath_Result_Fail                 0xBAD00002
#define GFSDK_Aftermath_Result_FAIL_VersionMismatch 0xBAD00003

// Your return: 0xBAD00001 = NotAvailable
```

**Meaning**:
- GPU crash dumps could NOT be enabled
- Possible reasons:
  1. Non-NVIDIA GPU (Aftermath only works on NVIDIA)
  2. Driver too old
  3. Feature not supported on this GPU
  4. Already enabled

**This tells us**: AoM Retold tries to enable Aftermath, but it's not available in your VM

---

## 🔍 API Parameter Extraction (Advanced)

### Current Limitation
```cpp
void* GFSDK_Aftermath_EnableGpuCrashDumps(...) {
```

The `...` (variadic) means we don't capture individual parameters.

### How to Capture Parameters

#### Method 1: Modify Hook Definition
```cpp
// Find actual signature from NVIDIA Aftermath SDK
extern "C" __declspec(dllexport)
int GFSDK_Aftermath_EnableGpuCrashDumps(
    unsigned int version,
    unsigned int flags,
    void* pCreateGpuCrashDumpCallback,
    void* pShaderDebugInfoCallback,
    void* pCrashDumpDescriptionCallback,
    void* pUserData
) {
    // Now you can log each parameter!
    if (g_logger) {
        g_logger->LogFormat("[PARAMS] version=%u, flags=0x%X, callbacks=%p,%p,%p, userdata=%p",
            version, flags,
            pCreateGpuCrashDumpCallback,
            pShaderDebugInfoCallback,
            pCrashDumpDescriptionCallback,
            pUserData);
    }

    // Call original with real parameters
    return orig_GFSDK_Aftermath_EnableGpuCrashDumps(
        version, flags,
        pCreateGpuCrashDumpCallback,
        pShaderDebugInfoCallback,
        pCrashDumpDescriptionCallback,
        pUserData
    );
}
```

#### Method 2: Stack Parameter Extraction
```cpp
// Access stack directly (x64 calling convention)
void* GFSDK_Aftermath_EnableGpuCrashDumps(...) {
    // On x64, first 4 params in RCX, RDX, R8, R9
    // Can use inline assembly or compiler intrinsics to read them

    void* rsp;
    __asm { mov rsp, RSP }

    // Stack parameters start at RSP+0x20 (after shadow space)
    void** stack_params = (void**)((char*)rsp + 0x20);

    if (g_logger) {
        g_logger->LogFormat("[STACK] Param5=%p, Param6=%p",
            stack_params[0], stack_params[1]);
    }
}
```

---

## 📈 Performance Metrics You Can Extract

### Timing Analysis
```cpp
// In logger.h, each log has timestamp:
[2025-11-23 16:50:40.317] [CALL] Function
[2025-11-23 16:50:40.318] [RETURN] Function

// Parse to get execution time: 1ms
```

### Call Frequency
```bash
# Count how many times each function is called
grep "\[CALL\]" log.txt | sort | uniq -c | sort -nr

# Output:
# 1523 [CALL] GFSDK_Aftermath_GetDeviceStatus
#  842 [CALL] GFSDK_Aftermath_SetEventMarker
#    1 [CALL] GFSDK_Aftermath_EnableGpuCrashDumps
```

### Hot Path Analysis
```
# Find most common call stacks
grep -A 5 "\[CALL\]" log.txt | grep "\[0\]" | sort | uniq -c | sort -nr
```

---

## 🎓 Summary of Extractable Data

| Data Type | Source | Requires PDB | Example |
|-----------|--------|--------------|---------|
| Function names (hooked) | Hook code | No | GFSDK_Aftermath_EnableGpuCrashDumps |
| Caller function names | SymFromAddr | No (uses exports) | GraphicsInit |
| Module names | GetModuleFileName | No | AoMRetold.exe |
| Memory addresses | CaptureStackBackTrace | No | 0x7FF6A1B34520 |
| Return values | Hook code | No | 0xBAD00001 |
| Timestamps | GetLocalTime | No | 16:50:40.317 |
| Source files | SymGetLineFromAddr64 | **Yes** | renderer.cpp |
| Line numbers | SymGetLineFromAddr64 | **Yes** | 234 |
| Function sizes | SymFromAddr | Sometimes | 0x150 bytes |
| Module base addresses | GetModuleHandleEx | No | 0x7FF6A1B00000 |
| Call frequencies | Log analysis | No | 1523 calls |
| Execution times | Timestamp delta | No | 1ms |
| Call graphs | Log analysis | No | WinMain → EngineStart → ... |

**Total: 13 types of data, 10 work without PDB files!**

---

**Last Updated**: 2025-11-23
**Purpose**: Complete technical reference for data extraction
**Target**: Reverse engineers, security researchers, performance analysts

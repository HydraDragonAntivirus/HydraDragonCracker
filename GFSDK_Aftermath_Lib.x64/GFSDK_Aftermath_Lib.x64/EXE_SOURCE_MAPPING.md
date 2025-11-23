# EXE Source Code Mapping - Complete Function Discovery

## Overview

The enhanced proxy DLL now automatically captures and maps **ALL functions from the calling EXE** that interact with GFSDK Aftermath. This creates a complete source code map of the target application's internal structure.

## What Gets Captured

### 1. **All EXE Functions**
- Function names (from export tables or symbols)
- Memory addresses (absolute and relative offsets)
- Module base addresses
- Source file paths (if PDB available)
- Line numbers (if PDB available)

### 2. **Function Relationships**
- **Callers**: Which EXE functions call each function
- **Callees**: Which EXE functions each function calls
- **GFSDK Connections**: Which GFSDK functions each EXE function calls
- **Call Frequency**: How many times each function is called

### 3. **Call Graph**
- Complete call chains showing function relationships
- Frequency of each call path
- Connection points through GFSDK functions

## How It Works

### Automatic Mapping
Every time a GFSDK function is called, the proxy:
1. Captures the full call stack (up to 32 frames)
2. Identifies all EXE modules (filters out DLLs)
3. Maps each EXE function with its address, name, and metadata
4. Builds relationships between functions
5. Tracks which GFSDK functions each EXE function calls

### Output File
When the DLL unloads (or application exits), it automatically generates:
- **EXE_SOURCE_CODE_MAP.txt** - Complete mapping of all discovered functions

## Example Output

```
================================================================================
           EXE SOURCE CODE MAP - Complete Function Mapping
================================================================================

Total EXE Functions Discovered: 47
Total EXE Modules: 1

=== MODULES ===
  AoMRetold.exe [Base: 0x7FF6A1A00000]

=== FUNCTIONS BY MODULE ===

--- AoMRetold.exe ---

  Function: GraphicsInit
    Address: 0x7FF6A1B34520
    Offset: 0x34520
    Source: renderer.cpp:234
    Call Count: 1
    Calls GFSDK Functions:
      - GFSDK_Aftermath_EnableGpuCrashDumps
    Called By:
      - AoMRetold.exe!D3D12Initialize
    Calls:
      - AoMRetold.exe!InitializeEngine

  Function: D3D12Initialize
    Address: 0x7FF6A1B35100
    Offset: 0x35100
    Source: d3d12_renderer.cpp:156
    Call Count: 1
    Calls GFSDK Functions:
      - GFSDK_Aftermath_DX12_Initialize
    Called By:
      - AoMRetold.exe!EngineStart
    Calls:
      - AoMRetold.exe!GraphicsInit

=== CALL GRAPH ===
Total Relationships: 23

  AoMRetold.exe!WinMain -> AoMRetold.exe!EngineStart [5x]
  AoMRetold.exe!EngineStart -> AoMRetold.exe!D3D12Initialize [3x]
  AoMRetold.exe!D3D12Initialize -> AoMRetold.exe!GraphicsInit [2x]
  ...
```

## What You Can Do With This

### 1. **Reverse Engineering**
- Map the entire application structure
- Understand initialization sequences
- Identify key functions and their relationships
- Find entry points for further analysis

### 2. **Function Discovery**
- Discover all functions that use GPU features
- Find graphics initialization code
- Locate crash handling routines
- Identify shader compilation paths

### 3. **Call Flow Analysis**
- Understand how functions call each other
- Trace execution paths
- Identify hot paths (frequently called functions)
- Map the complete call hierarchy

### 4. **Memory Mapping**
- Get exact addresses of functions
- Calculate offsets for static analysis
- Map code sections
- Identify function boundaries

## Technical Details

### Function Detection
- Uses Windows DbgHelp API for symbol resolution
- Works with export tables (no PDB required for function names)
- PDB files provide source file and line number information
- Automatically filters to only EXE modules (excludes DLLs)

### Thread Safety
- All mapping operations are thread-safe
- Uses critical sections to protect shared data
- Safe for multi-threaded applications

### Performance
- Minimal overhead (symbol resolution cached)
- Map generation only happens on DLL unload
- No impact on application performance during runtime

## Configuration

No additional configuration needed! The mapping happens automatically when:
- `EnableLogging=1` in config.ini
- The proxy DLL is loaded by the target application

## Output Location

The map file is saved as:
- **EXE_SOURCE_CODE_MAP.txt** in the same directory as the log file

## Advanced Usage

### Finding Specific Functions
Search the map file for:
- Function names
- Source files
- Memory addresses
- GFSDK function connections

### Building Call Trees
Use the call graph section to:
- Understand execution flow
- Identify critical paths
- Find entry points
- Map function dependencies

### Memory Analysis
Use the addresses and offsets to:
- Load in IDA Pro / Ghidra
- Set breakpoints in debuggers
- Calculate RVA offsets
- Map to disassembly

## Limitations

1. **PDB Required for Source Info**: Source files and line numbers only available if PDB files are present
2. **Export Table Only**: Function names come from export tables if no PDB
3. **Call Stack Depth**: Limited to 32 frames (configurable in code)
4. **EXE Only**: Only maps functions from .exe files, not DLLs

## Future Enhancements

Possible additions:
- Parameter capture (requires function signatures)
- Real-time map updates
- JSON/XML export format
- Visual call graph generation
- Function size calculation
- Code section mapping

---

**This feature automatically maps the entire EXE's source code structure that interacts with GFSDK Aftermath, giving you complete visibility into the target application's internal architecture.**


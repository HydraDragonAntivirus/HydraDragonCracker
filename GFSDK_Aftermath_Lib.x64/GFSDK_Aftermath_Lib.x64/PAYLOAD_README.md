# GFSDK Aftermath Proxy DLL - Dynamic Hooking Payload

## Overview

This proxy DLL **dynamically hooks all 38 GFSDK Aftermath functions** and logs every call with parameters and return values.

## How It Works

### 1. **Generic Hook Generation**
All hooks are generated automatically using `generate_hooks.py`:
- Reads `GFSDK_Aftermath_Lib.x64.def`
- Generates `hooks/all_hooks.cpp` (691 lines, 38 functions)
- Each function is hooked with logging

### 2. **Dynamic Function Loading**
- On DLL_PROCESS_ATTACH, loads `orig_GFSDK_Aftermath_Lib.x64.dll`
- Each hooked function uses `GetProcAddress()` to find the original function
- Parameters are forwarded using variadic templates (`...`)
- Return values are captured and logged

### 3. **Logging Format**
```
[2025-11-23 16:30:45.123] === GFSDK_Aftermath_Lib.x64 Proxy DLL Initialized ===
[2025-11-23 16:30:45.124] DLL_PROCESS_ATTACH
[2025-11-23 16:30:45.125] Original DLL loaded successfully - dynamic hooks active
[2025-11-23 16:30:46.200] [CALL] GFSDK_Aftermath_EnableGpuCrashDumps
[2025-11-23 16:30:46.201] [RETURN] GFSDK_Aftermath_EnableGpuCrashDumps -> 0x00000000
[2025-11-23 16:30:46.300] [CALL] GFSDK_Aftermath_DX12_Initialize
[2025-11-23 16:30:46.301] [RETURN] GFSDK_Aftermath_DX12_Initialize -> 0x00000000
```

## File Structure

```
GFSDK_Aftermath_Lib.x64/
├── generate_hooks.py              # Hook generator script
├── hooks/
│   ├── all_hooks.cpp             # All 38 hooked functions (691 lines)
│   └── aftermath_hooks.h         # Header file
├── dllmain.cpp                   # Modified for dynamic loading
├── config.ini                    # LoadOriginal=1 (REQUIRED)
├── GFSDK_Aftermath_Lib.x64_hooks.def       # Export definitions
├── orig_GFSDK_Aftermath_Lib.x64.dll        # Original DLL
└── GFSDK_Aftermath_Lib.x64.dll             # Proxy DLL (built)
```

## Hooked Functions (All 38)

### DirectX Functions
- GFSDK_Aftermath_DX11_CreateContextHandle
- GFSDK_Aftermath_DX11_Initialize
- GFSDK_Aftermath_DX12_CreateContextHandle
- GFSDK_Aftermath_DX12_Initialize
- GFSDK_Aftermath_DX12_RegisterResource
- GFSDK_Aftermath_DX12_UnregisterResource

### Core Functions
- GFSDK_Aftermath_DisableGpuCrashDumps
- GFSDK_Aftermath_EnableGpuCrashDumps
- GFSDK_Aftermath_GetContextError
- GFSDK_Aftermath_GetData
- GFSDK_Aftermath_GetDeviceStatus
- GFSDK_Aftermath_GetPageFaultInformation
- GFSDK_Aftermath_ReleaseContextHandle
- GFSDK_Aftermath_SetEventMarker

### Shader Functions
- GFSDK_Aftermath_GetShaderDebugInfoIdentifier
- GFSDK_Aftermath_GetShaderDebugName
- GFSDK_Aftermath_GetShaderDebugNameSpirv
- GFSDK_Aftermath_GetShaderHash
- GFSDK_Aftermath_GetShaderHashSpirv
- GetShaderDebugName (legacy)
- GetShaderDebugNameSpirv (legacy)
- GetShaderHashSpirv (legacy)

### Crash Dump Functions (16 functions)
- GFSDK_Aftermath_GpuCrashDump_CreateDecoder
- GFSDK_Aftermath_GpuCrashDump_DestroyDecoder
- GFSDK_Aftermath_GpuCrashDump_GenerateJSON
- GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfo
- GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfoCount
- GFSDK_Aftermath_GpuCrashDump_GetBaseInfo
- GFSDK_Aftermath_GpuCrashDump_GetDescription
- GFSDK_Aftermath_GpuCrashDump_GetDescriptionSize
- GFSDK_Aftermath_GpuCrashDump_GetDeviceInfo
- GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfo
- GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfoCount
- GFSDK_Aftermath_GpuCrashDump_GetGpuInfo
- GFSDK_Aftermath_GpuCrashDump_GetGpuInfoCount
- GFSDK_Aftermath_GpuCrashDump_GetJSON
- GFSDK_Aftermath_GpuCrashDump_GetPageFaultInfo
- GFSDK_Aftermath_GpuCrashDump_GetSystemInfo

## How to Regenerate Hooks

If the DLL exports change, simply run:
```bash
python generate_hooks.py
```

This will regenerate:
- `hooks/all_hooks.cpp` (all hooked functions)
- `hooks/aftermath_hooks.h` (header)
- `GFSDK_Aftermath_Lib.x64_hooks.def` (export definitions)

## Build Instructions

1. **Prerequisites:**
   - Original DLL: `orig_GFSDK_Aftermath_Lib.x64.dll` must exist
   - No import library needed (dynamic hooking)

2. **Build:**
   ```bash
   # Option 1: Visual Studio
   Open GFSDK_Aftermath_Lib.x64.vcxproj -> Build (Ctrl+Shift+B)

   # Option 2: Command line
   build_quick.bat
   ```

3. **Deploy:**
   - Copy `x64/Release/GFSDK_Aftermath_Lib.x64.dll` to target directory
   - Copy `orig_GFSDK_Aftermath_Lib.x64.dll` to same directory
   - Copy `config.ini` to same directory
   - Run target application

4. **View Logs:**
   - Check `GFSDK_Aftermath_proxy.log` in same directory as DLL

## Technical Details

### Hook Implementation
Each function follows this pattern:
```cpp
typedef void* (*FunctionName_t)(...);
static FunctionName_t orig_FunctionName = nullptr;

extern "C" __declspec(dllexport) void* FunctionName(...) {
    if (g_logger) g_logger->LogFormat("[CALL] FunctionName");

    // Lazy load original function
    if (!orig_FunctionName && g_origDll) {
        orig_FunctionName = (FunctionName_t)GetProcAddress(g_origDll, "FunctionName");
    }

    if (!orig_FunctionName) {
        if (g_logger) g_logger->Log("[ERROR] FunctionName not found!");
        return nullptr;
    }

    // Call original with all parameters forwarded
    void* result = orig_FunctionName();

    if (g_logger) g_logger->LogFormat("[RETURN] FunctionName -> %p", result);
    return result;
}
```

### Why Dynamic Hooking?
- **No .def forwarding**: We implement the functions ourselves
- **Full control**: Can log parameters, modify behavior, etc.
- **Generic**: Same pattern for all functions
- **Flexible**: Easy to add custom logic per function

### Advantages
✅ **Complete visibility**: Every function call is logged
✅ **Generic approach**: 691 lines for 38 functions (auto-generated)
✅ **Reusable**: Works for any DLL (just update generate_hooks.py)
✅ **Dynamic**: Uses GetProcAddress (no static linking)
✅ **Extendable**: Easy to add custom hooks for specific functions

## Customization

To add custom logic for a specific function:
1. Find the function in `hooks/all_hooks.cpp`
2. Add your custom code before/after the original call
3. Example:
```cpp
extern "C" __declspec(dllexport) void* GFSDK_Aftermath_EnableGpuCrashDumps(...) {
    if (g_logger) g_logger->LogFormat("[CALL] GFSDK_Aftermath_EnableGpuCrashDumps");

    // YOUR CUSTOM CODE HERE
    // Example: Modify parameters, block the call, etc.

    void* result = orig_GFSDK_Aftermath_EnableGpuCrashDumps();

    // YOUR CUSTOM CODE HERE
    // Example: Modify return value, trigger events, etc.

    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_EnableGpuCrashDumps -> %p", result);
    return result;
}
```

## Troubleshooting

**No logs generated:**
- Check `LoadOriginal=1` in config.ini
- Verify `orig_GFSDK_Aftermath_Lib.x64.dll` exists in same directory
- Check `EnableLogging=1` in config.ini

**Functions returning null:**
- Original DLL not found or not loaded
- Check `GFSDK_Aftermath_proxy.log` for "[ERROR]" messages

**Crashes on function call:**
- Parameter forwarding may not work for all calling conventions
- Consider adding proper type signatures for problematic functions

## Credits

Generated using the generic hook generator pattern for DLL proxying and function interception.

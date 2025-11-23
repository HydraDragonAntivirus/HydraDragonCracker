# GFSDK_Aftermath_Lib.x64 Proxy DLL

A proxy DLL for NVIDIA's GFSDK Aftermath library that forwards all function calls to the original DLL while providing logging and hooking capabilities.

## What is this?

This is a proxy/wrapper DLL that sits between your application and the original GFSDK_Aftermath_Lib.x64.dll. It:
- Forwards all 38 exported functions to the original DLL
- Logs DLL initialization and operations
- Provides a framework for hooking specific functions if needed
- Uses automatic forwarding via .def files (no manual GetProcAddress needed)

## Files

- **GFSDK_Aftermath_Lib.x64.dll** - Your proxy DLL (builds from this project)
- **orig_GFSDK_Aftermath_Lib.x64.dll** - The original NVIDIA Aftermath DLL (renamed)
- **config.ini** - Configuration file for logging and DLL loading
- **GFSDK_Aftermath_Lib.x64_forwarding.def** - Function forwarding definitions
- **dllmain.cpp** - Main proxy DLL implementation with logging

## How to Build

### Step 1: Create Import Library (Required First Time)

Before building, you need to create an import library (.lib) from the .def file:

**Option A: Using Visual Studio Developer Command Prompt**
1. Open Visual Studio Developer Command Prompt (or x64 Native Tools Command Prompt)
2. Navigate to this directory
3. Run `create_import_lib.bat`
4. This creates `orig_GFSDK_Aftermath_Lib.x64.lib` and `orig_GFSDK_Aftermath_Lib.x64.exp`

**Option B: Manual**
```bash
lib.exe /DEF:GFSDK_Aftermath_Lib.x64.def /OUT:orig_GFSDK_Aftermath_Lib.x64.lib /MACHINE:X64
```

### Step 2: Build the Proxy DLL

**Using Visual Studio**
1. Open `GFSDK_Aftermath_Lib.x64.vcxproj` in Visual Studio 2019 or 2022
2. Select your platform (x64 recommended)
3. Select configuration (Release recommended)
4. Build the project (Ctrl+Shift+B)

**Using Command Line**
1. Run `build_quick.bat`
2. Select platform (1 for x64, 2 for Win32)
3. Select configuration (1 for Release, 2 for Debug)
4. The DLL will be built to `x64\Release\GFSDK_Aftermath_Lib.x64.dll`

## How to Use

1. **Backup the original DLL**
   - Copy your original `GFSDK_Aftermath_Lib.x64.dll` to `orig_GFSDK_Aftermath_Lib.x64.dll`
   - Or ensure it's in the same directory as specified in config.ini

2. **Build the proxy DLL**
   - Use Visual Studio or `build_quick.bat`
   - Copy the built `GFSDK_Aftermath_Lib.x64.dll` to your application directory

3. **Deploy**
   - Place `GFSDK_Aftermath_Lib.x64.dll` (proxy) in your application directory
   - Place `orig_GFSDK_Aftermath_Lib.x64.dll` (original) in the same directory
   - Optionally copy `config.ini` to configure logging

4. **Run your application**
   - The proxy will automatically load and forward calls to the original DLL
   - Check `GFSDK_Aftermath_proxy.log` for operation logs

## Configuration (config.ini)

```ini
[General]
EnableLogging=1              # Enable/disable logging (0 or 1)
LogFile=GFSDK_Aftermath_proxy.log  # Log file name
DebugMode=0                  # Debug mode (0 or 1)

[DLL]
OriginalDLL=orig_GFSDK_Aftermath_Lib.x64.dll  # Original DLL name
LoadMethod=0                 # 0=Same dir, 1=System32, 2=Custom path
LoadOriginal=0               # Manually load original DLL (usually 0)
```

## Exported Functions

The proxy forwards all 38 functions from the original DLL:
- DirectX 11 & 12 initialization functions
- Crash dump management functions
- GPU debugging and profiling functions
- Shader debugging utilities
- And more...

See `GFSDK_Aftermath_Lib.x64_forwarding.def` for the complete list.

## Adding Custom Hooks

To intercept specific function calls:

1. Edit `dllmain.cpp`
2. Uncomment and modify the example hook function
3. Remove the function from the .def file (so it's not auto-forwarded)
4. Implement your custom logic
5. Call the original function via GetProcAddress
6. Rebuild the project

Example hook template is provided in `dllmain.cpp`.

## Technical Details

- **Platform**: Windows x64 (x86 also supported)
- **Language**: C++17
- **Forwarding**: Automatic via .def files
- **Logging**: Thread-safe file logging with timestamps
- **Configuration**: INI-based configuration

## Troubleshooting

**Application fails to start:**
- Ensure `orig_GFSDK_Aftermath_Lib.x64.dll` is in the correct location
- Check that the proxy DLL was built for the correct platform (x64 vs Win32)
- Review `GFSDK_Aftermath_proxy.log` for error messages

**No log file created:**
- Ensure `EnableLogging=1` in config.ini
- Check write permissions in the application directory
- Verify the proxy DLL is actually being loaded

**Functions not working:**
- Verify all 38 functions are listed in the .def file
- Ensure the original DLL is compatible with your application
- Check the log file for forwarding errors

## Credits

Based on the ucrtbase proxy DLL pattern from the HydraDragonCracker project.

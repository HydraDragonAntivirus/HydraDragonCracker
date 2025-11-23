# UCRTBASE Proxy DLL

This project creates a proxy DLL for `ucrtbase.dll` that forwards all function calls to the original Windows UCRT base library while allowing you to intercept and log specific operations.

## Features

- **2483 Exported Functions**: Automatically forwards all ucrtbase.dll exports
- **Logging System**: Built-in logging to track DLL usage
- **Configuration File**: Easy configuration via `config.ini`
- **Extensible**: Add custom hooks for specific functions as needed
- **Python Analysis Tools**: Includes utilities for analyzing DLL structure

## Files Overview

### Core Files
- `dllmain.cpp` - Main DLL implementation with logging and configuration
- `ucrtbase_forwarding.def` - Module definition file with all 2483 export forwards
- `config.ini` - Configuration file for logging and behavior
- `ucrtbase.vcxproj` - Visual Studio project file

### Python Utilities
- `prepare_build.py` - Prepares the build environment
- `extract_ucrtbase_exports.py` - Extracts exports from ucrtbase.dll
- `create_forwarding_def.py` - Creates forwarding .def file
- `analyze_dll.py` - Analyzes DLL structure
- `understand_dll.py` - Comprehensive DLL analysis
- `monitor_dll.py` - Runtime DLL monitoring

## Building the Proxy DLL

### Prerequisites
- Visual Studio 2022 (or compatible)
- Windows SDK
- Python 3.x with `pefile` module (for build preparation)

### Build Steps

1. **Prepare the Build Environment**
   ```bash
   python prepare_build.py
   ```
   This script will:
   - Copy the original `ucrtbase.dll` from System32 as `orig_ucrtbase.dll`
   - Verify all required files are present
   - Check the .def file integrity

2. **Open the Project**
   - Open `ucrtbase.vcxproj` in Visual Studio

3. **Select Configuration**
   - Choose **x64** or **Win32** platform (match your target application)
   - Choose **Release** or **Debug** configuration

4. **Build**
   - Build → Build Solution (Ctrl+Shift+B)
   - Output will be in `x64/Release/` or `Win32/Release/`

## Usage

### Basic Deployment

1. **Locate Your Built DLL**
   - After building, find `ucrtbase.dll` in the output directory

2. **Deploy the Files**
   ```
   your_app_directory/
   ├── your_application.exe
   ├── ucrtbase.dll          (your proxy DLL)
   ├── orig_ucrtbase.dll     (original from System32)
   └── config.ini            (optional)
   ```

3. **Run Your Application**
   - The proxy DLL will automatically load and forward all calls
   - Check `ucrtbase_proxy.log` for logging output

### Configuration

Edit `config.ini` to customize behavior:

```ini
[General]
EnableLogging=1              # Enable/disable logging
LogFile=ucrtbase_proxy.log   # Log file name
DebugMode=0                  # Extra debug information

[DLL]
OriginalDLL=orig_ucrtbase.dll  # Name of original DLL
LoadMethod=0                   # 0=Same dir, 1=System32, 2=Custom
```

## How It Works

### Forwarding Mechanism

The proxy DLL uses export forwarding in the `.def` file:

```def
LIBRARY ucrtbase
EXPORTS
    malloc=orig_ucrtbase.dll.malloc @1
    free=orig_ucrtbase.dll.free @2
    ...
```

When an application calls a function from your `ucrtbase.dll`, Windows automatically redirects the call to the corresponding function in `orig_ucrtbase.dll`.

### Adding Custom Hooks

To intercept specific functions:

1. **Remove the forward from the .def file**
   - Comment out or remove the line for the function you want to hook

2. **Implement the function in dllmain.cpp**
   ```cpp
   extern "C" __declspec(dllexport) void* malloc(size_t size) {
       if (g_logger) {
           g_logger->LogFormat("malloc called: size=%zu", size);
       }

       // Call original function
       typedef void* (*malloc_t)(size_t);
       static malloc_t orig_malloc = nullptr;

       if (!orig_malloc && g_origDll) {
           orig_malloc = (malloc_t)GetProcAddress(g_origDll, "malloc");
       }

       return orig_malloc ? orig_malloc(size) : nullptr;
   }
   ```

3. **Enable manual DLL loading in config.ini**
   ```ini
   [DLL]
   LoadOriginal=1
   ```

## Python Tools Usage

### Analyze DLL Structure
```bash
python analyze_dll.py ucrtbase.dll
```

### Extract Exports
```bash
python extract_ucrtbase_exports.py
```

### Create Forwarding Definition
```bash
python create_forwarding_def.py
```

## Troubleshooting

### Application Won't Start
- Ensure `orig_ucrtbase.dll` is in the same directory
- Check that platform (x64/x86) matches your application
- Verify Windows version compatibility

### No Logging Output
- Check `EnableLogging=1` in config.ini
- Ensure the application has write permissions
- Look for the log file in the application's directory

### Build Errors
- Verify all files are present (run `prepare_build.py`)
- Check that `ucrtbase_forwarding.def` exists and is properly formatted
- Ensure Visual Studio has the correct Windows SDK installed

## Security Considerations

⚠️ **Warning**: Replacing system DLLs can cause stability issues and security vulnerabilities.

- **Only for Testing**: Use this proxy DLL in controlled testing environments
- **Never Deploy to Production**: Do not distribute with production applications
- **Malware Detection**: Some antivirus software may flag proxy DLLs
- **Code Signing**: Consider signing your DLL for legitimate use cases

## License

This is a development and testing tool. Use responsibly and only in authorized environments.

## Credits

Based on the LX63 proxy DLL framework, adapted for ucrtbase.dll with 2483 exports.

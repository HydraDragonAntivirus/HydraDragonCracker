# Universal DLL Proxy Generator

This is a **generic, universal DLL proxy** that can intercept and forward calls from ANY Windows DLL, similar to the `fake_ctypes.c` pattern you use for Python extensions.

## How It Works

1. **Native C DLL** - Compiles to a native Windows DLL (not a .NET assembly)
2. **Transparent Forwarding** - Loads the original DLL and forwards all function calls
3. **Bypasses Strong-Name Verification** - Works even for strong-named .NET assemblies
4. **Logging** - Logs all intercepted calls for analysis

## Architecture

```
Application (RikaPy.exe)
    ↓
Proxy DLL (System.Windows.Forms.dll) ← Native C code
    ↓
Original DLL (orig.dll) ← Real .NET assembly
```

## Files

- **`generic_proxy.c`** - Universal proxy source code (works for ANY DLL)
- **`build_generic_proxy.bat`** - Windows build script
- **`generate_exports.py`** - Python script to extract DLL exports (optional)
- **`System.Windows.Forms.dll`** - The compiled proxy (79KB native DLL)
- **`orig.dll`** - The original System.Windows.Forms.dll (5.8MB .NET assembly)

## Quick Start

### Step 1: Prepare Original DLL

Make sure `orig.dll` exists in the same directory:

```cmd
copy "C:\WINDOWS\Microsoft.NET\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll" orig.dll
```

### Step 2: Build the Proxy

#### Option A: Using the build script
```cmd
build_generic_proxy.bat
```

#### Option B: Manual compilation
```cmd
gcc -shared -o System.Windows.Forms.dll generic_proxy.c -Wl,--enable-stdcall-fixup -static-libgcc
```

### Step 3: Test

```cmd
RikaPy.exe
```

Check `generic_proxy.log` for intercepted calls.

## Configuration

Edit `generic_proxy.c` to change settings:

```c
#define ORIGINAL_DLL_NAME "orig.dll"    // Name of original DLL
#define LOG_FILE "generic_proxy.log"    // Log file path
```

## Advantages Over Config Files

| Method | Strong-Name Bypass | No Admin Required | Works Immediately |
|--------|-------------------|-------------------|-------------------|
| **Config File** | ❌ No | ✅ Yes | ❌ No (needs registry) |
| **Native Proxy** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Registry Hack** | ✅ Yes | ❌ No (needs admin) | ✅ Yes |

## Why This Works

1. **CLR loads native DLLs first** - Before checking for .NET assemblies
2. **No strong-name check** - Native DLLs don't have strong names
3. **We control the load** - We manually load the original DLL and forward calls
4. **No app.config needed** - Works without any configuration files

## Customization for Other DLLs

To proxy a different DLL (e.g., `SomeDll.dll`):

1. Edit `generic_proxy.c`:
   ```c
   #define ORIGINAL_DLL_NAME "SomeDll_original.dll"
   ```

2. Rename files:
   ```cmd
   ren SomeDll.dll SomeDll_original.dll
   ```

3. Rebuild:
   ```cmd
   gcc -shared -o SomeDll.dll generic_proxy.c -Wl,--enable-stdcall-fixup
   ```

## Troubleshooting

### Problem: DLL fails to load
- Check `generic_proxy.log` for error messages
- Verify `orig.dll` exists in the same directory
- Make sure MinGW/GCC is installed

### Problem: Application crashes
- The original DLL may have exports we didn't handle
- Check the log to see which function failed
- Add explicit forwarding for that function in `generic_proxy.c`

### Problem: No log file created
- The proxy DLL may not be loading at all
- Check that RikaPy.exe is loading your proxy, not the GAC version
- Delete `System.Windows.Forms.dll` temporarily - if the app still runs, it's using GAC

## Advanced: Intercepting Specific Functions

To intercept and modify specific function calls, add code like this:

```c
__declspec(dllexport) int SomeFunction(int arg) {
    Log("[INTERCEPT] SomeFunction called with arg=%d", arg);

    // Modify argument
    arg = arg * 2;

    // Call original
    typedef int (*FuncType)(int);
    FuncType origFunc = (FuncType)GetProcAddress(g_hOriginalDll, "SomeFunction");

    if (origFunc) {
        int result = origFunc(arg);
        Log("[RESULT] SomeFunction returned %d", result);
        return result;
    }

    return 0;
}
```

## Comparison with fake_ctypes.c

| Feature | fake_ctypes.c | generic_proxy.c |
|---------|---------------|-----------------|
| Language | C | C |
| Target | Python extension (.pyd) | Any Windows DLL |
| Load Method | LoadLibrary + GetProcAddress | LoadLibrary + GetProcAddress |
| Forwarding | Python C API | Generic function pointers |
| Use Case | Python module hijacking | .NET/Win32 DLL hijacking |

## License

This is a security research and reverse engineering tool. Use responsibly and only on software you own or have permission to analyze.

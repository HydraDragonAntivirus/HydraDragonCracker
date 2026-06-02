# dnlib Proxy Project

This project builds a managed proxy named `dnlib.dll` for the local `dnlib.dll` in the repository root.

## Build

```powershell
Copy-Item ..\..\dnlib.dll .\orig.dll
dotnet build ..\Tools\RenameDnlib\RenameDnlib.csproj -c Release
dotnet ..\Tools\RenameDnlib\bin\Release\net8.0\RenameDnlib.dll .\orig.dll dnlib.real .\dnlib.real.dll
.\tools\GenerateTypeForwarders.ps1
dotnet build ..\dnlib.sln -c Release
```

The build output contains:

- `dnlib.dll`: proxy DLL
- `dnlib.real.dll`: renamed original dnlib DLL used by type forwarding
- `dnlib_proxy_log.txt`: created at runtime next to the target executable

The proxy analysis is tuned for the Rika.NET protection/auth flow. It logs metadata hits for names such as `ApiKey`, `apiKeys`, `uploadKey`, `UploadTicket`, `PixeldrainClient`, `DeleteFileAsync`, `UploadFileAsync`, `XorKey`, and related obfuscated `ldstr` tokens. Potential secret-like strings are redacted in the log.

## Test Layout

To test with `RikaNET.WinUI.exe`, put the proxy `dnlib.dll` next to the executable and keep the renamed original as `dnlib.real.dll` in the same folder.

```text
RikaNET.WinUI.exe
dnlib.dll      # proxy
dnlib.real.dll # renamed original dnlib
```

Patch the target `.deps.json` so .NET can probe `dnlib.real.dll`:

```powershell
.\tools\PatchDepsForDnlibProxy.ps1 -DepsJsonPath "..\..\Rika Inc\Rika.NET\RikaNET.WinUI.deps.json"
```

Or install into the included Rika.NET folder:

```powershell
.\tools\InstallProxyToRikaNet.ps1
```

You can also set `REAL_DNLIB_PATH` to point at `dnlib.real.dll`.

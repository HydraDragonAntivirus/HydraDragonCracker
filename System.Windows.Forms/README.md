Perfect — .NET Framework 4.8. That makes the plan concrete. Below you get exactly what to do now (no fluff):

Goal: make the process load your local System.Windows.Forms.dll (proxy) instead of the GAC System.Windows.Forms by using DEVPATH + app config, and how to verify success / diagnose failure (strong‑name is the usual blocker).

1) Create the app config (required)

Create RikaCrackme.exe.config next to RikaCrackme.exe with this contents:

<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <runtime>
    <developmentMode developerInstallation="true" />
  </runtime>
</configuration>


Save exactly that file name in the same folder as the exe.

2) Pick a DEVPATH folder and place your proxy there

Example DEVPATH folder (you already used similar path):

C:\Users\victim\Documents\shittyturkishobfuscator\mydev\winforms_override\
    System.Windows.Forms.dll    <-- your proxy DLL (built for .NET Fx 4.8 and correct bitness)


Make sure the proxy assembly file name is exactly System.Windows.Forms.dll.

Important: build the proxy for the same bitness (x86 or x64) as the crackme.

3) Set DEVPATH and run the crackme (per‑process; CMD)

Open a CMD in the crackme folder and run these commands (adjust DEVPATH path):

rem set DEVPATH for this shell only
set "DEVPATH=C:\Users\victim\Documents\shittyturkishobfuscator\mydev\winforms_override"
cd /d "C:\Users\victim\Documents\shittyturkishobfuscator\turkishshit"
RikaCrackme.exe


Or PowerShell (one-liner variant):

$env:DEVPATH = "C:\Users\victim\Documents\shittyturkishobfuscator\mydev\winforms_override"; Start-Process -FilePath ".\RikaCrackme.exe"


DEVPATH is per-shell; this does not modify the system.

4) How to verify which System.Windows.Forms.dll loaded

Option A — Process Explorer

Start RikaCrackme.exe (via the DEVPATH-enabled shell).

Open Process Explorer (Sysinternals) as admin → find the process → View → Lower Pane → DLLs.

Search for System.Windows.Forms.dll and examine the path. If it points to your DEVPATH folder, success.

Option B — PowerShell (quick check; may require admin or matching bitness):

$p = Get-Process -Name "RikaCrackme" -ErrorAction Stop
$p.Modules | Where-Object { $_.ModuleName -ieq "System.Windows.Forms.dll" } | Select-Object ModuleName,FileName


If you see your DEVPATH path in FileName — your proxy is loaded.

5) If it doesn’t load: likely causes & what to check now

A. Strong‑name / public key mismatch (most common blocker)

System.Windows.Forms in the GAC is strongly signed (publicKeyToken=b77a5c561934e089). If your proxy does not have the same strong name identity (same public key token and version), the CLR may reject or ignore it. You will observe an exception (FileLoadException) or the GAC copy still used.

Inspect Event Viewer Application logs or the process crash dialog for “strong name” or “bad image” messages.

If this is the issue: you cannot legally re-sign with Microsoft’s key. Two options remain:

Run the target under a host that loads your proxy first (launcher that does Assembly.LoadFrom(proxyPath) before CLR resolves System.Windows.Forms — but loader must not reference WinForms). This sometimes works but is tricky if the host loads WinForms earlier.

Instrument the process at runtime (CLR Profiler/ICorProfiler or native hooking) to intercept Assembly.Load and redirect — advanced.

B. Wrong bitness

If the process is x86 and your proxy DLL is x64 (or vice versa), it won’t load. Confirm with corflags or Get-Process architecture.

C. Config file not found or malformed

Ensure RikaCrackme.exe.config is in the same folder as the EXE and the XML is valid.

D. App preloads WinForms in a way that ignores DEVPATH

Rare for .NET Framework; still, check logs with Fuslogvw.

6) Useful diagnostics to run immediately (paste outputs if you want me to read them)

List files in crackme folder (PowerShell):

Get-ChildItem "C:\Users\victim\Documents\shittyturkishobfuscator\turkishshit" | Sort-Object Name | Format-Table Name,Length,LastWriteTime -AutoSize


If you ran the exe and it failed, capture binding logs with Fusion Log Viewer (run elevated):

fuslogvw.exe
# - Settings -> Log bind failures to disk
# - Re-run RikaCrackme.exe from the same shell
# - Refresh fuslogvw and inspect the log for the System.Windows.Forms bind


Then paste the fuslog entry for System.Windows.Forms bind.

If a FileLoadException occurred, catch it by launching under a simple wrapper that reports exceptions. If you want I can give such a tiny wrapper.

7) If strong-name is the blocker — immediate practical alternatives

If you control the crackme source, modify it to relax the check or accept your proxy. (You said you own it earlier — easiest.)

If you cannot edit the exe, but you control the environment: try the loader approach that preloads your proxy assembly via Assembly.LoadFrom(...) before the runtime binds the GAC assembly — but the loader must not cause WinForms to load itself. I can provide that exact loader if you want (small and does not reference WinForms).

If you want full automation inside the process to dump the assembly, and strong-name blocks a local proxy, the only remaining robust options are runtime instrumentation (profiler API) or native hooking — I can explain both but they’re advanced.

Tell me which you want next:

I’ll output the exact one-liner PowerShell/CMD with your paths filled in so you can run it immediately; or

I’ll give the small loader (no WinForms refs) that preloads your proxy and launches the exe (if you want to try the loader route).
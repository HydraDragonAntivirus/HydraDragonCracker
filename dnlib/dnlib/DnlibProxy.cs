extern alias real;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

[assembly: AssemblyTitle("dnlib")]
[assembly: AssemblyDescription("dnlib managed proxy for local testing")]
[assembly: AssemblyCompany("RikaProxy")]
[assembly: AssemblyProduct("dnlib proxy")]
[assembly: AssemblyVersion("4.5.0.0")]
[assembly: AssemblyFileVersion("4.5.0.0")]
[assembly: AssemblyInformationalVersion("4.5.0-proxy")]
[assembly: ComVisible(false)]

namespace DnlibProxy;

internal static class ProxyModule
{
    [ModuleInitializer]
    internal static void Initialize()
    {
        ProxyBootstrap.Touch();
    }
}

public static class ProxyBootstrap
{
    private static readonly object InitLock = new();
    private static Assembly? realDnlibAssembly;
    private static bool initialized;
    private static bool analysisStarted;
    private static bool resolving;

    public static void Touch()
    {
        lock (InitLock)
        {
            if (initialized)
                return;

            initialized = true;
            ProxyLog.Write("=== dnlib proxy loaded ===");
            ProxyLog.Write("Proxy assembly: " + typeof(ProxyBootstrap).Assembly.Location);
            ProxyLog.Write("Process: " + Process.GetCurrentProcess().ProcessName + " (" + Environment.ProcessId + ")");

            AppDomain.CurrentDomain.AssemblyResolve -= OnAssemblyResolve;
            AppDomain.CurrentDomain.AssemblyResolve += OnAssemblyResolve;
            AssemblyLoadContext.Default.Resolving -= OnAssemblyLoadContextResolving;
            AssemblyLoadContext.Default.Resolving += OnAssemblyLoadContextResolving;

            // Auth bypass: RikaNET.WinUI yüklenince Dhr_003D'yi patch'le
            AppDomain.CurrentDomain.AssemblyLoad += OnAssemblyLoad;

            // Belki zaten yüklüdür (nadiren ama olabilir)
            var already = AppDomain.CurrentDomain.GetAssemblies()
                .FirstOrDefault(a => string.Equals(a.GetName().Name, "RikaNET.WinUI", StringComparison.OrdinalIgnoreCase));
            if (already != null)
            {
                AuthBypass.TryPatch(already);
                ProtectionBypass.TryPatch(already);
            }

            PreloadRealAssembly();
            StartAnalysisTimer();
        }
    }

    private static void OnAssemblyLoad(object? sender, AssemblyLoadEventArgs args)
    {
        if (string.Equals(args.LoadedAssembly.GetName().Name, "RikaNET.WinUI", StringComparison.OrdinalIgnoreCase))
        {
            AuthBypass.TryPatch(args.LoadedAssembly);
            ProtectionBypass.TryPatch(args.LoadedAssembly);
        }
    }

    private static Assembly? OnAssemblyLoadContextResolving(AssemblyLoadContext context, AssemblyName assemblyName)
    {
        if (!IsDnlibRequest(assemblyName))
            return null;

        ProxyLog.Write("AssemblyLoadContext.Resolving: " + assemblyName.FullName);
        return realDnlibAssembly ?? PreloadRealAssembly();
    }

    private static Assembly? OnAssemblyResolve(object? sender, ResolveEventArgs args)
    {
        if (resolving)
            return null;

        try
        {
            resolving = true;
            var assemblyName = new AssemblyName(args.Name);
            if (!IsDnlibRequest(assemblyName))
                return null;

            ProxyLog.Write("AppDomain.AssemblyResolve: " + args.Name);
            return realDnlibAssembly ?? PreloadRealAssembly();
        }
        finally
        {
            resolving = false;
        }
    }

    private static bool IsDnlibRequest(AssemblyName assemblyName)
    {
        return string.Equals(assemblyName.Name, "dnlib", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(assemblyName.Name, "dnlib.real", StringComparison.OrdinalIgnoreCase);
    }

    private static Assembly? PreloadRealAssembly()
    {
        if (realDnlibAssembly != null)
            return realDnlibAssembly;

        realDnlibAssembly = AppDomain.CurrentDomain.GetAssemblies()
            .FirstOrDefault(assembly => string.Equals(assembly.GetName().Name, "dnlib.real", StringComparison.OrdinalIgnoreCase));

        if (realDnlibAssembly != null)
        {
            ProxyLog.Write("Real dnlib already loaded: " + realDnlibAssembly.FullName);
            return realDnlibAssembly;
        }

        var realPath = FindRealDnlibPath();
        if (realPath == null)
        {
            ProxyLog.Write("ERROR: real dnlib not found. Put dnlib.real.dll next to the proxy or set REAL_DNLIB_PATH.");
            return null;
        }

        ProxyLog.Write("Loading real dnlib from: " + realPath);

        foreach (var loader in new Func<string, Assembly?>[]
        {
            LoadWithLoadFile,
            LoadWithDefaultContext,
            LoadWithBytes
        })
        {
            try
            {
                realDnlibAssembly = loader(realPath);
                if (realDnlibAssembly != null)
                {
                    ProxyLog.Write("Real dnlib loaded: " + realDnlibAssembly.FullName);
                    return realDnlibAssembly;
                }
            }
            catch (Exception ex)
            {
                ProxyLog.Write("Loader failed: " + loader.Method.Name + " -> " + ex.GetType().Name + ": " + ex.Message);
            }
        }

        ProxyLog.Write("ERROR: all real dnlib loading strategies failed.");
        return null;
    }

    private static Assembly? LoadWithLoadFile(string path)
    {
        return Assembly.LoadFile(path);
    }

    private static Assembly? LoadWithDefaultContext(string path)
    {
        return AssemblyLoadContext.Default.LoadFromAssemblyPath(path);
    }

    private static Assembly? LoadWithBytes(string path)
    {
        return Assembly.Load(File.ReadAllBytes(path));
    }

    private static string? FindRealDnlibPath()
    {
        var candidates = new[]
        {
            Environment.GetEnvironmentVariable("REAL_DNLIB_PATH"),
            Path.Combine(AppContext.BaseDirectory, "dnlib.real.dll"),
            Path.Combine(AppContext.BaseDirectory, "orig.dll"),
            Path.Combine(Path.GetDirectoryName(typeof(ProxyBootstrap).Assembly.Location) ?? AppContext.BaseDirectory, "dnlib.real.dll"),
            Path.Combine(Path.GetDirectoryName(typeof(ProxyBootstrap).Assembly.Location) ?? AppContext.BaseDirectory, "orig.dll"),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "orig.dll")),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "dnlib.real.dll")),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "dnlib.real.dll"))
        };

        return candidates.FirstOrDefault(path => !string.IsNullOrWhiteSpace(path) && File.Exists(path));
    }

    private static void StartAnalysisTimer()
    {
        if (analysisStarted)
            return;

        analysisStarted = true;
        ThreadPool.QueueUserWorkItem(_ =>
        {
            try
            {
                Thread.Sleep(2500);
                PerformAnalysis();
            }
            catch (Exception ex)
            {
                ProxyLog.Write("Analysis error: " + ex);
            }
        });
    }

    private static void PerformAnalysis()
    {
        ProxyLog.Write("=== dnlib proxy analysis ===");
        var assemblies = AppDomain.CurrentDomain.GetAssemblies();
        ProxyLog.Write("Loaded assemblies: " + assemblies.Length);

        foreach (var assembly in assemblies.OrderBy(a => a.GetName().Name))
        {
            var name = assembly.GetName().Name ?? "";
            if (name.StartsWith("System", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(name, "dnlib", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(name, "dnlib.real", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            ProxyLog.Write("Assembly: " + assembly.FullName);
            AnalyzeAssemblyForDnlibUsage(assembly);
            AnalyzeAssemblyMetadata(assembly);
        }

        ProxyLog.Write("=== analysis complete ===");
    }

    private static void AnalyzeAssemblyForDnlibUsage(Assembly assembly)
    {
        Type[] types;
        try
        {
            types = assembly.GetTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            types = ex.Types.Where(t => t != null).Cast<Type>().ToArray();
            ProxyLog.Write("  Type load warning: " + ex.Message);
        }
        catch (Exception ex)
        {
            ProxyLog.Write("  Type enumeration failed: " + ex.Message);
            return;
        }

        foreach (var type in types)
        {
            AnalyzeType(type);
        }
    }

    private static void AnalyzeType(Type type)
    {
        const BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly;

        foreach (var field in SafeMembers(() => type.GetFields(flags)))
        {
            if (IsDnlibType(field.FieldType) || IsInterestingName(field.Name))
                ProxyLog.Write("  Field: " + type.FullName + "." + field.Name + " : " + SafeTypeName(field.FieldType));

            if (field.IsLiteral && field.FieldType == typeof(string) && IsInterestingName(field.Name))
            {
                try
                {
                    if (field.GetRawConstantValue() is string value)
                        ProxyLog.Write("  Const string: " + type.FullName + "." + field.Name + " = " + FormatStringFinding(value));
                }
                catch
                {
                }
            }
        }

        foreach (var property in SafeMembers(() => type.GetProperties(flags)))
        {
            if (IsDnlibType(property.PropertyType) || IsInterestingName(property.Name))
                ProxyLog.Write("  Property: " + type.FullName + "." + property.Name + " : " + SafeTypeName(property.PropertyType));
        }

        foreach (var method in SafeMembers(() => type.GetMethods(flags)))
        {
            if (IsInterestingMethod(method))
            {
                var parameters = string.Join(", ", method.GetParameters().Select(p => SafeTypeName(p.ParameterType) + " " + p.Name));
                ProxyLog.Write("  Method: " + type.FullName + "." + method.Name + "(" + parameters + ") -> " + SafeTypeName(method.ReturnType));
            }
        }
    }

    private static T[] SafeMembers<T>(Func<T[]> getter)
    {
        try
        {
            return getter();
        }
        catch
        {
            return Array.Empty<T>();
        }
    }

    private static bool IsInterestingMethod(MethodInfo method)
    {
        if (IsInterestingName(method.Name) || IsDnlibType(method.ReturnType))
            return true;

        try
        {
            return method.GetParameters().Any(parameter =>
                IsDnlibType(parameter.ParameterType) ||
                IsInterestingName(parameter.Name ?? ""));
        }
        catch
        {
            return false;
        }
    }

    private static bool IsInterestingName(string name)
    {
        var lower = name.ToLowerInvariant();
        return lower.Contains("dnlib") ||
               lower.Contains("module") ||
               lower.Contains("assembly") ||
               lower.Contains("protect") ||
               lower.Contains("obfus") ||
               lower.Contains("encrypt") ||
               lower.Contains("decrypt") ||
               lower.Contains("license") ||
               lower.Contains("auth") ||
               lower.Contains("api") ||
               lower.Contains("apikey") ||
               lower.Contains("upload") ||
               lower.Contains("pixeldrain") ||
               lower.Contains("ticket") ||
               lower.Contains("fileid") ||
               lower.Contains("endpoint") ||
               lower.Contains("bearer") ||
               lower.Contains("authorization") ||
               lower.Contains("xor") ||
               lower.Contains("serial") ||
               lower.Contains("key") ||
               lower.Contains("token");
    }

    private static void AnalyzeAssemblyMetadata(Assembly assembly)
    {
        string path;
        try
        {
            path = assembly.Location;
        }
        catch
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return;

        try
        {
            using var module = real::dnlib.DotNet.ModuleDefMD.Load(path);
            var stringFindings = 0;

            foreach (var type in module.GetTypes())
            {
                var typeName = type.FullName;
                var typeInteresting = IsInterestingName(typeName);
                if (typeInteresting)
                    ProxyLog.Write("  [metadata] Type: " + typeName);

                foreach (var field in type.Fields)
                {
                    var fieldName = field.Name.String;
                    if (IsInterestingName(fieldName))
                        ProxyLog.Write("  [metadata] Field: " + typeName + "." + fieldName + " : " + field.FieldType.FullName);

                    if (field.HasConstant && field.Constant.Value is string constant && (IsInterestingName(fieldName) || IsInterestingString(constant)))
                        ProxyLog.Write("  [metadata] Const: " + typeName + "." + fieldName + " = " + FormatStringFinding(constant));
                }

                foreach (var method in type.Methods)
                {
                    var methodName = method.Name.String;
                    var methodInteresting = typeInteresting || IsInterestingName(methodName);

                    foreach (var param in method.ParamDefs)
                    {
                        if (IsInterestingName(param.Name.String))
                        {
                            methodInteresting = true;
                            ProxyLog.Write("  [metadata] Param: " + typeName + "." + methodName + " -> " + param.Name);
                        }
                    }

                    if (methodInteresting)
                        ProxyLog.Write("  [metadata] Method: " + typeName + "." + methodName);

                    if (!method.HasBody)
                        continue;

                    foreach (var instruction in method.Body.Instructions)
                    {
                        if (instruction.OpCode.Code != real::dnlib.DotNet.Emit.Code.Ldstr ||
                            instruction.Operand is not string value)
                        {
                            continue;
                        }

                        if ((methodInteresting || typeInteresting) && IsInterestingString(value))
                        {
                            ProxyLog.Write("  [metadata] ldstr: " + typeName + "." + methodName + " -> " + FormatStringFinding(value));
                            stringFindings++;
                        }

                        if (stringFindings >= 80)
                        {
                            ProxyLog.Write("  [metadata] string scan capped at 80 findings for " + assembly.GetName().Name);
                            return;
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            ProxyLog.Write("  [metadata] scan failed: " + ex.GetType().Name + ": " + ex.Message);
        }
    }

    private static bool IsInterestingString(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        var lower = value.ToLowerInvariant();
        return lower.Contains("http://") ||
               lower.Contains("https://") ||
               lower.Contains("pixeldrain") ||
               lower.Contains("api") ||
               lower.Contains("apikey") ||
               lower.Contains("upload") ||
               lower.Contains("authorization") ||
               lower.Contains("bearer") ||
               lower.Contains("license") ||
               lower.Contains("token") ||
               lower.Contains("secret") ||
               lower.Contains("file_id") ||
               lower.Contains("fileid") ||
               LooksLikeSecret(value);
    }

    private static bool LooksLikeSecret(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length < 20)
            return false;

        var base64ish = trimmed.Count(c => char.IsLetterOrDigit(c) || c is '+' or '/' or '=');
        var hexish = trimmed.Count(Uri.IsHexDigit);
        return base64ish >= trimmed.Length * 0.9 || hexish >= trimmed.Length * 0.9;
    }

    private static string FormatStringFinding(string value)
    {
        var trimmed = value.Replace("\r", "\\r").Replace("\n", "\\n");
        if (trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return trimmed.Length <= 160 ? trimmed : trimmed[..80] + "...<len=" + trimmed.Length + ">";
        }

        if (trimmed.Length <= 12)
            return "<len=" + trimmed.Length + ">";

        return trimmed[..Math.Min(6, trimmed.Length)] + "..." + trimmed[^Math.Min(6, trimmed.Length)..] + " <len=" + trimmed.Length + ">";
    }

    private static bool IsDnlibType(Type type)
    {
        while (type.HasElementType)
            type = type.GetElementType()!;

        if ((type.FullName ?? "").StartsWith("dnlib.", StringComparison.Ordinal))
            return true;

        if (!type.IsGenericType)
            return false;

        return type.GetGenericArguments().Any(IsDnlibType);
    }

    private static string SafeTypeName(Type type)
    {
        try
        {
            return type.FullName ?? type.Name;
        }
        catch
        {
            return "<unknown>";
        }
    }
}

internal static class ProxyLog
{
    private static readonly object LogLock = new();
    private static readonly string LogPath = GetLogPath();

    public static void Write(string message)
    {
        try
        {
            lock (LogLock)
            {
                var line = "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + "] " + message + Environment.NewLine;
                File.AppendAllText(LogPath, line);
                Console.Write(line);
            }
        }
        catch
        {
        }
    }

    private static string GetLogPath()
    {
        try
        {
            return Path.Combine(AppContext.BaseDirectory, "dnlib_proxy_log.txt");
        }
        catch
        {
            return Path.Combine(Path.GetTempPath(), "dnlib_proxy_log.txt");
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime auth bypass — JIT function pointer swap
//
// Strateji: InitializeAsync ve SignInAsync [MethodImpl(NoInlining)] olduğu
// için JIT'in native code pointer'ları sabittir.
// Bu pointer'ların başına JMP yazarak stub static metodlara yönlendiriyoruz.
//
// Stub metodlar STATIC olmalı ve [MethodImpl(NoInlining)] ile işaretlenmeli.
// x64 calling convention: instance method'da RCX=this, RDX=arg1, ...
// Static method'da                              RCX=arg1, RDX=arg2, ...
// Stub'a jump edilince RCX=this (Dhr= instance) gelir — onu yok sayıyoruz.
//
// Stub return tipi: stub object döndürür ama aslında Task<T> nesnesinin
// pointer'ını RAX'a koyar. CLR caller castclass yapar, bu çalışır.
// ---------------------------------------------------------------------------
internal static unsafe class AuthBypass
{
    private static int _patched;
    private static int _endpointGetterLogged;
    private static int _apiKeysGetterLogged;
    private static int _currentLicenseGetterLogged;
    private static string _apiEndpoint = "https://pixeldrain.com/api";
    private static string[] _apiKeys = Array.Empty<string>();
    private static string _currentLicense = "RIKA-0000-0000-0000";
    private const string DefaultApiKeyBundle =
        "4640b1ae-5ceb-4e9e-a0f1-ece21fb06865|59a034ea-b784-49bb-a935-61e5d8aea8c6";

    // Tipleri statik alanlarda tut — GC koruma + hızlı erişim
    internal static Type? BootstrapStateType;
    internal static Type? AuthResultType;

    internal static void TryPatch(Assembly rikaAssembly)
    {
        if (System.Threading.Interlocked.Exchange(ref _patched, 1) != 0)
            return;

        try
        {
            ProxyLog.Write("[AuthBypass] RikaNET.WinUI yüklendi, patch başlıyor...");
            PatchMethods(rikaAssembly);
        }
        catch (Exception ex)
        {
            ProxyLog.Write("[AuthBypass] HATA: " + ex);
        }
    }

    private static void PatchMethods(Assembly asm)
    {
        // IAuthenticationService implementörünü bul
        Type? dhrType = FindAuthServiceImpl(asm);

        if (dhrType == null)
        {
            ProxyLog.Write("[AuthBypass] IAuthenticationService impl bulunamadı.");
            return;
        }

        ProxyLog.Write("[AuthBypass] Hedef tip: " + dhrType.FullName);

        // Tip referanslarını statik alanlara kaydet — stub metodlar buradan okur
        BootstrapStateType = FindTypeInLoadedAssemblies("AuthBootstrapState");
        AuthResultType = FindTypeInLoadedAssemblies("AuthResult");

        if (BootstrapStateType == null || AuthResultType == null)
        {
            ProxyLog.Write("[AuthBypass] Model tipleri bulunamadı: bootstrapState="
                + (BootstrapStateType?.FullName ?? "null")
                + " authResult=" + (AuthResultType?.FullName ?? "null"));
            return;
        }

        ProxyLog.Write("[AuthBypass] AuthBootstrapState: " + BootstrapStateType.FullName);
        ProxyLog.Write("[AuthBypass] AuthResult: " + AuthResultType.FullName);

        // IAuthenticationService interface tipini bul
        Type? ifaceType = dhrType.GetInterfaces()
            .FirstOrDefault(i => i.Name.Contains("IAuthenticationService"));

        if (ifaceType == null)
        {
            ProxyLog.Write("[AuthBypass] IAuthenticationService interface tipi bulunamadı.");
            return;
        }

        ProxyLog.Write("[AuthBypass] Interface tipi: " + ifaceType.FullName);

        // Stub metodları hazırla ve JIT'e derlet
        MethodInfo stubInit = typeof(AuthBypass).GetMethod(
            nameof(InitStub), BindingFlags.Static | BindingFlags.NonPublic)!;
        MethodInfo stubSignIn = typeof(AuthBypass).GetMethod(
            nameof(SignInStub), BindingFlags.Static | BindingFlags.NonPublic)!;
        MethodInfo stubCurrentLicense = typeof(AuthBypass).GetMethod(
            nameof(CurrentLicenseGetterStub), BindingFlags.Static | BindingFlags.NonPublic)!;

        RuntimeHelpers.PrepareMethod(stubInit.MethodHandle);
        RuntimeHelpers.PrepareMethod(stubSignIn.MethodHandle);
        RuntimeHelpers.PrepareMethod(stubCurrentLicense.MethodHandle);

        nint initPtr   = stubInit.MethodHandle.GetFunctionPointer();
        nint signInPtr = stubSignIn.MethodHandle.GetFunctionPointer();
        nint currentLicensePtr = stubCurrentLicense.MethodHandle.GetFunctionPointer();

        ProxyLog.Write($"[VTable] stubInit=0x{initPtr:X16} stubSignIn=0x{signInPtr:X16} "
            + $"stubCurrentLicense=0x{currentLicensePtr:X16}");

        // -----------------------------------------------------------------------
        // .NET 8 x64 MethodTable layout (coreclr/vm/methodtable.h):
        //   +0x00 DWORD  m_dwFlags
        //   +0x04 DWORD  m_BaseSize
        //   +0x08 WORD   m_wFlags2
        //   +0x0A WORD   m_wToken
        //   +0x0C WORD   m_wNumVirtuals
        //   +0x0E WORD   m_wNumInterfaces
        //   +0x10 PTR    m_pParentMethodTable
        //   +0x18 PTR    m_pLoaderModule
        //   +0x20 PTR    m_pWriteableData
        //   +0x28 PTR    m_pEEClass / m_pCanonMT
        //   +0x30 PTR    m_pPerInstInfo
        //   +0x38 PTR    m_pInterfaceMap
        //   +0x40        vtable slots başlar (her biri 8 byte, x64)
        //
        // InterfaceInfo_t (her biri 16 byte, x64):
        //   +0x00 PTR    m_pMethodTable  (8 byte)
        //   +0x08 WORD   m_wStartSlot    (2 byte, +6 byte pad)
        // -----------------------------------------------------------------------

        nint mt            = dhrType.TypeHandle.Value;
        ushort numVirtuals = *(ushort*)(mt + 0x0C);
        ushort numIfaces   = *(ushort*)(mt + 0x0E);
        nint ifaceMapPtr   = *(nint*)(mt + 0x38);
        nint ifaceMT       = ifaceType.TypeHandle.Value;

        ProxyLog.Write($"[VTable] mt=0x{mt:X16} numVirtuals={numVirtuals} numIfaces={numIfaces}");
        ProxyLog.Write($"[VTable] ifaceMapPtr=0x{ifaceMapPtr:X16} ifaceMT=0x{ifaceMT:X16}");

        // InterfaceInfo_t dizisinde IAuthenticationService'i bul → startSlot
        const int kInfoSize = 16; // sizeof(InterfaceInfo_t) on x64
        ushort startSlot = ushort.MaxValue;

        for (int i = 0; i < numIfaces; i++)
        {
            nint  entryMT   = *(nint*) (ifaceMapPtr + i * kInfoSize);
            ushort entrySlot = *(ushort*)(ifaceMapPtr + i * kInfoSize + 8);
            ProxyLog.Write($"[VTable] IfaceMap[{i}] mt=0x{entryMT:X16} startSlot={entrySlot}");

            if (entryMT == ifaceMT)
                startSlot = entrySlot;
        }

        if (startSlot == ushort.MaxValue)
        {
            ProxyLog.Write("[VTable] IAuthenticationService InterfaceInfo girişi bulunamadı.");
            return;
        }

        ProxyLog.Write($"[VTable] IAuthenticationService startSlot={startSlot}");

        // GetInterfaceMap → InterfaceMethods[i] dizisi interface slot sırasını verir.
        // Vtable'daki interface slot adresi: mt + 0x40 + (startSlot + i) * 8
        InterfaceMapping mapping = dhrType.GetInterfaceMap(ifaceType);

        const int kVTableBase = 0x40; // sizeof(MethodTable header) on .NET 8 x64

        for (int i = 0; i < mapping.InterfaceMethods.Length; i++)
        {
            MethodInfo ifaceMethod = mapping.InterfaceMethods[i];
            nint slotAddr = mt + kVTableBase + (startSlot + i) * 8;
            nint currentVal = *(nint*)slotAddr;

            ProxyLog.Write($"[VTable] slot[{startSlot + i}] method={ifaceMethod.Name} "
                + $"addr=0x{slotAddr:X16} current=0x{currentVal:X16}");

            nint stubPtr = 0;
            if (ifaceMethod.Name == "InitializeAsync")
                stubPtr = initPtr;
            else if (ifaceMethod.Name == "SignInAsync")
                stubPtr = signInPtr;
            else if (ifaceMethod.Name.IndexOf("CurrentLicense", StringComparison.OrdinalIgnoreCase) >= 0)
                stubPtr = currentLicensePtr;

            if (stubPtr == 0)
            {
                ProxyLog.Write($"[VTable] {ifaceMethod.Name} için stub yok, atlanıyor.");
                continue;
            }

            MakeWritable(slotAddr, 8);
            *(nint*)slotAddr = stubPtr;
            ProxyLog.Write($"[VTable] {ifaceMethod.Name} vtable slot patch'lendi → 0x{stubPtr:X16} ✓");
        }

        // -----------------------------------------------------------------------
        // JIT Prolog Patch — vtable patch'e ek güvence
        // VSD önbelleği vtable slot'u yoksaysa bile bu patch her zaman çalışır.
        // Trampoline: 48 B8 [8-byte LE stub adresi] FF E0
        //   MOV RAX, imm64   (10 byte)
        //   JMP RAX          (2 byte)
        // -----------------------------------------------------------------------
        ProxyLog.Write("[JIT] Prolog patch başlıyor...");

        var implPatchTargets = new (string Name, nint StubPtr)[]
        {
            ("InitializeAsync", initPtr),
            ("SignInAsync",     signInPtr),
            ("get_FJp_003D",     currentLicensePtr),
            ("get_FJp=",         currentLicensePtr),
            ("get_CurrentLicense", currentLicensePtr),
        };

        foreach (var (mname, stubPtr) in implPatchTargets)
        {
            MethodInfo? implMethod = dhrType
                .GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
                .FirstOrDefault(m => m.Name == mname);

            if (implMethod == null)
            {
                ProxyLog.Write($"[JIT] {mname} impl metodu bulunamadı, atlanıyor.");
                continue;
            }

            try
            {
                RuntimeHelpers.PrepareMethod(implMethod.MethodHandle);
                nint precode   = implMethod.MethodHandle.GetFunctionPointer();
                nint targetPtr = ResolveRealAddr(precode);

                ProxyLog.Write($"[JIT] {mname} precode=0x{precode:X16} real=0x{targetPtr:X16}");

                // 48 B8 [8-byte LE addr] FF E0
                byte[] trampoline = new byte[12];
                trampoline[0] = 0x48; // MOV RAX, imm64 — REX.W prefix
                trampoline[1] = 0xB8; // opcode
                long addr = (long)(ulong)stubPtr;
                for (int b = 0; b < 8; b++)
                    trampoline[2 + b] = (byte)(addr >> (b * 8));
                trampoline[10] = 0xFF; // JMP RAX
                trampoline[11] = 0xE0;

                MakeWritable(targetPtr, 12);
                Marshal.Copy(trampoline, 0, targetPtr, 12);

                ProxyLog.Write($"[JIT] {mname} prolog patch'lendi → 0x{stubPtr:X16} ✓");
            }
            catch (Exception ex)
            {
                ProxyLog.Write($"[JIT] {mname} prolog patch HATA: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // -----------------------------------------------------------------------
        // Statik helper metodlarını patch'le
        // LoginViewModel'deki state machine statik helper'ları doğrudan CALL
        // kullanır — VSD bypass'ı tamamen atlatır.
        // -----------------------------------------------------------------------
        PatchStaticHelpers(asm);

        // Protection flow reads this config through Dhr/wgc accessors. In proxy
        // tests those values can remain empty even after auth is stubbed.
        PatchApiBootstrap(asm);
    }

    // -----------------------------------------------------------------------
    // Stub metodlar — [MethodImpl(NoInlining)] ZORUNLU, yoksa JIT inline eder
    // ve pointer değişebilir.
    //
    // InitializeAsync imzası: (Dhr= this, CancellationToken ct) -> Task<AuthBootstrapState>
    // x64'te:  RCX=this, RDX=ct  → stub'a jump gelince RCX'te this var, onu yok sayıyoruz
    // Stub static olduğu için:   RCX=this(ignored), RDX=ct(ignored)
    // -----------------------------------------------------------------------
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static object InitStub(object self, CancellationToken ct)
    {
        try
        {
            ProxyLog.Write("[AuthBypass] InitializeAsync stub çağrıldı ✓");
            var type = BootstrapStateType;
            if (type == null) return Task.CompletedTask;
            var state = Activator.CreateInstance(type)!;
            string license = GetConfiguredLicense();
            TrySet(state, type, "IsReady", true);
            TrySet(state, type, "CachedLicense", license);
            TrySet(state, type, "RequiresUpdate", false);
            TrySet(state, type, "Message", "");
            TrySet(state, type, "DownloadUrl", "");
            return MakeTask(type, state);
        }
        catch (Exception ex)
        {
            ProxyLog.Write("[AuthBypass] InitStub hata: " + ex.Message);
            return Task.CompletedTask;
        }
    }

    // SignInAsync imzası: (Dhr= this, string license, bool rememberMe, CancellationToken ct) -> Task<AuthResult>
    // x64'te: RCX=this, RDX=license, R8=rememberMe, R9=ct
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static object SignInStub(object self, string license, bool rememberMe, CancellationToken ct)
    {
        try
        {
            ProxyLog.Write("[AuthBypass] SignInAsync stub çağrıldı ✓ license=" + (license ?? "(null)"));
            _currentLicense = GetConfiguredLicense(license);
            var type = AuthResultType;
            if (type == null) return Task.CompletedTask;
            var result = Activator.CreateInstance(type)!;
            TrySet(result, type, "IsSuccess", true);
            TrySet(result, type, "License", _currentLicense);
            TrySet(result, type, "LicenseKey", _currentLicense);
            TrySet(result, type, "CurrentLicense", _currentLicense);
            TrySet(result, type, "RemainingDays", 9999);
            TrySet(result, type, "PlanType", "Enterprise");
            TrySet(result, type, "ErrorMessage", (string?)null);
            return MakeTask(type, result);
        }
        catch (Exception ex)
        {
            ProxyLog.Write("[AuthBypass] SignInStub hata: " + ex.Message);
            return Task.CompletedTask;
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string CurrentLicenseGetterStub(object self)
    {
        string license = GetConfiguredLicense();
        if (Interlocked.Exchange(ref _currentLicenseGetterLogged, 1) == 0)
            ProxyLog.Write("[AuthBypass] CurrentLicense getter stub -> len=" + license.Length);
        return license;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(nint lpAddress, nuint dwSize, uint flNewProtect, out uint lpflOldProtect);

    internal static void MakeWritable(nint address, int size)
    {
        VirtualProtect(address, (nuint)size, 0x40 /* PAGE_EXECUTE_READWRITE */, out _);
    }

    // -----------------------------------------------------------------------
    // Yardımcı metodlar
    // -----------------------------------------------------------------------

    internal static object MakeTask(Type resultType, object value)
    {
        return typeof(Task)
            .GetMethod("FromResult")!
            .MakeGenericMethod(resultType)
            .Invoke(null, new[] { value })!;
    }

    internal static void TrySet(object instance, Type type, string name, object? value)
    {
        // 1) C# 9 init-only property'lerin backing field'ını doğrudan dene.
        //    prop.CanWrite init-only için true döner ama SetValue çalışma zamanında
        //    InvalidOperationException fırlatır; catch sessizce yutar ve field
        //    fallback'e hiç ulaşılmaz.  Backing field'ı önce deneyerek bunu atlatıyoruz.
        var backingField = type.GetField(
            $"<{name}>k__BackingField",
            BindingFlags.Instance | BindingFlags.NonPublic);
        if (backingField != null)
        {
            try { backingField.SetValue(instance, value); return; } catch { }
        }

        // 2) Normal yazılabilir property (init-only olmayan setter).
        try
        {
            var prop = type.GetProperty(name,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (prop?.CanWrite == true)
            {
                prop.SetValue(instance, value);
                return;
            }

            // 3) İsim içeren herhangi bir field (son çare).
            var field = type.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
                .FirstOrDefault(f => f.Name.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0);
            field?.SetValue(instance, value);
        }
        catch { }
    }

    private static Type? FindTypeInLoadedAssemblies(string simpleName)
    {
        foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
        {
            try
            {
                var t = asm.GetTypes().FirstOrDefault(x =>
                    string.Equals(x.Name, simpleName, StringComparison.OrdinalIgnoreCase));
                if (t != null) return t;
            }
            catch { }
        }
        return null;
    }

    private static Type? FindAuthServiceImpl(Assembly asm)
    {
        try
        {
            return asm.GetTypes().FirstOrDefault(t =>
                t.IsClass && !t.IsAbstract &&
                t.GetInterfaces().Any(i => i.Name.Contains("IAuthenticationService")));
        }
        catch { return null; }
    }

    private static Type[] GetLoadableTypes(Assembly asm)
    {
        try
        {
            return asm.GetTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            return ex.Types.Where(t => t != null).Cast<Type>().ToArray();
        }
        catch
        {
            return Array.Empty<Type>();
        }
    }

    // -----------------------------------------------------------------------
    // ResolveRealAddr — precode'daki JMP zincirini takip ederek gerçek
    // derlenmiş metod adresini döner.
    // Desteklenen opcode'lar:
    //   0xE9          → rel32 JMP
    //   0xEB          → rel8 short JMP
    //   0xFF 0x25     → JMP QWORD PTR [RIP+disp32]  (indirect)
    //   0x48 0xFF 0x25→ REX.W + JMP indirect (nadiren)
    // -----------------------------------------------------------------------
    internal static nint ResolveRealAddr(nint addr)
    {
        const int MaxHops = 8;
        for (int hop = 0; hop < MaxHops; hop++)
        {
            byte b0 = *(byte*)addr;

            if (b0 == 0xE9) // rel32 JMP
            {
                nint next = addr + 5 + *(int*)(addr + 1);
                ProxyLog.Write($"[Resolve] hop={hop} E9 0x{addr:X16} → 0x{next:X16}");
                addr = next;
                continue;
            }
            if (b0 == 0xEB) // rel8 short JMP
            {
                nint next = addr + 2 + *(sbyte*)(addr + 1);
                ProxyLog.Write($"[Resolve] hop={hop} EB 0x{addr:X16} → 0x{next:X16}");
                addr = next;
                continue;
            }
            if (b0 == 0xFF && *(byte*)(addr + 1) == 0x25) // JMP [RIP+disp32]
            {
                nint ripBase = addr + 6;
                nint slot   = ripBase + *(int*)(addr + 2);
                nint next   = *(nint*)slot;
                ProxyLog.Write($"[Resolve] hop={hop} FF25 0x{addr:X16} → slot=0x{slot:X16} → 0x{next:X16}");
                addr = next;
                continue;
            }
            // REX.W prefix (0x48) + FF 25
            if (b0 == 0x48 && *(byte*)(addr + 1) == 0xFF && *(byte*)(addr + 2) == 0x25)
            {
                nint ripBase = addr + 7;
                nint slot   = ripBase + *(int*)(addr + 3);
                nint next   = *(nint*)slot;
                ProxyLog.Write($"[Resolve] hop={hop} 48FF25 0x{addr:X16} → slot=0x{slot:X16} → 0x{next:X16}");
                addr = next;
                continue;
            }
            // Başka opcode — gerçek kod başlangıcındayız
            break;
        }
        return addr;
    }

    // -----------------------------------------------------------------------
    // InitHelperStub — statik InitializeAsync helper'ının yerini alır.
    // İmza: (IAuthenticationService, CancellationToken) → Task<AuthBootstrapState>
    // -----------------------------------------------------------------------
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static object InitHelperStub(object authService, CancellationToken ct)
    {
        ProxyLog.Write("[InitHelperStub] CALLED — returning fake AuthBootstrapState");
        try
        {
            // AuthBootstrapState tipini bul
            Type? bsType = FindTypeInLoadedAssemblies("AuthBootstrapState");
            if (bsType == null)
            {
                ProxyLog.Write("[InitHelperStub] AuthBootstrapState type NOT found — returning null task");
                return Task.FromResult<object?>(null)!;
            }

            // Enum ise "Licensed" veya index=1 değerini dön
            object bsValue;
            if (bsType.IsEnum)
            {
                string[] names = Enum.GetNames(bsType);
                ProxyLog.Write($"[InitHelperStub] AuthBootstrapState enum names: {string.Join(", ", names)}");
                // Önce "Licensed" ara, yoksa ilk değeri al
                string? licensedName = names.FirstOrDefault(n =>
                    n.IndexOf("Licensed", StringComparison.OrdinalIgnoreCase) >= 0
                    || n.IndexOf("Success", StringComparison.OrdinalIgnoreCase) >= 0
                    || n.IndexOf("Valid", StringComparison.OrdinalIgnoreCase) >= 0);
                bsValue = Enum.Parse(bsType, licensedName ?? names[0]);
                ProxyLog.Write($"[InitHelperStub] Using enum value: {bsValue}");
            }
            else
            {
                bsValue = Activator.CreateInstance(bsType)!;
                ProxyLog.Write($"[InitHelperStub] Created default AuthBootstrapState instance");
            }

            return MakeTask(bsType, bsValue);
        }
        catch (Exception ex)
        {
            ProxyLog.Write($"[InitHelperStub] EXCEPTION: {ex}");
            return Task.CompletedTask;
        }
    }

    // -----------------------------------------------------------------------
    // SignInHelperStub — statik SignInAsync helper'ının yerini alır.
    // İmza: (IAuthenticationService, string, CancellationToken) → Task<AuthResult>
    // -----------------------------------------------------------------------
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static object SignInHelperStub(object authService, string license, CancellationToken ct)
    {
        ProxyLog.Write($"[SignInHelperStub] CALLED license={license ?? "<null>"} — returning fake AuthResult");
        try
        {
            Type? resultType = FindTypeInLoadedAssemblies("AuthResult");
            if (resultType == null)
            {
                ProxyLog.Write("[SignInHelperStub] AuthResult type NOT found");
                return Task.FromResult<object?>(null)!;
            }

            object result = Activator.CreateInstance(resultType)!;
            _currentLicense = GetConfiguredLicense(license);
            // IsSuccess / Success alanını true yap
            TrySet(result, resultType, "IsSuccess", true);
            TrySet(result, resultType, "Success",   true);
            TrySet(result, resultType, "Succeeded", true);
            TrySet(result, resultType, "License", _currentLicense);
            TrySet(result, resultType, "LicenseKey", _currentLicense);
            TrySet(result, resultType, "CurrentLicense", _currentLicense);
            ProxyLog.Write($"[SignInHelperStub] AuthResult instance built: {resultType.FullName}");

            return MakeTask(resultType, result);
        }
        catch (Exception ex)
        {
            ProxyLog.Write($"[SignInHelperStub] EXCEPTION: {ex}");
            return Task.CompletedTask;
        }
    }

    // -----------------------------------------------------------------------
    // PatchStaticHelpers — LoginViewModel nested struct'larındaki iki obfüskelenmiş
    // statik helper metodunu bulur ve JIT prolog'larını stub'lara yönlendirir.
    //
    // Hedef metodlar (LoginViewModel.cs'den doğrulandı):
    //   _003C_0025_0021_002D_003F_002F_0026_0021(IAuthenticationService, CancellationToken)
    //   _0023_002B_005E_0026_005E_0040_002B_005E(IAuthenticationService, string, CancellationToken)
    // -----------------------------------------------------------------------
    private static void PatchStaticHelpers(Assembly winUiAsm)
    {
        ProxyLog.Write("[PatchStaticHelpers] Searching for obfuscated static helper methods...");

        const string InitHelperName   = "_003C_0025_0021_002D_003F_002F_0026_0021";
        const string SignInHelperName = "_0023_002B_005E_0026_005E_0040_002B_005E";

        MethodInfo? initTarget   = null;
        MethodInfo? signInTarget = null;

        try
        {
            foreach (Type t in winUiAsm.GetTypes())
            {
                if (initTarget != null && signInTarget != null) break;
                try
                {
                    foreach (MethodInfo mi in t.GetMethods(
                        BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
                    {
                        if (mi.Name == InitHelperName && initTarget == null)
                        {
                            var pms = mi.GetParameters();
                            // 2 parametre: IAuthenticationService + CancellationToken
                            if (pms.Length == 2)
                            {
                                initTarget = mi;
                                ProxyLog.Write($"[PatchStaticHelpers] Found init helper: {t.FullName}::{mi.Name}");
                            }
                        }
                        if (mi.Name == SignInHelperName && signInTarget == null)
                        {
                            var pms = mi.GetParameters();
                            // 3 parametre: IAuthenticationService + string + CancellationToken
                            if (pms.Length == 3)
                            {
                                signInTarget = mi;
                                ProxyLog.Write($"[PatchStaticHelpers] Found signIn helper: {t.FullName}::{mi.Name}");
                            }
                        }
                        if (initTarget != null && signInTarget != null) break;
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            ProxyLog.Write($"[PatchStaticHelpers] GetTypes error: {ex.Message}");
        }

        if (initTarget == null)
            ProxyLog.Write($"[PatchStaticHelpers] WARNING: init helper NOT found ({InitHelperName})");
        if (signInTarget == null)
            ProxyLog.Write($"[PatchStaticHelpers] WARNING: signIn helper NOT found ({SignInHelperName})");

        // Stub metodlarını hazırla
        MethodInfo initStub   = typeof(AuthBypass).GetMethod(nameof(InitHelperStub),
            BindingFlags.Static | BindingFlags.NonPublic)!;
        MethodInfo signInStub = typeof(AuthBypass).GetMethod(nameof(SignInHelperStub),
            BindingFlags.Static | BindingFlags.NonPublic)!;

        PatchOneStaticHelper(initTarget,   initStub,   "InitHelper");
        PatchOneStaticHelper(signInTarget, signInStub, "SignInHelper");
    }

    private static void PatchApiBootstrap(Assembly winUiAsm)
    {
        ProxyLog.Write("[ApiBootstrap] Searching for Endpoint/ApiKeys accessors...");

        Type? authImplType = FindAuthServiceImpl(winUiAsm);
        if (authImplType == null)
        {
            ProxyLog.Write("[ApiBootstrap] Authentication implementation not found.");
            return;
        }

        MethodInfo endpointGetterStub = typeof(AuthBypass).GetMethod(nameof(ApiEndpointGetterStub),
            BindingFlags.Static | BindingFlags.NonPublic)!;
        MethodInfo endpointSetterStub = typeof(AuthBypass).GetMethod(nameof(ApiEndpointSetterStub),
            BindingFlags.Static | BindingFlags.NonPublic)!;
        MethodInfo apiKeysGetterStub = typeof(AuthBypass).GetMethod(nameof(ApiKeysGetterStub),
            BindingFlags.Static | BindingFlags.NonPublic)!;
        MethodInfo apiKeysSetterStub = typeof(AuthBypass).GetMethod(nameof(ApiKeysSetterStub),
            BindingFlags.Static | BindingFlags.NonPublic)!;
        MethodInfo currentLicenseGetterStub = typeof(AuthBypass).GetMethod(nameof(CurrentLicenseGetterStub),
            BindingFlags.Static | BindingFlags.NonPublic)!;

        int patched = 0;
        foreach (Type type in GetLoadableTypes(winUiAsm))
        {
            if (type != authImplType)
                continue;

            MethodInfo[] methods;
            try
            {
                methods = type.GetMethods(BindingFlags.Instance | BindingFlags.Public |
                    BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
            }
            catch
            {
                continue;
            }

            foreach (MethodInfo method in methods)
            {
                if (method.IsAbstract || method.ContainsGenericParameters)
                    continue;

                if (IsEndpointGetter(method))
                {
                    PatchOneStaticHelper(method, endpointGetterStub,
                        "ApiBootstrap:" + type.Name + "." + method.Name);
                    patched++;
                }
                else if (IsEndpointSetter(method))
                {
                    PatchOneStaticHelper(method, endpointSetterStub,
                        "ApiBootstrap:" + type.Name + "." + method.Name);
                    patched++;
                }
                else if (IsApiKeysGetter(method))
                {
                    PatchOneStaticHelper(method, apiKeysGetterStub,
                        "ApiBootstrap:" + type.Name + "." + method.Name);
                    patched++;
                }
                else if (IsApiKeysSetter(method))
                {
                    PatchOneStaticHelper(method, apiKeysSetterStub,
                        "ApiBootstrap:" + type.Name + "." + method.Name);
                    patched++;
                }
                else if (IsCurrentLicenseGetter(method))
                {
                    PatchOneStaticHelper(method, currentLicenseGetterStub,
                        "ApiBootstrap:" + type.Name + "." + method.Name);
                    patched++;
                }
            }
        }

        ProxyLog.Write("[ApiBootstrap] Accessor patch count: " + patched);
    }

    private static bool IsEndpointGetter(MethodInfo method)
    {
        return method.ReturnType == typeof(string) &&
               method.GetParameters().Length == 0 &&
               NameLooksLikeEndpoint(method.Name);
    }

    private static bool IsEndpointSetter(MethodInfo method)
    {
        var parameters = method.GetParameters();
        return method.ReturnType == typeof(void) &&
               parameters.Length == 1 &&
               parameters[0].ParameterType == typeof(string) &&
               NameLooksLikeEndpoint(method.Name);
    }

    private static bool IsApiKeysGetter(MethodInfo method)
    {
        return method.ReturnType == typeof(string[]) &&
               method.GetParameters().Length == 0 &&
               NameLooksLikeApiKeys(method.Name);
    }

    private static bool IsApiKeysSetter(MethodInfo method)
    {
        var parameters = method.GetParameters();
        return method.ReturnType == typeof(void) &&
               parameters.Length == 1 &&
               parameters[0].ParameterType == typeof(string[]) &&
               NameLooksLikeApiKeys(method.Name);
    }

    private static bool IsCurrentLicenseGetter(MethodInfo method)
    {
        return method.ReturnType == typeof(string) &&
               method.GetParameters().Length == 0 &&
               NameLooksLikeCurrentLicense(method.Name);
    }

    private static bool NameLooksLikeEndpoint(string name)
    {
        return name.IndexOf("Endpoint", StringComparison.OrdinalIgnoreCase) >= 0 ||
               name.IndexOf("ILZ_003D", StringComparison.OrdinalIgnoreCase) >= 0 ||
               name.IndexOf("ILZ=", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static bool NameLooksLikeApiKeys(string name)
    {
        return name.IndexOf("ApiKeys", StringComparison.OrdinalIgnoreCase) >= 0 ||
               name.IndexOf("yVP_003D", StringComparison.OrdinalIgnoreCase) >= 0 ||
               name.IndexOf("yVP=", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static bool NameLooksLikeCurrentLicense(string name)
    {
        return name.IndexOf("CurrentLicense", StringComparison.OrdinalIgnoreCase) >= 0 ||
               name.IndexOf("FJp_003D", StringComparison.OrdinalIgnoreCase) >= 0 ||
               name.IndexOf("FJp=", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string ApiEndpointGetterStub(object self)
    {
        string endpoint = GetConfiguredEndpoint(self, out string source);
        if (Interlocked.Exchange(ref _endpointGetterLogged, 1) == 0)
            ProxyLog.Write("[ApiBootstrap] Endpoint getter stub -> " + endpoint + " source=" + source);
        return endpoint;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ApiEndpointSetterStub(object self, string value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            _apiEndpoint = value.Trim();
            ProxyLog.Write("[ApiBootstrap] Endpoint setter captured -> " + _apiEndpoint);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string[] ApiKeysGetterStub(object self)
    {
        string[] keys = GetConfiguredApiKeys(self, out string source);
        if (Interlocked.Exchange(ref _apiKeysGetterLogged, 1) == 0)
            ProxyLog.Write("[ApiBootstrap] ApiKeys getter stub -> count=" + keys.Length
                + " source=" + source + " " + DescribeKeys(keys));
        return keys;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ApiKeysSetterStub(object self, string[] value)
    {
        string[] cleaned = CleanApiKeys(value);
        if (cleaned.Length > 0)
        {
            _apiKeys = cleaned;
            ProxyLog.Write("[ApiBootstrap] ApiKeys setter captured -> count=" + cleaned.Length);
        }
    }

    private static string GetConfiguredEndpoint(object? self, out string source)
    {
        string? env = Environment.GetEnvironmentVariable("RIKA_PROXY_ENDPOINT");
        if (!string.IsNullOrWhiteSpace(env))
        {
            source = "env";
            return env.Trim();
        }

        string? fromInstance = TryReadEndpointFromInstance(self);
        if (!string.IsNullOrWhiteSpace(fromInstance))
        {
            _apiEndpoint = fromInstance.Trim();
            source = "instance-field";
            return _apiEndpoint;
        }

        source = "default";
        return _apiEndpoint;
    }

    private static string[] GetConfiguredApiKeys(object? self, out string source)
    {
        string? env = Environment.GetEnvironmentVariable("RIKA_PROXY_API_KEYS");
        if (!string.IsNullOrWhiteSpace(env))
        {
            string[] fromEnv = CleanApiKeyText(env);
            if (fromEnv.Length > 0)
            {
                source = "env";
                return fromEnv;
            }
        }

        string[] fromRikaTxt = TryReadApiKeysFromRikaTxt(out string fileSource);
        if (fromRikaTxt.Length > 0)
        {
            _apiKeys = fromRikaTxt;
            source = fileSource;
            return fromRikaTxt;
        }

        string[] fromInstance = TryReadApiKeysFromInstance(self);
        if (fromInstance.Length > 0)
        {
            _apiKeys = fromInstance;
            source = "instance-field";
            return fromInstance;
        }

        string[] keys = CleanApiKeys(_apiKeys);
        if (keys.Length > 0)
        {
            source = "captured-setter";
            return keys;
        }

        source = "hardcoded-real";
        return CleanApiKeyText(DefaultApiKeyBundle);
    }

    private static string[] TryReadApiKeysFromRikaTxt(out string source)
    {
        source = "rika.txt";

        string? envPath = Environment.GetEnvironmentVariable("RIKA_PROXY_API_KEYS_FILE");
        string[] candidates = new[]
        {
            envPath,
            Path.Combine(AppContext.BaseDirectory, "rika.txt"),
            Path.Combine(Path.GetDirectoryName(typeof(ProxyBootstrap).Assembly.Location) ?? "", "rika.txt"),
            Path.Combine(Directory.GetCurrentDirectory(), "rika.txt")
        }
        .Where(path => !string.IsNullOrWhiteSpace(path))
        .Select(path => Path.GetFullPath(path!))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

        foreach (string path in candidates)
        {
            try
            {
                if (!File.Exists(path))
                    continue;

                string[] keys = CleanApiKeyText(File.ReadAllText(path));
                if (keys.Length > 0)
                {
                    source = "rika.txt";
                    return keys;
                }
            }
            catch (Exception ex)
            {
                ProxyLog.Write("[ApiBootstrap] rika.txt read failed: "
                    + Path.GetFileName(path) + " -> " + ex.GetType().Name + ": " + ex.Message);
            }
        }

        return Array.Empty<string>();
    }

    internal static string GetConfiguredLicense(string? preferred = null)
    {
        string? env = Environment.GetEnvironmentVariable("RIKA_PROXY_LICENSE");
        if (!string.IsNullOrWhiteSpace(env))
            return env.Trim();

        string[] candidates = new[]
        {
            Environment.GetEnvironmentVariable("RIKA_PROXY_LICENSE_FILE"),
            Path.Combine(AppContext.BaseDirectory, "rika_license.txt"),
            Path.Combine(Path.GetDirectoryName(typeof(ProxyBootstrap).Assembly.Location) ?? "", "rika_license.txt"),
            Path.Combine(AppContext.BaseDirectory, "license.txt"),
            Path.Combine(Path.GetDirectoryName(typeof(ProxyBootstrap).Assembly.Location) ?? "", "license.txt")
        }
        .Where(path => !string.IsNullOrWhiteSpace(path))
        .Select(path => Path.GetFullPath(path!))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

        foreach (string path in candidates)
        {
            try
            {
                if (!File.Exists(path))
                    continue;

                string value = File.ReadAllText(path).Trim();
                if (!string.IsNullOrWhiteSpace(value))
                    return value;
            }
            catch (Exception ex)
            {
                ProxyLog.Write("[AuthBypass] license file read failed: "
                    + Path.GetFileName(path) + " -> " + ex.GetType().Name + ": " + ex.Message);
            }
        }

        if (!string.IsNullOrWhiteSpace(preferred))
            return preferred.Trim();

        if (!string.IsNullOrWhiteSpace(_currentLicense))
            return _currentLicense.Trim();

        return "RIKA-0000-0000-0000";
    }

    private static string? TryReadEndpointFromInstance(object? self)
    {
        object[] candidates = EnumerateConfigCandidates(self);
        foreach (object candidate in candidates)
        {
            string? value = ReadBestStringField(candidate, value => LooksLikeEndpointValue(value));
            if (!string.IsNullOrWhiteSpace(value))
                return value;
        }

        foreach (object candidate in candidates.Skip(1))
        {
            string? value = ReadBestStringProperty(candidate, value => LooksLikeEndpointValue(value));
            if (!string.IsNullOrWhiteSpace(value))
                return value;
        }

        return null;
    }

    private static string[] TryReadApiKeysFromInstance(object? self)
    {
        object[] candidates = EnumerateConfigCandidates(self);
        foreach (object candidate in candidates)
        {
            string[] keys = ReadBestStringArrayField(candidate);
            if (keys.Length > 0)
                return keys;
        }

        foreach (object candidate in candidates.Skip(1))
        {
            string[] keys = ReadBestStringArrayProperty(candidate);
            if (keys.Length > 0)
                return keys;
        }

        return Array.Empty<string>();
    }

    private static object[] EnumerateConfigCandidates(object? self)
    {
        if (self == null)
            return Array.Empty<object>();

        object?[] candidates = new object?[8];
        int count = 0;
        candidates[count++] = self;

        foreach (FieldInfo field in self.GetType().GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
        {
            if (count >= candidates.Length)
                break;

            object? value = null;
            try { value = field.GetValue(self); }
            catch { }

            if (value == null || value is string || value.GetType().IsValueType)
                continue;

            string typeName = value.GetType().Name;
            if (typeName.IndexOf("wgc", StringComparison.OrdinalIgnoreCase) >= 0 ||
                field.Name.IndexOf("yGp", StringComparison.OrdinalIgnoreCase) >= 0)
                candidates[count++] = value;
        }

        return candidates.Take(count).Where(candidate => candidate != null).Cast<object>().ToArray();
    }

    private static string? ReadBestStringField(object instance, Func<string, bool> predicate)
    {
        foreach (FieldInfo field in instance.GetType().GetFields(BindingFlags.Instance | BindingFlags.Static |
                     BindingFlags.Public | BindingFlags.NonPublic))
        {
            if (field.FieldType != typeof(string))
                continue;

            object? raw = null;
            try { raw = field.GetValue(field.IsStatic ? null : instance); }
            catch { }

            if (raw is string value && predicate(value))
                return value.Trim();
        }

        return null;
    }

    private static string? ReadBestStringProperty(object instance, Func<string, bool> predicate)
    {
        foreach (PropertyInfo property in instance.GetType().GetProperties(BindingFlags.Instance |
                     BindingFlags.Public | BindingFlags.NonPublic))
        {
            if (property.PropertyType != typeof(string) || property.GetIndexParameters().Length != 0)
                continue;

            object? raw = null;
            try { raw = property.GetValue(instance); }
            catch (Exception ex)
            {
                ProxyLog.Write("[ApiBootstrap] Endpoint property read failed: "
                    + instance.GetType().Name + "." + property.Name + " -> "
                    + ex.GetType().Name + ": " + ex.Message);
            }

            if (raw is string value && predicate(value))
                return value.Trim();
        }

        return null;
    }

    private static string[] ReadBestStringArrayField(object instance)
    {
        foreach (FieldInfo field in instance.GetType().GetFields(BindingFlags.Instance | BindingFlags.Static |
                     BindingFlags.Public | BindingFlags.NonPublic))
        {
            if (field.FieldType != typeof(string[]))
                continue;

            object? raw = null;
            try { raw = field.GetValue(field.IsStatic ? null : instance); }
            catch { }

            string[] keys = CleanApiKeys(raw as string[]);
            if (keys.Length > 0 && keys.All(key => !LooksLikeEndpointValue(key)))
                return keys;
        }

        return Array.Empty<string>();
    }

    private static string[] ReadBestStringArrayProperty(object instance)
    {
        foreach (PropertyInfo property in instance.GetType().GetProperties(BindingFlags.Instance |
                     BindingFlags.Public | BindingFlags.NonPublic))
        {
            if (property.PropertyType != typeof(string[]) || property.GetIndexParameters().Length != 0)
                continue;

            object? raw = null;
            try { raw = property.GetValue(instance); }
            catch (Exception ex)
            {
                ProxyLog.Write("[ApiBootstrap] ApiKeys property read failed: "
                    + instance.GetType().Name + "." + property.Name + " -> "
                    + ex.GetType().Name + ": " + ex.Message);
            }

            string[] keys = CleanApiKeys(raw as string[]);
            if (keys.Length > 0 && keys.All(key => !LooksLikeEndpointValue(key)))
                return keys;
        }

        return Array.Empty<string>();
    }

    private static bool LooksLikeEndpointValue(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        string trimmed = value.Trim();
        return trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
               trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase);
    }

    private static string DescribeKeys(string[] keys)
    {
        if (keys.Length == 0)
            return "(no keys)";

        return "lengths=" + string.Join(",", keys.Select(key => key.Length.ToString()));
    }

    private static string[] CleanApiKeys(string[]? keys)
    {
        if (keys == null)
            return Array.Empty<string>();

        return keys
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Select(key => key.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    private static string[] CleanApiKeyText(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return Array.Empty<string>();

        return CleanApiKeys(value.Split(new[] { ';', ',', '|', '\r', '\n', '\t', ' ' },
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    internal static void PatchOneStaticHelper(MethodInfo? target, MethodInfo stub, string label)
    {
        if (target == null || stub == null)
        {
            ProxyLog.Write($"[{label}] Skipped — target or stub is null");
            return;
        }
        try
        {
            RuntimeHelpers.PrepareMethod(target.MethodHandle);
            RuntimeHelpers.PrepareMethod(stub.MethodHandle);

            nint targetPrecode = target.MethodHandle.GetFunctionPointer();
            nint stubPrecode   = stub.MethodHandle.GetFunctionPointer();

            nint targetReal = ResolveRealAddr(targetPrecode);
            nint stubReal   = ResolveRealAddr(stubPrecode);

            ProxyLog.Write($"[{label}] target precode=0x{targetPrecode:X16} real=0x{targetReal:X16}");
            ProxyLog.Write($"[{label}] stub   precode=0x{stubPrecode:X16}   real=0x{stubReal:X16}");

            // MOV RAX, imm64 (10 byte) + JMP RAX (2 byte) = 12 byte trampoline
            byte[] trampoline = new byte[12];
            trampoline[0] = 0x48; // REX.W
            trampoline[1] = 0xB8; // MOV RAX, imm64
            BitConverter.GetBytes((long)stubReal).CopyTo(trampoline, 2);
            trampoline[10] = 0xFF; // JMP RAX
            trampoline[11] = 0xE0;

            MakeWritable(targetReal, 12);
            Marshal.Copy(trampoline, 0, targetReal, 12);

            ProxyLog.Write($"[{label}] Trampoline written successfully at 0x{targetReal:X16}");
        }
        catch (Exception ex)
        {
            ProxyLog.Write($"[{label}] EXCEPTION: {ex}");
        }
    }
}

internal static class ProtectionBypass
{
    private static Type? _uploadTicketType;
    private static readonly OpCode[] OneByteOpCodes = new OpCode[0x100];
    private static readonly OpCode[] TwoByteOpCodes = new OpCode[0x100];

    static ProtectionBypass()
    {
        foreach (var field in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            if (field.GetValue(null) is not OpCode op)
                continue;

            ushort value = unchecked((ushort)op.Value);
            if (value < 0x100)
                OneByteOpCodes[value] = op;
            else if ((value & 0xFF00) == 0xFE00)
                TwoByteOpCodes[value & 0xFF] = op;
        }
    }

    internal static void TryPatch(Assembly asm)
    {
        try
        {
            // sEp= tipini bul: aYN_003D instance metoduna sahip olan
            var sEpType = asm.GetTypes().FirstOrDefault(t =>
                t.GetMethod("aYN=", BindingFlags.Instance | BindingFlags.NonPublic) != null);
            if (sEpType == null)
            {
                ProxyLog.Write("[ProtBypass] sEp= type not found");
                return;
            }

            ProxyLog.Write("[ProtBypass] sEp= type found: " + sEpType.FullName);

            // PixeldrainClient nested tipini bul: UploadFileAsync static metoduna sahip olan
            var pdClientType = sEpType
                .GetNestedTypes(BindingFlags.NonPublic | BindingFlags.Public)
                .FirstOrDefault(t =>
                    t.GetMethod("UploadFileAsync", BindingFlags.Static | BindingFlags.Public) != null);
            if (pdClientType == null)
            {
                ProxyLog.Write("[ProtBypass] PixeldrainClient not found");
                return;
            }

            ProxyLog.Write("[ProtBypass] PixeldrainClient type found: " + pdClientType.FullName);

            var uploadMethod = pdClientType.GetMethod("UploadFileAsync", BindingFlags.Static | BindingFlags.Public);
            _uploadTicketType = uploadMethod?.ReturnType.GetGenericArguments().FirstOrDefault();
            ProxyLog.Write("[ProtBypass] UploadTicket type: " + (_uploadTicketType?.FullName ?? "null"));

            var self = typeof(ProtectionBypass);
            AuthBypass.PatchOneStaticHelper(
                uploadMethod,
                self.GetMethod(nameof(UploadFileStub), BindingFlags.Static | BindingFlags.Public)!,
                "UploadFile");
            PatchHttpDiagnostics(asm);
            PatchHttpContentRequestDiagnostics(sEpType);

            if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("RIKA_PROXY_PATCH_PROTECTION_STAGES")))
            {
                ProxyLog.Write("[ProtBypass] Environment variable check skipped - Patching StartJob/WaitForFile/MoveNext unconditionally.");
            }

            // Patch StartJob (aYN=) — sEp= üzerindeki instance metot
            var startJobMethod = sEpType.GetMethod("aYN=", BindingFlags.Instance | BindingFlags.NonPublic);
            if (startJobMethod != null)
            {
                AuthBypass.PatchOneStaticHelper(
                    startJobMethod,
                    self.GetMethod(nameof(StartJobStub), BindingFlags.Static | BindingFlags.Public)!,
                    "StartJob");
                ProxyLog.Write("[ProtBypass] aYN= (StartJob) patched ✓");
            }
            else
            {
                ProxyLog.Write("[ProtBypass] aYN= method not found on sEp= type — skipped");
            }

            // Patch WaitForFile (blA=) — sEp= üzerindeki instance metot
            var waitForFileMethod = sEpType.GetMethod("blA=", BindingFlags.Instance | BindingFlags.NonPublic);
            if (waitForFileMethod != null)
            {
                AuthBypass.PatchOneStaticHelper(
                    waitForFileMethod,
                    self.GetMethod(nameof(WaitForFileStub), BindingFlags.Static | BindingFlags.Public)!,
                    "WaitForFile");
                ProxyLog.Write("[ProtBypass] blA= (WaitForFile) patched ✓");
            }
            else
            {
                ProxyLog.Write("[ProtBypass] blA= method not found on sEp= type — skipped");
            }

            // Patch ProtectAsync state machine MoveNext
            // The TPL async continuation calls IAsyncStateMachine.MoveNext() via interface dispatch —
            // a separate JIT entry point from the private void MoveNext() implementation.
            // We must patch BOTH to intercept all call paths.
            var protectSMType = sEpType.GetNestedTypes(BindingFlags.NonPublic | BindingFlags.Public)
                .FirstOrDefault(t => t.Name.Contains("ProtectAsync") || t.Name == "_003CProtectAsync_003Ed__2");
            if (protectSMType != null)
            {
                var stubMethod = self.GetMethod(nameof(MoveNextStub), BindingFlags.Static | BindingFlags.Public);

                // 1) Patch the private void MoveNext() direct implementation
                var moveNext = protectSMType.GetMethod("MoveNext",
                    BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
                if (moveNext != null)
                {
                    AuthBypass.PatchOneStaticHelper(moveNext, stubMethod!, "ProtectAsync.MoveNext");
                    ProxyLog.Write("[ProtBypass] ProtectAsync.MoveNext (private) patched ✓");
                }
                else
                {
                    ProxyLog.Write("[ProtBypass] ProtectAsync SM type found but private MoveNext not found");
                }

                // 2) Patch the IAsyncStateMachine.MoveNext() explicit interface implementation
                //    This is the entry point the TPL actually calls via interface dispatch.
                try
                {
                    var ifaceType = typeof(System.Runtime.CompilerServices.IAsyncStateMachine);
                    var ifaceMoveNext = ifaceType.GetMethod("MoveNext");
                    if (ifaceMoveNext != null)
                    {
                        var map = protectSMType.GetInterfaceMap(ifaceType);
                        int idx = Array.IndexOf(map.InterfaceMethods, ifaceMoveNext);
                        if (idx >= 0)
                        {
                            var ifaceTarget = map.TargetMethods[idx];
                            AuthBypass.PatchOneStaticHelper(ifaceTarget, stubMethod!, "ProtectAsync.IAsyncStateMachine.MoveNext");
                            ProxyLog.Write("[ProtBypass] ProtectAsync.IAsyncStateMachine.MoveNext (interface dispatch) patched ✓");
                        }
                        else
                        {
                            ProxyLog.Write("[ProtBypass] IAsyncStateMachine.MoveNext not found in interface map");
                        }
                    }
                    else
                    {
                        ProxyLog.Write("[ProtBypass] IAsyncStateMachine.MoveNext reflection lookup failed");
                    }
                }
                catch (Exception ifaceEx)
                {
                    ProxyLog.Write("[ProtBypass] Interface map patch error: " + ifaceEx.Message);
                }
            }
            else
            {
                ProxyLog.Write("[ProtBypass] ProtectAsync SM type not found — logging all nested types:");
                foreach (var nt in sEpType.GetNestedTypes(BindingFlags.NonPublic | BindingFlags.Public))
                    ProxyLog.Write("[ProtBypass]   nested: " + nt.Name);
            }

            ProxyLog.Write("[ProtBypass] TryPatch complete — UploadFileAsync + StartJob + WaitForFile + MoveNext (private+interface) patched");
        }
        catch (Exception ex)
        {
            ProxyLog.Write("[ProtBypass] TryPatch error: " + ex);
        }
    }

    private static void PatchHttpDiagnostics(Assembly asm)
    {
        try
        {
            var stub = typeof(ProtectionBypass).GetMethod(
                nameof(EnsureSuccessStatusCodeStub),
                BindingFlags.Static | BindingFlags.Public)!;
            int patched = 0;

            foreach (var type in SafeGetTypes(asm))
            {
                MethodInfo[] methods;
                try
                {
                    methods = type.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
                }
                catch
                {
                    continue;
                }

                foreach (var method in methods)
                {
                    var parameters = method.GetParameters();
                    if (method.ReturnType != typeof(System.Net.Http.HttpResponseMessage)
                        || parameters.Length != 1
                        || parameters[0].ParameterType != typeof(System.Net.Http.HttpResponseMessage)
                        || !CallsEnsureSuccessStatusCode(method))
                    {
                        continue;
                    }

                    AuthBypass.PatchOneStaticHelper(method, stub, "HttpEnsure:" + type.Name + "." + method.Name);
                    patched++;
                }
            }

            ProxyLog.Write("[ProtBypass] HTTP diagnostics patched wrappers=" + patched);
        }
        catch (Exception ex)
        {
            ProxyLog.Write("[ProtBypass] HTTP diagnostics patch error: " + ex.Message);
        }
    }

    private static void PatchHttpContentRequestDiagnostics(Type sEpType)
    {
        try
        {
            var stub = typeof(ProtectionBypass).GetMethod(
                nameof(HttpContentRequestStub),
                BindingFlags.Static | BindingFlags.Public)!;
            int patched = 0;

            var scanTypes = new[] { sEpType }
                .Concat(sEpType.GetNestedTypes(BindingFlags.Public | BindingFlags.NonPublic));

            foreach (var type in scanTypes)
            {
                MethodInfo[] methods;
                try
                {
                    methods = type.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
                }
                catch
                {
                    continue;
                }

                foreach (var method in methods)
                {
                    var parameters = method.GetParameters();
                    if (!IsTaskOfHttpResponse(method.ReturnType)
                        || parameters.Length != 4
                        || parameters[0].ParameterType != typeof(System.Net.Http.HttpClient)
                        || parameters[1].ParameterType != typeof(string)
                        || parameters[2].ParameterType != typeof(System.Net.Http.HttpContent)
                        || parameters[3].ParameterType != typeof(CancellationToken))
                    {
                        continue;
                    }

                    AuthBypass.PatchOneStaticHelper(method, stub, "HttpContent:" + type.Name + "." + method.Name);
                    patched++;
                }
            }

            ProxyLog.Write("[ProtBypass] HTTP content request diagnostics patched wrappers=" + patched);
        }
        catch (Exception ex)
        {
            ProxyLog.Write("[ProtBypass] HTTP content request diagnostics patch error: " + ex.Message);
        }
    }

    public static Task<System.Net.Http.HttpResponseMessage> HttpContentRequestStub(
        System.Net.Http.HttpClient client,
        string url,
        System.Net.Http.HttpContent content,
        CancellationToken ct)
    {
        return SendHttpContentRequestWithLogAsync(client, url, content, ct);
    }

    private static async Task<System.Net.Http.HttpResponseMessage> SendHttpContentRequestWithLogAsync(
        System.Net.Http.HttpClient client,
        string url,
        System.Net.Http.HttpContent content,
        CancellationToken ct)
    {
        content = EnsureLicenseInMultipartContent(content);

        ProxyLog.Write("[ProtBypass] HTTP content request url=" + RedactForLog(url, 300)
            + " content=" + DescribeHttpContent(content));

        var response = await client.PostAsync(url, content, ct).ConfigureAwait(false);
        string body = "";
        try
        {
            if (response.Content != null)
                body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            body = "<read failed: " + ex.GetType().Name + ": " + ex.Message + ">";
        }

        ProxyLog.Write("[ProtBypass] HTTP content response status=" + (int)response.StatusCode
            + " " + response.StatusCode + " body=" + RedactForLog(body, 1200));
        return response;
    }

    private static bool IsTaskOfHttpResponse(Type type)
    {
        return type.IsGenericType
            && type.GetGenericTypeDefinition() == typeof(Task<>)
            && type.GetGenericArguments()[0] == typeof(System.Net.Http.HttpResponseMessage);
    }

    private static System.Net.Http.HttpContent EnsureLicenseInMultipartContent(
        System.Net.Http.HttpContent content)
    {
        try
        {
            if (content.GetType().Name != "MultipartFormDataContent")
                return content;

            string body = content.ReadAsStringAsync()
                .ConfigureAwait(false)
                .GetAwaiter()
                .GetResult();

            if (string.IsNullOrEmpty(body) ||
                !body.Contains("name=license", StringComparison.OrdinalIgnoreCase))
            {
                return content;
            }

            var fields = ParseMultipartTextFields(body).ToArray();
            if (fields.Length == 0)
                return content;

            bool changed = false;
            string license = AuthBypass.GetConfiguredLicense();
            var rebuilt = new System.Net.Http.MultipartFormDataContent();
            foreach (var (name, value) in fields)
            {
                string nextValue = value;
                if (string.Equals(name, "license", StringComparison.OrdinalIgnoreCase) &&
                    string.IsNullOrWhiteSpace(nextValue))
                {
                    nextValue = license;
                    changed = true;
                }

                rebuilt.Add(new System.Net.Http.StringContent(nextValue), name);
            }

            if (!changed)
                return content;

            ProxyLog.Write("[ProtBypass] Multipart license field was empty; injected len=" + license.Length);
            return rebuilt;
        }
        catch (Exception ex)
        {
            ProxyLog.Write("[ProtBypass] Multipart license injection failed: "
                + ex.GetType().Name + ": " + ex.Message);
            return content;
        }
    }

    private static IEnumerable<(string Name, string Value)> ParseMultipartTextFields(string body)
    {
        var matches = Regex.Matches(body,
            "Content-Disposition:\\s*form-data;\\s*name=\"?(?<name>[^\"\\r\\n]+)\"?\\r\\n\\r\\n(?<value>.*?)(?=\\r\\n--)",
            RegexOptions.Singleline | RegexOptions.IgnoreCase);

        foreach (Match match in matches)
        {
            string name = match.Groups["name"].Value.Trim();
            string value = match.Groups["value"].Value;
            if (!string.IsNullOrWhiteSpace(name))
                yield return (name, value);
        }
    }

    public static System.Net.Http.HttpResponseMessage EnsureSuccessStatusCodeStub(
        System.Net.Http.HttpResponseMessage response)
    {
        try
        {
            string status = response == null
                ? "null"
                : ((int)response.StatusCode).ToString() + " " + response.StatusCode;
            string body = "";
            if (response?.Content != null)
            {
                body = response.Content.ReadAsStringAsync()
                    .ConfigureAwait(false)
                    .GetAwaiter()
                    .GetResult();
            }

            ProxyLog.Write("[ProtBypass] HTTP EnsureSuccessStatusCode status=" + status
                + " body=" + RedactForLog(body, 900));
        }
        catch (Exception ex)
        {
            ProxyLog.Write("[ProtBypass] HTTP diagnostic read failed: " + ex.GetType().Name + ": " + ex.Message);
        }

        if (response == null)
            throw new NullReferenceException("HttpResponseMessage response was null.");

        return response.EnsureSuccessStatusCode();
    }

    private static Type[] SafeGetTypes(Assembly asm)
    {
        try
        {
            return asm.GetTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            return ex.Types.Where(t => t != null).Cast<Type>().ToArray();
        }
        catch
        {
            return Array.Empty<Type>();
        }
    }

    private static bool CallsEnsureSuccessStatusCode(MethodInfo method)
    {
        byte[]? il;
        try
        {
            il = method.GetMethodBody()?.GetILAsByteArray();
        }
        catch
        {
            return false;
        }

        if (il == null || il.Length == 0)
            return false;

        for (int i = 0; i < il.Length;)
        {
            OpCode op;
            byte b = il[i++];
            if (b == 0xFE)
            {
                if (i >= il.Length)
                    return false;
                op = TwoByteOpCodes[il[i++]];
            }
            else
            {
                op = OneByteOpCodes[b];
            }

            int operandStart = i;
            int operandSize = GetOperandSize(op.OperandType, il, operandStart);
            if (operandSize < 0 || operandStart + operandSize > il.Length)
                return false;

            if ((op == OpCodes.Call || op == OpCodes.Callvirt) && operandSize == 4)
            {
                int token = BitConverter.ToInt32(il, operandStart);
                try
                {
                    var resolved = method.Module.ResolveMethod(token);
                    if (resolved is MethodInfo called
                        && called.Name == nameof(System.Net.Http.HttpResponseMessage.EnsureSuccessStatusCode)
                        && called.DeclaringType == typeof(System.Net.Http.HttpResponseMessage))
                    {
                        return true;
                    }
                }
                catch
                {
                    // Ignore tokens that cannot be resolved in the current module context.
                }
            }

            i = operandStart + operandSize;
        }

        return false;
    }

    private static int GetOperandSize(OperandType operandType, byte[] il, int operandStart)
    {
        return operandType switch
        {
            OperandType.InlineNone => 0,
            OperandType.ShortInlineBrTarget => 1,
            OperandType.ShortInlineI => 1,
            OperandType.ShortInlineVar => 1,
            OperandType.InlineVar => 2,
            OperandType.InlineI => 4,
            OperandType.InlineBrTarget => 4,
            OperandType.InlineField => 4,
            OperandType.InlineMethod => 4,
            OperandType.InlineSig => 4,
            OperandType.InlineString => 4,
            OperandType.InlineTok => 4,
            OperandType.InlineType => 4,
            OperandType.ShortInlineR => 4,
            OperandType.InlineI8 => 8,
            OperandType.InlineR => 8,
            OperandType.InlineSwitch => ReadSwitchOperandSize(il, operandStart),
            _ => -1
        };
    }

    private static int ReadSwitchOperandSize(byte[] il, int operandStart)
    {
        if (operandStart + 4 > il.Length)
            return -1;

        int count = BitConverter.ToInt32(il, operandStart);
        if (count < 0)
            return -1;

        long size = 4L + (4L * count);
        return size > int.MaxValue ? -1 : (int)size;
    }

    private static string DescribeHttpContent(System.Net.Http.HttpContent? content)
    {
        if (content == null)
            return "null";

        string headers = "";
        string body = "";
        try
        {
            headers = content.Headers?.ToString() ?? "";
        }
        catch (Exception ex)
        {
            headers = "<headers read failed: " + ex.GetType().Name + ">";
        }

        try
        {
            body = content.ReadAsStringAsync()
                .ConfigureAwait(false)
                .GetAwaiter()
                .GetResult();
        }
        catch (Exception ex)
        {
            body = "<body read failed: " + ex.GetType().Name + ": " + ex.Message + ">";
        }

        return "type=" + content.GetType().Name
            + " headers=" + RedactForLog(headers, 300)
            + " body=" + RedactForLog(body, 1200);
    }

    private static string RedactForLog(string? value, int maxLength)
    {
        if (string.IsNullOrEmpty(value))
            return "";

        string cleaned = value.Replace("\r", "\\r").Replace("\n", "\\n");
        cleaned = Regex.Replace(cleaned,
            @"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            "[guid-redacted]");

        if (cleaned.Length <= maxLength)
            return cleaned;

        return cleaned.Substring(0, maxLength) + "...<truncated>";
    }

    private static byte[] _lastUploadedBytes = Array.Empty<byte>();

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static object UploadFileStub(byte[] fileBytes, string uploadKey, string[] apiKeys, CancellationToken ct)
    {
        _lastUploadedBytes = fileBytes ?? Array.Empty<byte>();
        ProxyLog.Write("[ProtBypass] UploadFileAsync stub called ✓ — performing real Pixeldrain upload");

        const string FallbackPixeldrainApiKey = "4640b1ae-5ceb-4e9e-a0f1-ece21fb06865";
        const string RikaXorKey = "{C1B8DA14-46C7-45F6-95C2-EAB1146DF091}";

        var type = _uploadTicketType;
        if (type == null)
        {
            ProxyLog.Write("[ProtBypass] UploadTicket type is null, returning null task");
            return Task.FromResult<object?>(null)!;
        }

        // Run the real upload on a thread-pool thread and return the Task<UploadTicket>-shaped object.
        var tcs = new System.Threading.Tasks.TaskCompletionSource<object?>();

        System.Threading.ThreadPool.QueueUserWorkItem(_ =>
        {
            try
            {
                string pixeldrainApiKey = (apiKeys ?? Array.Empty<string>())
                    .FirstOrDefault(k => !string.IsNullOrWhiteSpace(k))
                    ?? FallbackPixeldrainApiKey;

                string fileId = PixeldrainUpload(fileBytes, pixeldrainApiKey, ct);
                ProxyLog.Write("[ProtBypass] Pixeldrain upload succeeded — file_id=" + fileId);

                string refMode = (Environment.GetEnvironmentVariable("RIKA_PROXY_REF_MODE") ?? "uploadkey").Trim();
                string encryptedRef;
                if (refMode.Equals("plain", StringComparison.OrdinalIgnoreCase))
                {
                    encryptedRef = fileId;
                }
                else if (refMode.Equals("uploadkey", StringComparison.OrdinalIgnoreCase))
                {
                    encryptedRef = string.IsNullOrEmpty(uploadKey)
                        ? fileId
                        : XorToBase64(fileId, uploadKey);
                }
                else
                {
                    refMode = "xorkey";
                    encryptedRef = XorToBase64(fileId, RikaXorKey);
                }

                ProxyLog.Write("[ProtBypass] Upload ticket built mode=" + refMode
                    + " fileIdLen=" + fileId.Length
                    + " uploadKeyLen=" + (uploadKey?.Length ?? 0)
                    + " encryptedRefLen=" + encryptedRef.Length
                    + " apiKeys=" + (apiKeys?.Length ?? 0));

                var ticket = Activator.CreateInstance(type, encryptedRef, fileId, pixeldrainApiKey)!;
                tcs.SetResult(ticket);
            }
            catch (Exception ex)
            {
                ProxyLog.Write("[ProtBypass] Pixeldrain upload FAILED: " + ex.GetType().Name + ": " + ex.Message);

                // Fallback: build a ticket with the api key so the app at least has it.
                try
                {
                    var ticket = Activator.CreateInstance(type, "upload-failed", "upload-failed", FallbackPixeldrainApiKey)!;
                    tcs.SetResult(ticket);
                }
                catch
                {
                    tcs.SetResult(null);
                }
            }
        });

        // Return Task<UploadTicket> using the generic Task.FromResult shape the app expects.
        // We chain the TCS task to produce the correctly typed task via reflection.
        return ChainToTypedTask(tcs.Task, type);
    }

    // -----------------------------------------------------------------------
    // ChainToTypedTask — converts Task<object?> to Task<T> where T = ticketType.
    // The app awaits Task<UploadTicket>, so we need the correct generic type.
    // -----------------------------------------------------------------------
    private static object ChainToTypedTask(System.Threading.Tasks.Task<object?> source, Type ticketType)
    {
        // Task<T>.ContinueWith + TaskCompletionSource<T> via reflection
        var tcsType    = typeof(System.Threading.Tasks.TaskCompletionSource<>).MakeGenericType(ticketType);
        var tcsInner   = Activator.CreateInstance(tcsType)!;
        var setResult  = tcsType.GetMethod("SetResult")!;
        var setExc     = tcsType.GetMethod("SetException", new[] { typeof(Exception) })!;
        var taskProp   = tcsType.GetProperty("Task")!;

        source.ContinueWith(t =>
        {
            if (t.IsFaulted)
            {
                try { setExc.Invoke(tcsInner, new object?[] { t.Exception!.InnerException ?? t.Exception }); } catch { }
            }
            else
            {
                try { setResult.Invoke(tcsInner, new object?[] { t.Result }); } catch { }
            }
        }, System.Threading.Tasks.TaskContinuationOptions.ExecuteSynchronously);

        return taskProp.GetValue(tcsInner)!;
    }

    // -----------------------------------------------------------------------
    // PixeldrainUpload — uploads raw bytes to pixeldrain.com and returns
    // the file_id string from the JSON response.
    // API: PUT https://pixeldrain.com/api/file/{filename}
    //   Authorization: Basic base64(":" + apiKey)
    //   Content-Type: application/octet-stream
    //   Body: raw file bytes
    // PUT endpoint kabul eder raw body; POST /api/file multipart gerektirir.
    // -----------------------------------------------------------------------
    private static string PixeldrainUpload(byte[] fileBytes, string apiKey, System.Threading.CancellationToken ct)
    {
        using var client = new System.Net.Http.HttpClient();
        client.Timeout = System.TimeSpan.FromMinutes(10);

        // Basic auth: username is empty, password is the api key.
        string credentials = System.Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes(":" + apiKey));
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", credentials);

        using var content = new System.Net.Http.ByteArrayContent(fileBytes);
        content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

        ProxyLog.Write("[ProtBypass] Uploading " + fileBytes.Length + " bytes to pixeldrain (PUT)...");

        // PUT /api/file/{name} — raw body, no multipart needed
        var response = client.PutAsync("https://pixeldrain.com/api/file/upload.exe", content, ct)
                             .ConfigureAwait(false).GetAwaiter().GetResult();

        string body = response.Content.ReadAsStringAsync()
                              .ConfigureAwait(false).GetAwaiter().GetResult();

        ProxyLog.Write("[ProtBypass] Pixeldrain HTTP " + (int)response.StatusCode + " body=" + body);

        if (!response.IsSuccessStatusCode)
            throw new System.Net.Http.HttpRequestException(
                "Pixeldrain upload failed: HTTP " + (int)response.StatusCode + " " + body);

        // Parse {"id":"<file_id>", ...}
        using var doc = System.Text.Json.JsonDocument.Parse(body);
        if (doc.RootElement.TryGetProperty("id", out var idElem))
            return idElem.GetString() ?? throw new InvalidOperationException("Empty file_id in response");

        throw new InvalidOperationException("'id' field missing from pixeldrain response: " + body);
    }

    // -----------------------------------------------------------------------
    // XorToBase64 — XOR-encrypts a UTF-8 string with a key, returns base64.
    // Mirrors the XorToBase64 used by PixeldrainClient inside sEp=.
    // -----------------------------------------------------------------------
    private static string XorToBase64(string input, string key)
    {
        byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(input);
        byte[] keyBytes   = System.Text.Encoding.UTF8.GetBytes(key);
        byte[] result     = new byte[inputBytes.Length];
        for (int i = 0; i < inputBytes.Length; i++)
            result[i] = (byte)(inputBytes[i] ^ keyBytes[i % keyBytes.Length]);
        return System.Convert.ToBase64String(result);
    }

    // -----------------------------------------------------------------------
    // MoveNextStub — ProtectAsync state machine MoveNext'ini replace eder.
    // x64 instance call: RCX = struct ptr (managed ref)
    // Reflection ile builder.SetResult(ProtectionResult{IsSuccess=true}) çağırır.
    // -----------------------------------------------------------------------
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void MoveNextStub(object self)
    {
        ProxyLog.Write("[ProtBypass] ProtectAsync.MoveNext stub called ✓");
        try
        {
            if (self == null) return;
            var smType = self.GetType();

            // request alanından inputPath oku
            string? inputPath = null;
            try
            {
                foreach (var f in smType.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
                {
                    var val = f.GetValue(self);
                    if (val == null) continue;
                    var vt = val.GetType();
                    foreach (var propName in new[] { "AssemblyPath", "InputPath", "FilePath", "Path" })
                    {
                        var p = vt.GetProperty(propName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                        if (p != null && p.PropertyType == typeof(string))
                        {
                            inputPath = p.GetValue(val) as string;
                            if (!string.IsNullOrEmpty(inputPath)) goto foundPath;
                        }
                    }
                }
                foundPath:;
            }
            catch { }

            string outputPath = string.IsNullOrEmpty(inputPath)
                ? "protected_output.exe"
                : System.IO.Path.Combine(
                    System.IO.Path.GetDirectoryName(inputPath) ?? "",
                    System.IO.Path.GetFileNameWithoutExtension(inputPath) + ".protected"
                    + System.IO.Path.GetExtension(inputPath));

            ProxyLog.Write("[ProtBypass] MoveNextStub outputPath=" + outputPath);

            try
            {
                if (!string.IsNullOrEmpty(inputPath) && System.IO.File.Exists(inputPath))
                    System.IO.File.Copy(inputPath, outputPath, overwrite: true);
            }
            catch (Exception ex) { ProxyLog.Write("[ProtBypass] File copy: " + ex.Message); }

            Type? resultType = AppDomain.CurrentDomain.GetAssemblies()
                .SelectMany(a => { try { return a.GetTypes(); } catch { return Array.Empty<Type>(); } })
                .FirstOrDefault(t => t.Name == "ProtectionResult");
            if (resultType == null) { ProxyLog.Write("[ProtBypass] MoveNextStub: ProtectionResult not found"); return; }

            var result = Activator.CreateInstance(resultType)!;
            AuthBypass.TrySet(result, resultType, "IsSuccess",    true);
            AuthBypass.TrySet(result, resultType, "OutputPath",   outputPath);
            AuthBypass.TrySet(result, resultType, "ErrorMessage", (string?)null);

            // state = -2 (completed)
            var stateField = smType.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
                .FirstOrDefault(f => f.Name.Contains("1__state"));
            try { stateField?.SetValue(self, -2); } catch { }

            // builder.SetResult(result)
            var builderField = smType.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
                .FirstOrDefault(f => f.Name.Contains("t__builder"));
            if (builderField == null) { ProxyLog.Write("[ProtBypass] MoveNextStub: builder field not found"); return; }

            var builder = builderField.GetValue(self)!;
            var setResult = builder.GetType().GetMethod("SetResult");
            if (setResult == null) { ProxyLog.Write("[ProtBypass] MoveNextStub: SetResult not found"); return; }

            setResult.Invoke(builder, new object[] { result });
            try { builderField.SetValue(self, builder); } catch { }

            ProxyLog.Write("[ProtBypass] MoveNextStub: SetResult called ✓");
        }
        catch (Exception ex)
        {
            ProxyLog.Write("[ProtBypass] MoveNextStub EXCEPTION: " + ex);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static object StartJobStub(object self, object req, string a, string b, CancellationToken ct)
    {
        ProxyLog.Write("[ProtBypass] aYN_003D (StartJob) stub called ✓");
        return Task.FromResult("https://bypass");
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static object WaitForFileStub(object self, string jobUrl, object ticket, object progress, CancellationToken ct)
    {
        ProxyLog.Write("[ProtBypass] blA_003D (WaitForFile) stub called ✓");
        return Task.FromResult(_lastUploadedBytes)!;
    }
}

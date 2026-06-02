extern alias real;

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
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
                AuthBypass.TryPatch(already);

            PreloadRealAssembly();
            StartAnalysisTimer();
        }
    }

    private static void OnAssemblyLoad(object? sender, AssemblyLoadEventArgs args)
    {
        if (string.Equals(args.LoadedAssembly.GetName().Name, "RikaNET.WinUI", StringComparison.OrdinalIgnoreCase))
            AuthBypass.TryPatch(args.LoadedAssembly);
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
    private static string _apiEndpoint = "https://pixeldrain.com/api";
    private static string[] _apiKeys = new[] { "proxy-api-key" };

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

        RuntimeHelpers.PrepareMethod(stubInit.MethodHandle);
        RuntimeHelpers.PrepareMethod(stubSignIn.MethodHandle);

        nint initPtr   = stubInit.MethodHandle.GetFunctionPointer();
        nint signInPtr = stubSignIn.MethodHandle.GetFunctionPointer();

        ProxyLog.Write($"[VTable] stubInit=0x{initPtr:X16} stubSignIn=0x{signInPtr:X16}");

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
        PatchProtectionService(asm);
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
            TrySet(state, type, "IsReady", true);
            TrySet(state, type, "CachedLicense", "RIKA-0000-0000-0000");
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
            var type = AuthResultType;
            if (type == null) return Task.CompletedTask;
            var result = Activator.CreateInstance(type)!;
            TrySet(result, type, "IsSuccess", true);
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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(nint lpAddress, nuint dwSize, uint flNewProtect, out uint lpflOldProtect);

    private static void MakeWritable(nint address, int size)
    {
        VirtualProtect(address, (nuint)size, 0x40 /* PAGE_EXECUTE_READWRITE */, out _);
    }

    // -----------------------------------------------------------------------
    // Yardımcı metodlar
    // -----------------------------------------------------------------------

    private static object MakeTask(Type resultType, object value)
    {
        return typeof(Task)
            .GetMethod("FromResult")!
            .MakeGenericMethod(resultType)
            .Invoke(null, new[] { value })!;
    }

    private static void TrySet(object instance, Type type, string name, object? value)
    {
        try
        {
            var prop = type.GetProperty(name,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (prop?.CanWrite == true)
            {
                prop.SetValue(instance, value);
                return;
            }
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
    private static nint ResolveRealAddr(nint addr)
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
            // IsSuccess / Success alanını true yap
            TrySet(result, resultType, "IsSuccess", true);
            TrySet(result, resultType, "Success",   true);
            TrySet(result, resultType, "Succeeded", true);
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

        MethodInfo endpointGetterStub = typeof(AuthBypass).GetMethod(nameof(ApiEndpointGetterStub),
            BindingFlags.Static | BindingFlags.NonPublic)!;
        MethodInfo endpointSetterStub = typeof(AuthBypass).GetMethod(nameof(ApiEndpointSetterStub),
            BindingFlags.Static | BindingFlags.NonPublic)!;
        MethodInfo apiKeysGetterStub = typeof(AuthBypass).GetMethod(nameof(ApiKeysGetterStub),
            BindingFlags.Static | BindingFlags.NonPublic)!;
        MethodInfo apiKeysSetterStub = typeof(AuthBypass).GetMethod(nameof(ApiKeysSetterStub),
            BindingFlags.Static | BindingFlags.NonPublic)!;

        int patched = 0;
        foreach (Type type in GetLoadableTypes(winUiAsm))
        {
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

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string ApiEndpointGetterStub(object self)
    {
        string endpoint = GetConfiguredEndpoint();
        if (Interlocked.Exchange(ref _endpointGetterLogged, 1) == 0)
            ProxyLog.Write("[ApiBootstrap] Endpoint getter stub -> " + endpoint);
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
        string[] keys = GetConfiguredApiKeys();
        if (Interlocked.Exchange(ref _apiKeysGetterLogged, 1) == 0)
            ProxyLog.Write("[ApiBootstrap] ApiKeys getter stub -> count=" + keys.Length);
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

    private static string GetConfiguredEndpoint()
    {
        string? env = Environment.GetEnvironmentVariable("RIKA_PROXY_ENDPOINT");
        return string.IsNullOrWhiteSpace(env) ? _apiEndpoint : env.Trim();
    }

    private static string[] GetConfiguredApiKeys()
    {
        string? env = Environment.GetEnvironmentVariable("RIKA_PROXY_API_KEYS");
        if (!string.IsNullOrWhiteSpace(env))
        {
            string[] fromEnv = CleanApiKeys(env.Split(new[] { ';', ',', '|', '\r', '\n', '\t', ' ' },
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            if (fromEnv.Length > 0)
                return fromEnv;
        }

        string[] keys = CleanApiKeys(_apiKeys);
        return keys.Length > 0 ? keys : new[] { "proxy-api-key" };
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

    private static void PatchProtectionService(Assembly winUiAsm)
    {
        ProxyLog.Write("[ProtectionStub] Searching for ProtectAsync targets...");

        MethodInfo stub = typeof(AuthBypass).GetMethod(nameof(ProtectAsyncStub),
            BindingFlags.Static | BindingFlags.NonPublic)!;

        int patched = 0;
        foreach (Type type in GetLoadableTypes(winUiAsm))
        {
            MethodInfo[] methods;
            try
            {
                methods = type.GetMethods(BindingFlags.Instance | BindingFlags.Static |
                    BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
            }
            catch
            {
                continue;
            }

            foreach (MethodInfo method in methods)
            {
                if (method.IsAbstract || method.ContainsGenericParameters)
                    continue;

                bool target =
                    (!method.IsStatic && method.Name == "ProtectAsync" && IsTaskOf(method.ReturnType, "ProtectionResult")) ||
                    (method.IsStatic && IsProtectionServiceHelper(method));

                if (!target)
                    continue;

                PatchOneStaticHelper(method, stub, "ProtectionStub:" + type.Name + "." + method.Name);
                patched++;
            }
        }

        ProxyLog.Write("[ProtectionStub] ProtectAsync patch count: " + patched);
    }

    private static bool IsProtectionServiceHelper(MethodInfo method)
    {
        if (!IsTaskOf(method.ReturnType, "ProtectionResult"))
            return false;

        var parameters = method.GetParameters();
        return parameters.Length == 4 &&
               parameters[0].ParameterType.Name.IndexOf("IProtectionService", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static bool IsTaskOf(Type type, string resultTypeName)
    {
        return type.IsGenericType &&
               type.GetGenericTypeDefinition() == typeof(Task<>) &&
               string.Equals(type.GetGenericArguments()[0].Name, resultTypeName, StringComparison.OrdinalIgnoreCase);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static object ProtectAsyncStub(object self, object request, object progress, CancellationToken ct)
    {
        try
        {
            ProxyLog.Write("[ProtectionStub] ProtectAsync stub called");
            ReportProtectionProgress(progress, "Preparing", 5);

            Type? resultType = FindTypeInLoadedAssemblies("ProtectionResult");
            if (resultType == null)
            {
                ProxyLog.Write("[ProtectionStub] ProtectionResult type not found");
                return Task.FromResult<object?>(null)!;
            }

            string? inputPath = TryGetValue(request, "FilePath") as string;
            byte[]? inputBytes = TryGetValue(request, "InputBytes") as byte[];
            string outputPath = BuildProxyOutputPath(inputPath);

            Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? AppContext.BaseDirectory);

            if (inputBytes != null && inputBytes.Length > 0)
            {
                File.WriteAllBytes(outputPath, inputBytes);
                ProxyLog.Write("[ProtectionStub] Wrote InputBytes -> " + outputPath + " (" + inputBytes.Length + " bytes)");
            }
            else if (!string.IsNullOrWhiteSpace(inputPath) && File.Exists(inputPath))
            {
                File.Copy(inputPath, outputPath, true);
                ProxyLog.Write("[ProtectionStub] Copied file -> " + outputPath);
            }
            else
            {
                File.WriteAllBytes(outputPath, Array.Empty<byte>());
                ProxyLog.Write("[ProtectionStub] No input bytes/file found; wrote empty output -> " + outputPath);
            }

            ReportProtectionProgress(progress, "Finalizing", 95);

            object result = Activator.CreateInstance(resultType)!;
            TrySet(result, resultType, "IsSuccess", true);
            TrySet(result, resultType, "OutputPath", outputPath);
            TrySet(result, resultType, "ErrorMessage", (string?)null);
            TrySet(result, resultType, "AppliedFeatures", Array.Empty<string>());

            ReportProtectionProgress(progress, "Complete", 100);
            ProxyLog.Write("[ProtectionStub] Returning success -> " + outputPath);
            return MakeTask(resultType, result);
        }
        catch (Exception ex)
        {
            ProxyLog.Write("[ProtectionStub] EXCEPTION: " + ex);
            Type? resultType = FindTypeInLoadedAssemblies("ProtectionResult");
            if (resultType == null)
                return Task.FromResult<object?>(null)!;

            object result = Activator.CreateInstance(resultType)!;
            TrySet(result, resultType, "IsSuccess", false);
            TrySet(result, resultType, "ErrorMessage", ex.Message);
            return MakeTask(resultType, result);
        }
    }

    private static void ReportProtectionProgress(object? progress, string step, double value)
    {
        if (progress == null)
            return;

        try
        {
            Type? progressType = FindTypeInLoadedAssemblies("ProtectionProgress");
            if (progressType == null)
                return;

            object update = Activator.CreateInstance(progressType)!;
            TrySet(update, progressType, "Step", step);
            TrySet(update, progressType, "Value", value);
            progress.GetType().GetMethod("Report")?.Invoke(progress, new[] { update });
        }
        catch (Exception ex)
        {
            ProxyLog.Write("[ProtectionStub] Progress report skipped: " + ex.Message);
        }
    }

    private static object? TryGetValue(object? instance, string name)
    {
        if (instance == null)
            return null;

        try
        {
            Type type = instance.GetType();
            var prop = type.GetProperty(name,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (prop?.CanRead == true)
                return prop.GetValue(instance);

            var field = type.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
                .FirstOrDefault(f => string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase) ||
                                     f.Name.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0);
            return field?.GetValue(instance);
        }
        catch
        {
            return null;
        }
    }

    private static string BuildProxyOutputPath(string? inputPath)
    {
        if (string.IsNullOrWhiteSpace(inputPath))
            return Path.Combine(AppContext.BaseDirectory, "rika-proxy-output.bin");

        string directory = Path.GetDirectoryName(inputPath) ?? AppContext.BaseDirectory;
        string fileName = Path.GetFileNameWithoutExtension(inputPath);
        string extension = Path.GetExtension(inputPath);

        if (string.IsNullOrWhiteSpace(fileName))
            fileName = "rika-proxy-output";

        return Path.Combine(directory, fileName + ".proxy-protected" + extension);
    }

    private static void PatchOneStaticHelper(MethodInfo? target, MethodInfo stub, string label)
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

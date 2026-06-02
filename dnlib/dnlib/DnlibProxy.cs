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

        // InitializeAsync(CancellationToken) -> Task<AuthBootstrapState>
        MethodInfo? initMethod = dhrType.GetMethod(
            "InitializeAsync",
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            null,
            new[] { typeof(CancellationToken) },
            null);

        if (initMethod != null)
            TrySwap(initMethod,
                typeof(AuthBypass).GetMethod(nameof(InitStub),
                    BindingFlags.Static | BindingFlags.NonPublic)!,
                "InitializeAsync");
        else
            ProxyLog.Write("[AuthBypass] InitializeAsync metodu bulunamadı.");

        // SignInAsync(string, bool, CancellationToken) -> Task<AuthResult>
        MethodInfo? signInMethod = dhrType.GetMethod(
            "SignInAsync",
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            null,
            new[] { typeof(string), typeof(bool), typeof(CancellationToken) },
            null);

        if (signInMethod != null)
            TrySwap(signInMethod,
                typeof(AuthBypass).GetMethod(nameof(SignInStub),
                    BindingFlags.Static | BindingFlags.NonPublic)!,
                "SignInAsync");
        else
            ProxyLog.Write("[AuthBypass] SignInAsync metodu bulunamadı.");
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

    // -----------------------------------------------------------------------
    // JIT pointer swap
    // -----------------------------------------------------------------------

    private static void TrySwap(MethodInfo target, MethodInfo stub, string label)
    {
        try
        {
            RuntimeHelpers.PrepareMethod(target.MethodHandle);
            RuntimeHelpers.PrepareMethod(stub.MethodHandle);

            nint targetPtr = target.MethodHandle.GetFunctionPointer();
            nint stubPtr = stub.MethodHandle.GetFunctionPointer();

            ProxyLog.Write($"[AuthBypass] {label}: target=0x{targetPtr:X16} stub=0x{stubPtr:X16}");

            MakeWritable(targetPtr, 12);
            WriteJump((byte*)targetPtr, (byte*)stubPtr);

            ProxyLog.Write("[AuthBypass] " + label + " patch'lendi ✓");
        }
        catch (Exception ex)
        {
            ProxyLog.Write("[AuthBypass] " + label + " swap hatası: " + ex);
        }
    }

    private static void WriteJump(byte* from, byte* to)
    {
        long delta = (long)to - (long)from - 5;
        if (delta >= int.MinValue && delta <= int.MaxValue)
        {
            from[0] = 0xE9; // JMP rel32
            int rel = (int)delta;
            from[1] = (byte)(rel & 0xFF);
            from[2] = (byte)((rel >> 8) & 0xFF);
            from[3] = (byte)((rel >> 16) & 0xFF);
            from[4] = (byte)((rel >> 24) & 0xFF);
        }
        else
        {
            // MOV RAX, imm64 + JMP RAX (12 bytes)
            from[0] = 0x48; from[1] = 0xB8;
            long addr = (long)to;
            for (int i = 0; i < 8; i++)
                from[2 + i] = (byte)((addr >> (i * 8)) & 0xFF);
            from[10] = 0xFF; from[11] = 0xE0; // JMP RAX
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
}

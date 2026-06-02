using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Threading;

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

internal static class ProxyBootstrap
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

            PreloadRealAssembly();
            StartAnalysisTimer();
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
                string.Equals(name, "dnlib", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            ProxyLog.Write("Assembly: " + assembly.FullName);
            AnalyzeAssemblyForDnlibUsage(assembly);
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
            return method.GetParameters().Any(parameter => IsDnlibType(parameter.ParameterType));
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
               lower.Contains("serial") ||
               lower.Contains("key") ||
               lower.Contains("token");
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

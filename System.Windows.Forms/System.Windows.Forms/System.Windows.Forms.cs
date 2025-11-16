using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

// IMMEDIATE BOOTSTRAP - Runs as soon as assembly is loaded
[assembly: RikaProxy.__ModuleInit]

// ══════════════════════════════════════════════════════════════════════════════
// MINIMAL METADATA - No strong naming to avoid CLR conflicts
// ══════════════════════════════════════════════════════════════════════════════
[assembly: AssemblyTitle("System.Windows.Forms")]
[assembly: ComVisible(false)]
[assembly: AssemblyVersion("4.0.0.0")]

// Application stub to bootstrap the proxy system
namespace System.Windows.Forms
{
    public sealed class Application
    {
        static Application()
        {
            try
            {
                var logPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PROXY_LOADED.txt");
                System.IO.File.WriteAllText(logPath, "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] PROXY DLL LOADED!\nAssembly: " + typeof(Application).Assembly.Location + "\n");
            }
            catch { }
            
            try
            {
                RikaProxy.ProxyBootstrap.Touch();
            }
            catch (Exception ex)
            {
                try
                {
                    var logPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PROXY_ERROR.txt");
                    System.IO.File.WriteAllText(logPath, "Bootstrap error: " + ex.ToString());
                }
                catch { }
            }
        }
        
        // Delegate all methods to real Application via reflection
        private static System.Type _realAppType;
        
        private static System.Type RealAppType
        {
            get
            {
                if (_realAppType == null)
                {
                    var asm = System.AppDomain.CurrentDomain.GetAssemblies()
                        .FirstOrDefault(a => a.FullName.StartsWith("System.Windows.Forms,") && a.Location.Contains("Microsoft.NET"));
                    if (asm != null)
                        _realAppType = asm.GetType("System.Windows.Forms.Application");
                }
                return _realAppType;
            }
        }
        
        public static void Run()
        {
            RealAppType?.GetMethod("Run", System.Type.EmptyTypes)?.Invoke(null, null);
        }
        
        public static void Exit()
        {
            RealAppType?.GetMethod("Exit", System.Type.EmptyTypes)?.Invoke(null, null);
        }
        
        public static void DoEvents()
        {
            RealAppType?.GetMethod("DoEvents")?.Invoke(null, null);
        }
        
        public static void EnableVisualStyles()
        {
            RealAppType?.GetMethod("EnableVisualStyles")?.Invoke(null, null);
        }
        
        public static void SetCompatibleTextRenderingDefault(bool defaultValue)
        {
            RealAppType?.GetMethod("SetCompatibleTextRenderingDefault")?.Invoke(null, new object[] { defaultValue });
        }
    }
}

namespace RikaProxy
{
    // Custom attribute that runs initialization code when assembly is loaded
    [AttributeUsage(AttributeTargets.Assembly)]
    internal sealed class __ModuleInit : Attribute
    {
        static __ModuleInit()
        {
            try
            {
                string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PROXY_LOADED.txt");
                File.WriteAllText(logPath, "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] PROXY DLL MODULE INIT!\n");
                File.AppendAllText(logPath, "Assembly: " + Assembly.GetExecutingAssembly().Location + "\n");
            }
            catch { }
            
            // Initialize bootstrap immediately
            ProxyBootstrap.Touch();
        }
    }
    
    internal static class ProxyBootstrap
    {
        private static readonly object InitLock = new object();
        private static Assembly _realWinFormsAssembly;
        private static bool _analysisTimerStarted = false;
        private static bool _isResolving = false; // Prevent recursion

        private const string LOCAL_ORIG_DLL = "orig.dll"; // Local backup of real System.Windows.Forms
        private const string GAC_WINFORMS_PATH = @"C:\WINDOWS\Microsoft.NET\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll";

        public static void Touch()
        {
            AppDomain.CurrentDomain.AssemblyResolve -= OnAssemblyResolve;
            AppDomain.CurrentDomain.AssemblyResolve += OnAssemblyResolve;
            ProxyLog.Write("ProxyBootstrap initialized.");

            // Pre-load the real assembly to avoid recursion issues
            PreloadRealAssembly();
        }

        private static void PreloadRealAssembly()
        {
            lock (InitLock)
            {
                if (_realWinFormsAssembly != null) return;

                try
                {
                    string realWinformsPath = null;
                    
                    // Priority 1: Environment variable
                    realWinformsPath = Environment.GetEnvironmentVariable("REAL_WINFORMS_PATH");
                    
                    // Priority 2: Local orig.dll (for when GAC is renamed)
                    if (string.IsNullOrEmpty(realWinformsPath) || !File.Exists(realWinformsPath))
                    {
                        string localOrigPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, LOCAL_ORIG_DLL);
                        if (File.Exists(localOrigPath))
                        {
                            realWinformsPath = localOrigPath;
                            ProxyLog.Write($"Using local orig.dll: {localOrigPath}");
                        }
                    }
                    
                    // Priority 3: GAC path
                    if (string.IsNullOrEmpty(realWinformsPath) || !File.Exists(realWinformsPath))
                    {
                        if (File.Exists(GAC_WINFORMS_PATH))
                        {
                            realWinformsPath = GAC_WINFORMS_PATH;
                        }
                    }

                    if (string.IsNullOrEmpty(realWinformsPath) || !File.Exists(realWinformsPath))
                    {
                        ProxyLog.Write($"ERROR: Real System.Windows.Forms.dll not found!");
                        ProxyLog.Write($"  Tried: local orig.dll, GAC, environment variable");
                        return;
                    }

                    ProxyLog.Write($"Pre-loading real assembly from: {realWinformsPath}");

                    // Load as bytes to avoid FileLoadException with TypeForwarders
                    byte[] asmBytes = File.ReadAllBytes(realWinformsPath);
                    _realWinFormsAssembly = Assembly.Load(asmBytes);

                    ProxyLog.Write($"Real assembly loaded: {_realWinFormsAssembly.FullName}");

                    StartAnalysisTimer();
                }
                catch (Exception ex)
                {
                    ProxyLog.Write($"FATAL ERROR pre-loading assembly: {ex}");
                }
            }
        }

        private static Assembly OnAssemblyResolve(object sender, ResolveEventArgs args)
        {
            // Prevent infinite recursion
            if (_isResolving) return null;

            try
            {
                _isResolving = true;

                ProxyLog.Write($"AssemblyResolve: '{args.Name}'");

                // Only handle System.Windows.Forms requests
                if (!args.Name.StartsWith("System.Windows.Forms,"))
                {
                    return null;
                }

                // Return the pre-loaded assembly
                if (_realWinFormsAssembly != null)
                {
                    ProxyLog.Write("Returning pre-loaded real assembly.");
                    return _realWinFormsAssembly;
                }

                ProxyLog.Write("WARNING: Real assembly not loaded yet!");
                return null;
            }
            finally
            {
                _isResolving = false;
            }
        }

        private static void StartAnalysisTimer()
        {
            if (_analysisTimerStarted) return;
            _analysisTimerStarted = true;

            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    ProxyLog.Write("Analysis timer started (5 second delay)...");
                    Thread.Sleep(5000);
                    ProxyLog.Write("Analysis complete.");

                    // Add your crackme analysis logic here
                    PerformAnalysis();
                }
                catch (Exception ex)
                {
                    ProxyLog.Write($"Analysis error: {ex}");
                }
            });
        }

        private static void PerformAnalysis()
        {
            try
            {
                ProxyLog.Write("=== CRACKME LOGIN ANALYSIS ===");
                
                // Find all open forms
                var formsType = _realWinFormsAssembly?.GetType("System.Windows.Forms.Form");
                var applicationClass = _realWinFormsAssembly?.GetType("System.Windows.Forms.Application");
                
                if (applicationClass != null)
                {
                    var openFormsProperty = applicationClass.GetProperty("OpenForms");
                    if (openFormsProperty != null)
                    {
                        var openForms = openFormsProperty.GetValue(null);
                        var countProperty = openForms?.GetType().GetProperty("Count");
                        int formCount = (int)(countProperty?.GetValue(openForms) ?? 0);
                        
                        ProxyLog.Write($"Found {formCount} open form(s)");
                        
                        // Enumerate all forms
                        for (int i = 0; i < formCount; i++)
                        {
                            var formItem = openForms.GetType().GetProperty("Item", new[] { typeof(int) });
                            var form = formItem?.GetValue(openForms, new object[] { i });
                            
                            if (form != null)
                            {
                                AnalyzeForm(form);
                            }
                        }
                    }
                }
                
                // Analyze all loaded assemblies for password/serial validation
                ProxyLog.Write("\n=== ANALYZING ASSEMBLIES FOR PASSWORD LOGIC ===");
                foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
                {
                    if (!asm.FullName.StartsWith("System") && !asm.FullName.StartsWith("mscorlib"))
                    {
                        ProxyLog.Write($"\n[Assembly: {asm.GetName().Name}]");
                        AnalyzeAssemblyForCredentials(asm);
                    }
                }
                
                ProxyLog.Write("\n=== ANALYSIS COMPLETE ===");
            }
            catch (Exception ex)
            {
                ProxyLog.Write($"Analysis exception: {ex}");
            }
        }
        
        private static void AnalyzeForm(object form)
        {
            try
            {
                var formType = form.GetType();
                ProxyLog.Write($"\n--- Form: {formType.Name} ---");
                ProxyLog.Write($"    Text: {formType.GetProperty("Text")?.GetValue(form)}");
                
                // Get all controls
                var controlsProperty = formType.GetProperty("Controls");
                if (controlsProperty != null)
                {
                    var controls = controlsProperty.GetValue(form);
                    AnalyzeControls(controls, "  ");
                }
                
                // Find all event handlers (especially Button clicks)
                ProxyLog.Write("  [Event Handlers]:");
                var events = formType.GetEvents(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
                foreach (var evt in events)
                {
                    if (evt.Name.Contains("Click") || evt.Name.Contains("Load"))
                    {
                        ProxyLog.Write($"    Event: {evt.Name}");
                    }
                }
                
                // Try to find password validation methods
                var methods = formType.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
                foreach (var method in methods)
                {
                    var methodName = method.Name.ToLower();
                    if (methodName.Contains("check") || methodName.Contains("valid") || 
                        methodName.Contains("login") || methodName.Contains("auth") ||
                        methodName.Contains("password") || methodName.Contains("serial"))
                    {
                        ProxyLog.Write($"  [IMPORTANT METHOD]: {method.Name}");
                        ProxyLog.Write($"    Return Type: {method.ReturnType.Name}");
                        ProxyLog.Write($"    Parameters: {string.Join(", ", method.GetParameters().Select(p => p.ParameterType.Name + " " + p.Name))}");
                    }
                }
            }
            catch (Exception ex)
            {
                ProxyLog.Write($"  Form analysis error: {ex.Message}");
            }
        }
        
        private static void AnalyzeControls(object controls, string indent)
        {
            try
            {
                if (controls == null) return;
                
                var controlsType = controls.GetType();
                var countProperty = controlsType.GetProperty("Count");
                int count = (int)(countProperty?.GetValue(controls) ?? 0);
                
                ProxyLog.Write($"{indent}[Controls: {count}]");
                
                for (int i = 0; i < count; i++)
                {
                    var itemProperty = controlsType.GetProperty("Item", new[] { typeof(int) });
                    var control = itemProperty?.GetValue(controls, new object[] { i });
                    
                    if (control != null)
                    {
                        var ctrlType = control.GetType();
                        var name = ctrlType.GetProperty("Name")?.GetValue(control);
                        var text = ctrlType.GetProperty("Text")?.GetValue(control);
                        
                        ProxyLog.Write($"{indent}  [{ctrlType.Name}] Name={name}, Text=\"{text}\"");
                        
                        // If it's a TextBox, log its current value
                        if (ctrlType.Name == "TextBox")
                        {
                            ProxyLog.Write($"{indent}    >>> TEXTBOX VALUE: \"{text}\"");
                        }
                        
                        // If it's a Button, try to find its Click handler
                        if (ctrlType.Name == "Button")
                        {
                            ProxyLog.Write($"{indent}    >>> BUTTON (potential login trigger)");
                        }
                        
                        // Recursively analyze child controls
                        var childControls = ctrlType.GetProperty("Controls")?.GetValue(control);
                        if (childControls != null)
                        {
                            var childCount = (int)(childControls.GetType().GetProperty("Count")?.GetValue(childControls) ?? 0);
                            if (childCount > 0)
                            {
                                AnalyzeControls(childControls, indent + "    ");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                ProxyLog.Write($"{indent}Controls analysis error: {ex.Message}");
            }
        }
        
        private static void AnalyzeAssemblyForCredentials(Assembly asm)
        {
            try
            {
                var types = asm.GetTypes();
                foreach (var type in types)
                {
                    // Look for string fields (potential hardcoded passwords)
                    var fields = type.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance);
                    foreach (var field in fields)
                    {
                        if (field.FieldType == typeof(string))
                        {
                            var fieldName = field.Name.ToLower();
                            if (fieldName.Contains("pass") || fieldName.Contains("key") || 
                                fieldName.Contains("serial") || fieldName.Contains("code") ||
                                fieldName.Contains("secret"))
                            {
                                try
                                {
                                    var value = field.IsStatic ? field.GetValue(null) : null;
                                    ProxyLog.Write($"  [POTENTIAL PASSWORD FIELD]: {type.Name}.{field.Name} = \"{value}\"");
                                }
                                catch { }
                            }
                        }
                    }
                    
                    // Look for string properties
                    var properties = type.GetProperties(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance);
                    foreach (var prop in properties)
                    {
                        if (prop.PropertyType == typeof(string) && prop.CanRead)
                        {
                            var propName = prop.Name.ToLower();
                            if (propName.Contains("pass") || propName.Contains("key") || 
                                propName.Contains("serial") || propName.Contains("code"))
                            {
                                try
                                {
                                    var getter = prop.GetGetMethod(true);
                                    if (getter?.IsStatic == true)
                                    {
                                        var value = prop.GetValue(null);
                                        ProxyLog.Write($"  [POTENTIAL PASSWORD PROPERTY]: {type.Name}.{prop.Name} = \"{value}\"");
                                    }
                                }
                                catch { }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                ProxyLog.Write($"  Assembly credential analysis error: {ex.Message}");
            }
        }
    }

    internal static class ProxyLog
    {
        private static readonly object LogLock = new object();
        private static readonly string LogPath;

        static ProxyLog()
        {
            try
            {
                LogPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "proxy_log.txt");
                // Clear old log on startup
                File.WriteAllText(LogPath, $"=== Proxy Log Started: {DateTime.Now} ==={Environment.NewLine}");
            }
            catch
            {
                LogPath = Path.Combine(Path.GetTempPath(), "proxy_log.txt");
            }
        }

        public static void Write(string message)
        {
            try
            {
                lock (LogLock)
                {
                    string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                    string line = $"[{timestamp}] {message}{Environment.NewLine}";
                    File.AppendAllText(LogPath, line);
                    Console.WriteLine(line); // Also write to console
                }
            }
            catch { /* Fail silently */ }
        }
    }
}
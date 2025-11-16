extern alias real;
using System;
using System.IO;
using System.Reflection;
using System.Diagnostics;
using System.Linq;
using System.Collections.Generic;

namespace RikaDrawingProxy
{
    // Module initializer - runs as SOON as assembly is loaded
    internal static class __ModuleInit
    {
        static __ModuleInit()
        {
            try
            {
                ProxyBootstrap.Touch();
            }
            catch (Exception ex)
            {
                File.WriteAllText("DRAWING_PROXY_ERROR.txt", 
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] MODULE INIT ERROR\n{ex}");
            }
        }
    }

    public static class ProxyBootstrap
    {
        private static bool _initialized = false;
        private static readonly object _lock = new object();
        private static string LogPath = "DRAWING_PROXY_LOG.txt";

        public static void Touch()
        {
            lock (_lock)
            {
                if (_initialized) return;
                _initialized = true;

                try
                {
                    Log("=== SYSTEM.DRAWING PROXY LOADED ===");
                    Log($"Process: {Process.GetCurrentProcess().ProcessName}");
                    Log($"PID: {Process.GetCurrentProcess().Id}");
                    Log($"Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    
                    PreloadRealAssembly();
                    
                    // Start analysis in background
                    System.Threading.ThreadPool.QueueUserWorkItem(_ => {
                        System.Threading.Thread.Sleep(2000); // Wait for app to initialize
                        PerformAnalysis();
                    });
                }
                catch (Exception ex)
                {
                    Log($"ERROR in Touch(): {ex}");
                }
            }
        }

        private static void Log(string message)
        {
            try
            {
                File.AppendAllText(LogPath, message + "\n");
            }
            catch { }
        }

        private static void PreloadRealAssembly()
        {
            try
            {
                // Check environment variable first
                string realDrawingPath = Environment.GetEnvironmentVariable("REAL_DRAWING_PATH");
                
                if (string.IsNullOrEmpty(realDrawingPath))
                {
                    string currentDir = AppDomain.CurrentDomain.BaseDirectory;
                    if (string.IsNullOrEmpty(currentDir))
                    {
                        currentDir = Path.GetDirectoryName(typeof(ProxyBootstrap).Assembly.Location);
                    }
                    if (!string.IsNullOrEmpty(currentDir))
                    {
                        realDrawingPath = Path.Combine(currentDir, "orig_drawing.dll");
                    }
                    
                    // If local orig.dll not found, try GAC path
                    if (!File.Exists(realDrawingPath))
                    {
                        string gacPath = @"C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Drawing\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Drawing.dll";
                        string gacBackup = gacPath + ".backup";
                        
                        if (File.Exists(gacBackup))
                        {
                            realDrawingPath = gacBackup;
                        }
                        else if (File.Exists(gacPath))
                        {
                            realDrawingPath = gacPath;
                        }
                    }
                }
                
                Log($"Loading real System.Drawing from: {realDrawingPath}");
                
                if (File.Exists(realDrawingPath))
                {
                    // Use Assembly.Load(byte[]) to avoid FileLoadException with TypeForwarders
                    byte[] asmBytes = File.ReadAllBytes(realDrawingPath);
                    Assembly loadedAsm = Assembly.Load(asmBytes);
                    Log($"Real System.Drawing loaded successfully: {loadedAsm.FullName}");
                }
                else
                {
                    Log($"ERROR: Could not find real System.Drawing at {realDrawingPath}");
                }
            }
            catch (Exception ex)
            {
                Log($"ERROR loading real assembly: {ex}");
            }
        }

        private static void PerformAnalysis()
        {
            try
            {
                Log("\n=== STARTING CRACKME ANALYSIS ===");
                
                var currentProcess = Process.GetCurrentProcess();
                Log($"Analyzing process: {currentProcess.ProcessName} (PID: {currentProcess.Id})");
                
                // Get all loaded assemblies
                var assemblies = AppDomain.CurrentDomain.GetAssemblies();
                Log($"\nLoaded assemblies: {assemblies.Length}");
                
                foreach (var asm in assemblies)
                {
                    try
                    {
                        string name = asm.GetName().Name;
                        if (name.Contains("Rika") || name.Contains("Crackme"))
                        {
                            Log($"\n>>> FOUND CRACKME ASSEMBLY: {name}");
                            AnalyzeAssembly(asm);
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"Error analyzing assembly: {ex.Message}");
                    }
                }
                
                // Wait for forms to be created
                System.Threading.Thread.Sleep(3000);
                AnalyzeForms();
                
                Log("\n=== ANALYSIS COMPLETE ===");
            }
            catch (Exception ex)
            {
                Log($"ERROR in PerformAnalysis: {ex}");
            }
        }

        private static void AnalyzeAssembly(Assembly asm)
        {
            try
            {
                Log($"\nAnalyzing types in {asm.GetName().Name}:");
                
                var types = asm.GetTypes();
                Log($"  Total types: {types.Length}");
                
                foreach (var type in types)
                {
                    try
                    {
                        // Look for Form types
                        if (type.BaseType != null && type.BaseType.Name.Contains("Form"))
                        {
                            Log($"\n  >>> FORM FOUND: {type.FullName}");
                            AnalyzeType(type);
                        }
                        
                        // Look for methods with interesting names
                        var methods = type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | 
                                                     BindingFlags.Static | BindingFlags.Instance);
                        
                        foreach (var method in methods)
                        {
                            string methodName = method.Name.ToLower();
                            if (methodName.Contains("check") || methodName.Contains("valid") || 
                                methodName.Contains("login") || methodName.Contains("password") ||
                                methodName.Contains("serial") || methodName.Contains("key"))
                            {
                                Log($"    >>> Interesting method: {type.Name}.{method.Name}");
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Log($"Error in AnalyzeAssembly: {ex.Message}");
            }
        }

        private static void AnalyzeType(Type type)
        {
            try
            {
                // Look for fields
                var fields = type.GetFields(BindingFlags.Public | BindingFlags.NonPublic | 
                                            BindingFlags.Static | BindingFlags.Instance);
                
                foreach (var field in fields)
                {
                    try
                    {
                        string fieldName = field.Name.ToLower();
                        if (fieldName.Contains("password") || fieldName.Contains("serial") || 
                            fieldName.Contains("key") || fieldName.Contains("textbox") ||
                            fieldName.Contains("txt") || fieldName.Contains("user"))
                        {
                            Log($"      Field: {field.Name} ({field.FieldType.Name})");
                        }
                    }
                    catch { }
                }
                
                // Look for properties
                var props = type.GetProperties(BindingFlags.Public | BindingFlags.NonPublic | 
                                              BindingFlags.Static | BindingFlags.Instance);
                
                foreach (var prop in props)
                {
                    try
                    {
                        string propName = prop.Name.ToLower();
                        if (propName.Contains("password") || propName.Contains("serial") || 
                            propName.Contains("key") || propName.Contains("text"))
                        {
                            Log($"      Property: {prop.Name} ({prop.PropertyType.Name})");
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Log($"Error in AnalyzeType: {ex.Message}");
            }
        }

        private static void AnalyzeForms()
        {
            try
            {
                Log("\n=== ANALYZING FORMS ===");
                
                // Use reflection to access System.Windows.Forms if it's loaded
                var winformsAsm = AppDomain.CurrentDomain.GetAssemblies()
                    .FirstOrDefault(a => a.GetName().Name == "System.Windows.Forms");
                
                if (winformsAsm == null)
                {
                    Log("System.Windows.Forms not loaded yet");
                    return;
                }
                
                var formType = winformsAsm.GetType("System.Windows.Forms.Form");
                var controlType = winformsAsm.GetType("System.Windows.Forms.Control");
                var textBoxType = winformsAsm.GetType("System.Windows.Forms.TextBox");
                
                if (formType == null)
                {
                    Log("Form type not found");
                    return;
                }
                
                // Find all Form instances
                var openFormsProperty = formType.GetProperty("OpenForms", 
                    BindingFlags.Public | BindingFlags.Static);
                
                if (openFormsProperty != null)
                {
                    var openForms = openFormsProperty.GetValue(null);
                    Log($"Found OpenForms collection");
                    
                    // Iterate through forms using reflection
                    var countProp = openForms.GetType().GetProperty("Count");
                    if (countProp != null)
                    {
                        int count = (int)countProp.GetValue(openForms);
                        Log($"Open forms count: {count}");
                        
                        var indexer = openForms.GetType().GetProperty("Item", new[] { typeof(int) });
                        for (int i = 0; i < count; i++)
                        {
                            var form = indexer.GetValue(openForms, new object[] { i });
                            Log($"\n  Form {i}: {form.GetType().FullName}");
                            AnalyzeFormControls(form, textBoxType, controlType);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Error in AnalyzeForms: {ex}");
            }
        }

        private static void AnalyzeFormControls(object form, Type textBoxType, Type controlType)
        {
            try
            {
                var controlsProp = form.GetType().GetProperty("Controls");
                if (controlsProp == null) return;
                
                var controls = controlsProp.GetValue(form);
                if (controls == null) return;
                
                var enumerator = controls.GetType().GetMethod("GetEnumerator").Invoke(controls, null) as System.Collections.IEnumerator;
                
                while (enumerator.MoveNext())
                {
                    var control = enumerator.Current;
                    var ctrlType = control.GetType();
                    
                    var nameProp = ctrlType.GetProperty("Name");
                    var textProp = ctrlType.GetProperty("Text");
                    
                    string name = nameProp?.GetValue(control)?.ToString() ?? "";
                    string text = textProp?.GetValue(control)?.ToString() ?? "";
                    
                    Log($"    Control: {ctrlType.Name} | Name: {name} | Text: {text}");
                    
                    // If it's a TextBox, try to get its value
                    if (textBoxType != null && textBoxType.IsAssignableFrom(ctrlType))
                    {
                        Log($"      >>> TEXTBOX: {name} = '{text}'");
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Error in AnalyzeFormControls: {ex.Message}");
            }
        }
    }
}

// Stub to trigger proxy loading
namespace System.Drawing
{
    public static class Graphics
    {
        static Graphics()
        {
            try
            {
                RikaDrawingProxy.ProxyBootstrap.Touch();
            }
            catch (Exception ex)
            {
                File.WriteAllText("DRAWING_BOOTSTRAP_ERROR.txt", 
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] BOOTSTRAP ERROR\n{ex}");
            }
        }
    }
}


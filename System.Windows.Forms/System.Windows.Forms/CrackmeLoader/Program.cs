using System;
using System.IO;
using System.Reflection;

namespace CrackmeLoader
{
    class Program
    {
        private static string LogFile = "LOADER_LOG.txt";
        
        static void Main(string[] args)
        {
            try
            {
                Log("=== CRACKME LOADER STARTED ===");
                Log($"Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                
                // Setup current directory
                string currentDir = AppDomain.CurrentDomain.BaseDirectory;
                Log($"Current directory: {currentDir}");
                
                // Force load our proxy DLLs FIRST
                Log("\n=== LOADING PROXY DLLs ===");
                ForceLoadProxyDlls(currentDir);
                
                // Setup assembly resolve handler
                AppDomain.CurrentDomain.AssemblyResolve += CurrentDomain_AssemblyResolve;
                Log("AssemblyResolve handler installed");
                
                // Load and execute crackme
                string crackmePath = Path.Combine(currentDir, "RikaCrackmeV1.exe");
                Log($"\n=== LOADING CRACKME: {crackmePath} ===");
                
                if (!File.Exists(crackmePath))
                {
                    Log($"ERROR: Crackme not found at {crackmePath}");
                    Console.WriteLine("ERROR: RikaCrackmeV1.exe not found!");
                    Console.ReadKey();
                    return;
                }
                
                // Load crackme assembly
                byte[] crackmeBytes = File.ReadAllBytes(crackmePath);
                Assembly crackmeAsm = Assembly.Load(crackmeBytes);
                Log($"Crackme loaded: {crackmeAsm.FullName}");
                
                // Get entry point
                MethodInfo entryPoint = crackmeAsm.EntryPoint;
                if (entryPoint == null)
                {
                    Log("ERROR: Entry point not found!");
                    Console.WriteLine("ERROR: Entry point not found!");
                    Console.ReadKey();
                    return;
                }
                
                Log($"Entry point: {entryPoint.DeclaringType.FullName}.{entryPoint.Name}");
                
                // Wait a bit for proxy initialization
                System.Threading.Thread.Sleep(500);
                
                Log("\n=== EXECUTING CRACKME ===");
                
                // Execute entry point
                object[] parameters = entryPoint.GetParameters().Length == 0 ? null : new object[] { new string[0] };
                entryPoint.Invoke(null, parameters);
                
                Log("\n=== CRACKME EXECUTION COMPLETE ===");
            }
            catch (Exception ex)
            {
                Log($"\n=== FATAL ERROR ===");
                Log($"{ex}");
                Console.WriteLine($"ERROR: {ex.Message}");
                Console.ReadKey();
            }
        }
        
        private static void ForceLoadProxyDlls(string currentDir)
        {
            try
            {
                // Load System.Drawing proxy first (it's loaded before System.Windows.Forms)
                string drawingPath = Path.Combine(currentDir, "System.Drawing.dll");
                if (File.Exists(drawingPath))
                {
                    Log($"Loading System.Drawing proxy from: {drawingPath}");
                    byte[] drawingBytes = File.ReadAllBytes(drawingPath);
                    Assembly drawingAsm = Assembly.Load(drawingBytes);
                    Log($"  Loaded: {drawingAsm.FullName}");
                    
                    // Trigger static constructor
                    try
                    {
                        Type graphicsType = drawingAsm.GetType("System.Drawing.Graphics");
                        if (graphicsType != null)
                        {
                            System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(graphicsType.TypeHandle);
                            Log("  System.Drawing.Graphics static constructor triggered");
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"  Warning triggering static constructor: {ex.Message}");
                    }
                }
                else
                {
                    Log($"WARNING: System.Drawing.dll not found at {drawingPath}");
                }
                
                // Load System.Windows.Forms proxy
                string winformsPath = Path.Combine(currentDir, "System.Windows.Forms.dll");
                if (File.Exists(winformsPath))
                {
                    Log($"Loading System.Windows.Forms proxy from: {winformsPath}");
                    byte[] winformsBytes = File.ReadAllBytes(winformsPath);
                    Assembly winformsAsm = Assembly.Load(winformsBytes);
                    Log($"  Loaded: {winformsAsm.FullName}");
                    
                    // Trigger static constructor
                    try
                    {
                        Type appType = winformsAsm.GetType("System.Windows.Forms.Application");
                        if (appType != null)
                        {
                            System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(appType.TypeHandle);
                            Log("  System.Windows.Forms.Application static constructor triggered");
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"  Warning triggering static constructor: {ex.Message}");
                    }
                }
                else
                {
                    Log($"WARNING: System.Windows.Forms.dll not found at {winformsPath}");
                }
            }
            catch (Exception ex)
            {
                Log($"ERROR in ForceLoadProxyDlls: {ex}");
            }
        }
        
        private static Assembly CurrentDomain_AssemblyResolve(object sender, ResolveEventArgs args)
        {
            try
            {
                Log($"\n[AssemblyResolve] Requested: {args.Name}");
                
                string assemblyName = new AssemblyName(args.Name).Name;
                string currentDir = AppDomain.CurrentDomain.BaseDirectory;
                
                // Check for our proxy DLLs
                if (assemblyName == "System.Drawing" || assemblyName == "System.Windows.Forms")
                {
                    string dllPath = Path.Combine(currentDir, assemblyName + ".dll");
                    if (File.Exists(dllPath))
                    {
                        Log($"  Loading from: {dllPath}");
                        byte[] asmBytes = File.ReadAllBytes(dllPath);
                        Assembly asm = Assembly.Load(asmBytes);
                        Log($"  Loaded: {asm.FullName}");
                        return asm;
                    }
                }
                
                Log($"  Not found, returning null");
                return null;
            }
            catch (Exception ex)
            {
                Log($"  ERROR in AssemblyResolve: {ex.Message}");
                return null;
            }
        }
        
        private static void Log(string message)
        {
            try
            {
                File.AppendAllText(LogFile, message + "\n");
                Console.WriteLine(message);
            }
            catch { }
        }
    }
}


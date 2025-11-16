using System;
using System.IO;
using System.Reflection;
using System.Diagnostics;

/// <summary>
/// Launcher that forces RikaCrackmeV1.exe to load our proxy System.Windows.Forms.dll
/// instead of the GAC version
/// </summary>
class ProxyLauncher
{
    static void Main()
    {
        Console.WriteLine("=== RikaCrackme Proxy DLL Launcher ===");
        Console.WriteLine();
        
        // Setup AssemblyResolve BEFORE loading the crackme
        AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
        {
            var asmName = new AssemblyName(args.Name);
            
            Console.WriteLine("[Resolve] " + asmName.Name);
            
            // Force our proxy DLL for System.Windows.Forms
            if (asmName.Name == "System.Windows.Forms")
            {
                string proxyPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "System.Windows.Forms.dll");
                
                if (File.Exists(proxyPath))
                {
                    Console.WriteLine("  -> Loading PROXY DLL: " + proxyPath);
                    return Assembly.LoadFrom(proxyPath);
                }
            }
            
            return null;
        };
        
        try
        {
            Console.WriteLine("Loading RikaCrackmeV1.exe...");
            Console.WriteLine();
            
            string crackmeExe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "RikaCrackmeV1.exe");
            
            if (!File.Exists(crackmeExe))
            {
                Console.WriteLine("ERROR: RikaCrackmeV1.exe not found!");
                Console.ReadLine();
                return;
            }
            
            // Load the crackme assembly
            Assembly crackmeAsm = Assembly.LoadFrom(crackmeExe);
            
            Console.WriteLine("Loaded: " + crackmeAsm.FullName);
            Console.WriteLine();
            
            // Get entry point
            MethodInfo entryPoint = crackmeAsm.EntryPoint;
            
            if (entryPoint == null)
            {
                Console.WriteLine("ERROR: No entry point found!");
                Console.ReadLine();
                return;
            }
            
            Console.WriteLine("Entry Point: " + entryPoint.DeclaringType.FullName + "." + entryPoint.Name);
            Console.WriteLine();
            Console.WriteLine("Starting crackme in 2 seconds...");
            Console.WriteLine("(Wait 5 more seconds after it opens for analysis to complete)");
            Console.WriteLine();
            
            System.Threading.Thread.Sleep(2000);
            
            // Invoke entry point
            object[] parameters = entryPoint.GetParameters().Length == 0 ? null : new object[] { new string[0] };
            entryPoint.Invoke(null, parameters);
            
            Console.WriteLine();
            Console.WriteLine("Crackme closed.");
            
            // Show log if exists
            string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "proxy_log.txt");
            if (File.Exists(logPath))
            {
                Console.WriteLine();
                Console.WriteLine("=== PROXY LOG CONTENT ===");
                Console.WriteLine(File.ReadAllText(logPath));
                Console.WriteLine("=== END OF LOG ===");
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("WARNING: No proxy_log.txt found!");
                Console.WriteLine("The GAC version might still be loading.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine();
            Console.WriteLine("ERROR: " + ex.Message);
            Console.WriteLine();
            Console.WriteLine("Stack Trace:");
            Console.WriteLine(ex.StackTrace);
        }
        
        Console.WriteLine();
        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }
}


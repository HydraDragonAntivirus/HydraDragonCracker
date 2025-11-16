using System;
using System.IO;
using System.Reflection;

// AppDomain-based loader - Forces our proxy DLL without touching GAC
class ProxyLoader
{
    static void Main()
    {
        Console.WriteLine("=== PROXY LOADER - GodMode Obfuscation Cracker ===");
        Console.WriteLine();
        
        // Create isolated AppDomain with our assembly resolver
        AppDomainSetup setup = new AppDomainSetup
        {
            ApplicationBase = AppDomain.CurrentDomain.BaseDirectory,
            PrivateBinPath = AppDomain.CurrentDomain.BaseDirectory
        };
        
        AppDomain domain = AppDomain.CreateDomain("CrackmeIsolated", null, setup);
        
        // Hook assembly resolver BEFORE loading crackme
        domain.AssemblyResolve += (sender, args) =>
        {
            Console.WriteLine($"[AssemblyResolve] {args.Name}");
            
            // Force our proxy DLL for System.Windows.Forms
            if (args.Name.StartsWith("System.Windows.Forms,"))
            {
                string proxyPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "System.Windows.Forms.dll");
                
                if (File.Exists(proxyPath))
                {
                    Console.WriteLine($"  >>> Loading PROXY from: {proxyPath}");
                    byte[] bytes = File.ReadAllBytes(proxyPath);
                    return Assembly.Load(bytes);
                }
            }
            
            return null;
        };
        
        try
        {
            Console.WriteLine("Loading RikaCrackmeV1.exe in isolated AppDomain...");
            
            // Load crackme in isolated domain
            string crackmePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "RikaCrackmeV1.exe");
            byte[] crackmeBytes = File.ReadAllBytes(crackmePath);
            
            Assembly crackmeAsm = domain.Load(crackmeBytes);
            
            Console.WriteLine($"Crackme loaded: {crackmeAsm.FullName}");
            Console.WriteLine();
            Console.WriteLine("Executing crackme entry point...");
            Console.WriteLine("Check proxy_log.txt for analysis results!");
            Console.WriteLine();
            
            // Execute entry point
            MethodInfo entryPoint = crackmeAsm.EntryPoint;
            if (entryPoint != null)
            {
                object[] parameters = entryPoint.GetParameters().Length == 0 ? null : new object[] { new string[] { } };
                domain.DoCallBack(() =>
                {
                    entryPoint.Invoke(null, parameters);
                });
            }
            
            Console.WriteLine();
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
            Console.ReadKey();
        }
        finally
        {
            AppDomain.Unload(domain);
        }
    }
}


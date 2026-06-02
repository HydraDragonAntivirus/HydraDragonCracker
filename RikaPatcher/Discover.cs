// Keşif modu: DLL içindeki tüm tipleri, metodları ve interface implementasyonlarını listele
// Kullanım: dotnet run -- --discover <dll_yolu>
//           dotnet run -- --fields <dll_yolu>

using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

static class Discover
{
    static readonly string[] SmTargets = ["d__13", "d__14", "d__28", "d__29", "d__41", "d__47"];

    public static void DumpFields(string dllPath)
    {
        Console.WriteLine($"=== FIELD DUMP: {Path.GetFileName(dllPath)} ===\n");
        var module = ModuleDefMD.Load(dllPath, new ModuleCreationOptions { TryToLoadPdbFromDisk = false });

        foreach (var type in module.GetTypes())
        {
            if (!SmTargets.Any(t => type.Name.String.Contains(t))) continue;

            Console.WriteLine($"\n[TYPE] {type.FullName}");
            foreach (var f in type.Fields)
                Console.WriteLine($"  FIELD [{f.Name}] : {f.FieldType.FullName}");
            foreach (var m in type.Methods)
                Console.WriteLine($"  METHOD [{m.Name}] ret={m.MethodSig?.RetType?.TypeName} body={m.HasBody}");
        }
    }

    public static void Run(string dllPath)
    {
        Console.WriteLine($"=== KEŞIF: {Path.GetFileName(dllPath)} ===\n");

        var module = ModuleDefMD.Load(dllPath, new ModuleCreationOptions
        {
            TryToLoadPdbFromDisk = false,
        });

        // 1. IAuthenticationService implement eden tipler
        Console.WriteLine("--- IAuthenticationService implementasyonları ---");
        foreach (var type in module.GetTypes())
        {
            bool impl = type.Interfaces.Any(i =>
                i.Interface.Name.String.Contains("IAuthentication") ||
                i.Interface.FullName.Contains("IAuthentication"));

            if (!impl) continue;

            Console.WriteLine($"  TYPE: {type.FullName}");
            foreach (var m in type.Methods)
                Console.WriteLine($"    METHOD: {m.Name} | HasBody: {m.HasBody}");
        }

        // 2. AuthResult ve AuthBootstrapState tipleri
        Console.WriteLine("\n--- AuthResult / AuthBootstrapState tipleri ---");
        foreach (var type in module.GetTypes())
        {
            if (type.Name.String.Contains("AuthResult") ||
                type.Name.String.Contains("AuthBootstrap") ||
                type.Name.String.Contains("AuthBoot"))
            {
                Console.WriteLine($"  TYPE: {type.FullName}");
                foreach (var m in type.Methods)
                    Console.WriteLine($"    METHOD: {m.Name} | IsSpecial: {m.IsSpecialName}");
                foreach (var p in type.Properties)
                    Console.WriteLine($"    PROP:   {p.Name} : {p.PropertySig?.RetType}");
            }
        }

        // 3. Async state machine'ler: AuthResult veya AuthBootstrap referans edenler
        Console.WriteLine("\n--- AuthResult/AuthBootstrap kullanan state machine'ler ---");
        foreach (var type in module.GetTypes())
        {
            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;

                bool ref1 = method.Body.Instructions.Any(i =>
                    i.Operand is ITypeDefOrRef t &&
                    (t.Name.String.Contains("AuthResult") || t.Name.String.Contains("AuthBootstrap")));

                bool ref2 = method.Body.Instructions.Any(i =>
                    i.Operand is MemberRef mr &&
                    (mr.DeclaringType?.Name.String.Contains("AuthResult") == true ||
                     mr.DeclaringType?.Name.String.Contains("AuthBootstrap") == true));

                if (!ref1 && !ref2) continue;

                Console.WriteLine($"  TYPE: {type.FullName}");
                Console.WriteLine($"    METHOD: {method.Name}");

                // IL dump
                foreach (var instr in method.Body.Instructions.Take(30))
                    Console.WriteLine($"      {instr}");

                Console.WriteLine($"      ... (toplam {method.Body.Instructions.Count} instr)");
                break; // her tip için bir kez
            }
        }

        // 4. Tüm tipleri say
        var allTypes = module.GetTypes().ToList();
        Console.WriteLine($"\n--- ÖZET ---");
        Console.WriteLine($"Toplam tip: {allTypes.Count}");
        Console.WriteLine($"Namespace'ler:");
        foreach (var ns in allTypes.Select(t => t.Namespace.String).Distinct().OrderBy(x => x))
            Console.WriteLine($"  {(string.IsNullOrEmpty(ns) ? "<global>" : ns)}");
    }
}

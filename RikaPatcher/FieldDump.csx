// Belirli state machine tiplerinin field'larını listele
using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;

var dllPath = args.Length > 0 ? args[0] : @"..\Rika Inc\Rika.NET\RikaNET.WinUI.dll";
var module = ModuleDefMD.Load(dllPath);

string[] targets = [
    "d__13", "d__14", "d__28", "d__29", "d__41", "d__47"
];

foreach (var type in module.GetTypes())
{
    if (!targets.Any(t => type.Name.String.Contains(t))) continue;
    
    Console.WriteLine($"\n=== {type.FullName} ===");
    Console.WriteLine("  FIELDS:");
    foreach (var f in type.Fields)
        Console.WriteLine($"    [{f.Name}] : {f.FieldType.TypeName}  | FullType: {f.FieldType.FullName}");
    
    Console.WriteLine("  METHODS:");
    foreach (var m in type.Methods)
        Console.WriteLine($"    [{m.Name}] HasBody:{m.HasBody} RetType:{m.MethodSig?.RetType?.TypeName}");
}

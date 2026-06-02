using System;
using System.IO;
using System.Linq;
using System.Reflection;

// dnlib.real.dll yolunu hesapla (proje kökünden göreceli)
var baseDir = AppContext.BaseDirectory;
var dllPath = Path.GetFullPath(Path.Combine(baseDir, @"..\..\..\..\..\dnlib\dnlib\dnlib.real.dll"));

if (!File.Exists(dllPath))
{
    Console.Error.WriteLine($"DLL bulunamadı: {dllPath}");
    Environment.Exit(1);
}

Console.Error.WriteLine($"Yükleniyor: {dllPath}");

Assembly asm;
try
{
    asm = Assembly.LoadFrom(dllPath);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Yükleme hatası: {ex.Message}");
    Environment.Exit(1);
    return;
}

// Tüm public interface tiplerini al
var interfaces = asm.GetExportedTypes()
    .Where(t => t.IsInterface)
    .OrderBy(t => t.FullName)
    .ToArray();

Console.Error.WriteLine($"Bulunan interface sayısı: {interfaces.Length}");

var outputPath = Path.Combine(AppContext.BaseDirectory, "interface_forwarders.txt");
using var writer = new StreamWriter(outputPath);

foreach (var iface in interfaces)
{
    string fullName = iface.FullName!;
    
    // Generic type ise backtick notasyonunu köşeli parantez formatına çevir
    // Örn: dnlib.DotNet.IList`1 → dnlib.DotNet.IList<>
    string formatted = FormatTypeName(iface);
    
    string line = $"[assembly: global::System.Runtime.CompilerServices.TypeForwardedTo(typeof(real.{formatted}))]";
    writer.WriteLine(line);
    Console.WriteLine(line);
}

Console.Error.WriteLine($"Çıktı kaydedildi: {outputPath}");

static string FormatTypeName(Type t)
{
    if (!t.IsGenericTypeDefinition)
        return t.FullName!.Replace("+", ".");

    // Generic tip: backtick'ten önceki kısmı al, sonra <,,,> ekle
    var fullName = t.FullName!;
    var backtickIdx = fullName.IndexOf('`');
    if (backtickIdx < 0)
        return fullName.Replace("+", ".");

    var baseName = fullName[..backtickIdx].Replace("+", ".");
    int arity = t.GetGenericArguments().Length;
    var commas = new string(',', arity - 1);
    return $"{baseName}<{commas}>";
}

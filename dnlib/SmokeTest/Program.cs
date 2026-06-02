using System;
using dnlib.DotNet;

Console.WriteLine("dnlib type assembly: " + typeof(ModuleDefMD).Assembly.FullName);

using var module = ModuleDefMD.Load(typeof(Program).Assembly.Location);
Console.WriteLine("loaded module: " + module.Name);

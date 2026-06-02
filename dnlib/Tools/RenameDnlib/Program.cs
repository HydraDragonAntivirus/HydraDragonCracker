using System;
using System.IO;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

if (args.Length != 3)
{
    Console.Error.WriteLine("Usage: RenameDnlib <input-dll> <new-assembly-name> <output-dll>");
    return 2;
}

var inputPath = Path.GetFullPath(args[0]);
var newAssemblyName = args[1];
var outputPath = Path.GetFullPath(args[2]);

if (!File.Exists(inputPath))
{
    Console.Error.WriteLine("Input DLL not found: " + inputPath);
    return 3;
}

Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);

using var module = ModuleDefMD.Load(inputPath);
if (module.Assembly is null)
{
    Console.Error.WriteLine("Input DLL has no assembly definition: " + inputPath);
    return 4;
}

module.Assembly.Name = newAssemblyName;
module.Name = Path.GetFileName(outputPath);
InjectLoadLog(module);

var options = new ModuleWriterOptions(module)
{
    Logger = DummyLogger.NoThrowInstance
};

module.Write(outputPath, options);
Console.WriteLine("Wrote " + outputPath + " as assembly " + module.Assembly.FullName);
return 0;

static void InjectLoadLog(ModuleDef module)
{
    var globalType = module.GlobalType;
    if (globalType is null)
        return;

    var cctor = globalType.FindStaticConstructor();
    if (cctor is null)
    {
        cctor = new MethodDefUser(
            ".cctor",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            dnlib.DotNet.MethodImplAttributes.IL | dnlib.DotNet.MethodImplAttributes.Managed,
            dnlib.DotNet.MethodAttributes.Private | dnlib.DotNet.MethodAttributes.Static | dnlib.DotNet.MethodAttributes.SpecialName | dnlib.DotNet.MethodAttributes.RTSpecialName);
        globalType.Methods.Add(cctor);
    }

    cctor.Body ??= new CilBody();
    cctor.Body.InitLocals = true;

    var instructions = cctor.Body.Instructions;
    if (instructions.Count == 0)
        instructions.Add(Instruction.Create(OpCodes.Ret));

    var firstOriginalInstruction = instructions[0];
    var ret = Instruction.Create(OpCodes.Nop);
    var tryStart = Instruction.Create(OpCodes.Call, module.Import(typeof(AppContext).GetProperty(nameof(AppContext.BaseDirectory))!.GetMethod!));
    var handlerStart = Instruction.Create(OpCodes.Pop);

    var injected = new[]
    {
        tryStart,
        Instruction.Create(OpCodes.Ldstr, "dnlib_proxy_log.txt"),
        Instruction.Create(OpCodes.Call, module.Import(typeof(Path).GetMethod(nameof(Path.Combine), new[] { typeof(string), typeof(string) })!)),
        Instruction.Create(OpCodes.Ldstr, "[dnlib.real] loaded through dnlib proxy" + Environment.NewLine),
        Instruction.Create(OpCodes.Call, module.Import(typeof(File).GetMethod(nameof(File.AppendAllText), new[] { typeof(string), typeof(string) })!)),
        Instruction.Create(OpCodes.Ldstr, "DnlibProxy.ProxyBootstrap, dnlib"),
        Instruction.Create(OpCodes.Ldc_I4_0),
        Instruction.Create(OpCodes.Call, module.Import(typeof(Type).GetMethod(nameof(Type.GetType), new[] { typeof(string), typeof(bool) })!)),
        Instruction.Create(OpCodes.Ldstr, "Touch"),
        Instruction.Create(OpCodes.Ldc_I4, (int)(BindingFlags.Public | BindingFlags.Static)),
        Instruction.Create(OpCodes.Callvirt, module.Import(typeof(Type).GetMethod(nameof(Type.GetMethod), new[] { typeof(string), typeof(BindingFlags) })!)),
        Instruction.Create(OpCodes.Ldnull),
        Instruction.Create(OpCodes.Ldnull),
        Instruction.Create(OpCodes.Callvirt, module.Import(typeof(MethodBase).GetMethod(nameof(MethodBase.Invoke), new[] { typeof(object), typeof(object[]) })!)),
        Instruction.Create(OpCodes.Pop),
        Instruction.Create(OpCodes.Leave_S, ret),
        handlerStart,
        Instruction.Create(OpCodes.Leave_S, ret),
        ret
    };

    for (var i = injected.Length - 1; i >= 0; i--)
        instructions.Insert(0, injected[i]);

    cctor.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
    {
        CatchType = module.Import(typeof(Exception)),
        TryStart = tryStart,
        TryEnd = handlerStart,
        HandlerStart = handlerStart,
        HandlerEnd = ret
    });

    instructions.Insert(instructions.IndexOf(ret) + 1, Instruction.Create(OpCodes.Br_S, firstOriginalInstruction));
}

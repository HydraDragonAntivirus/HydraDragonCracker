// RikaNET.WinUI.dll License Patcher
// Field dump sonuçlarına göre:
//   wkj=.Dhr=/<SignInAsync>d__14       : <>t__builder = AsyncTaskMethodBuilder`1<AuthResult>
//   wkj=.Dhr=/<InitializeAsync>d__13   : <>t__builder = AsyncTaskMethodBuilder`1<AuthBootstrapState>
//   wkj=.Dhr=/...ResetHardwareId d__29 : <>t__builder = AsyncTaskMethodBuilder`1<AuthResult>
//   LoginViewModel/<SignInAsync>d__47   : <>t__builder = AsyncTaskMethodBuilder (non-generic)
//   LoginViewModel/<InitializeAsync>d__41: <>t__builder = AsyncTaskMethodBuilder (non-generic)

using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

class Program
{
    static int Main(string[] args)
    {
        if (args.Length >= 2 && args[0] == "--discover")
        {
            Discover.Run(args[1]);
            return 0;
        }

        if (args.Length >= 2 && args[0] == "--fields")
        {
            Discover.DumpFields(args[1]);
            return 0;
        }

        string dllPath = args.Length > 0
            ? args[0]
            : Path.Combine("..", "Rika Inc", "Rika.NET", "RikaNET.WinUI.dll");

        string coreDllPath = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(dllPath))!, "RikaNET.Core.dll");

        if (!File.Exists(dllPath))  { Console.Error.WriteLine($"[!] WinUI DLL yok: {dllPath}"); return 1; }
        if (!File.Exists(coreDllPath)) { Console.Error.WriteLine($"[!] Core DLL yok: {coreDllPath}"); return 1; }

        Console.WriteLine($"[*] WinUI: {dllPath}");
        Console.WriteLine($"[*] Core:  {coreDllPath}");

        var coreModule = ModuleDefMD.Load(coreDllPath, new ModuleCreationOptions { TryToLoadPdbFromDisk = false });
        var winuiModule = ModuleDefMD.Load(dllPath, new ModuleCreationOptions { TryToLoadPdbFromDisk = false });

        var authResultType  = FindType(coreModule, "RikaNET.Core.Models.AuthResult")!;
        var bootstrapType   = FindType(coreModule, "RikaNET.Core.Models.AuthBootstrapState")!;

        if (authResultType == null || bootstrapType == null)
        {
            Console.Error.WriteLine("[!] Core model tipleri bulunamadı."); return 1;
        }

        int patchCount = 0;

        foreach (var type in winuiModule.GetTypes())
        {
            string tn = type.FullName;

            // 1. wkj=.Dhr=/<SignInAsync>d__14  →  MoveNext
            if (tn.Contains("Dhr=") && tn.Contains("SignInAsync") && tn.Contains("d__"))
            {
                var mv = type.Methods.FirstOrDefault(m => m.Name == "MoveNext" && m.HasBody);
                if (mv != null)
                {
                    Console.WriteLine($"[*] SignIn (wkj) SM: {tn}");
                    PatchWithAuthResult(winuiModule, coreModule, mv, authResultType, isSuccess: true, days: 9999, plan: "Enterprise");
                    patchCount++;
                }
            }

            // 2. wkj=.Dhr=/<InitializeAsync>d__13  →  MoveNext
            if (tn.Contains("Dhr=") && tn.Contains("InitializeAsync") && tn.Contains("d__"))
            {
                var mv = type.Methods.FirstOrDefault(m => m.Name == "MoveNext" && m.HasBody);
                if (mv != null)
                {
                    Console.WriteLine($"[*] Initialize (wkj) SM: {tn}");
                    PatchWithBootstrap(winuiModule, coreModule, mv, bootstrapType);
                    patchCount++;
                }
            }

            // 3. wkj=.Dhr=/...ResetHardwareId...d__29  →  MoveNext
            if (tn.Contains("Dhr=") && tn.Contains("ResetHardware") && tn.Contains("d__"))
            {
                var mv = type.Methods.FirstOrDefault(m => m.Name == "MoveNext" && m.HasBody);
                if (mv != null)
                {
                    Console.WriteLine($"[*] ResetHWID (wkj) SM: {tn}");
                    PatchWithAuthResult(winuiModule, coreModule, mv, authResultType, isSuccess: true, days: 9999, plan: "Enterprise");
                    patchCount++;
                }
            }

            // 4. LoginViewModel/<SignInAsync>d__47  →  MoveNext (void, non-generic builder)
            if (tn.Contains("LoginViewModel") && tn.Contains("SignInAsync") && tn.Contains("d__"))
            {
                var mv = type.Methods.FirstOrDefault(m => m.Name == "MoveNext" && m.HasBody);
                if (mv != null)
                {
                    Console.WriteLine($"[*] SignIn (LoginVM) SM: {tn}");
                    PatchLoginVMSignIn(winuiModule, coreModule, mv, type, authResultType);
                    patchCount++;
                }
            }

            // 5. LoginViewModel/<InitializeAsync>d__41  →  MoveNext (void, non-generic builder)
            if (tn.Contains("LoginViewModel") && tn.Contains("InitializeAsync") && tn.Contains("d__"))
            {
                var mv = type.Methods.FirstOrDefault(m => m.Name == "MoveNext" && m.HasBody);
                if (mv != null)
                {
                    Console.WriteLine($"[*] Initialize (LoginVM) SM: {tn}");
                    PatchLoginVMInitialize(winuiModule, coreModule, mv, type, bootstrapType);
                    patchCount++;
                }
            }
        }

        Console.WriteLine($"\n[*] Toplam {patchCount} patch uygulandı.");
        if (patchCount == 0) { Console.Error.WriteLine("[!] Patch uygulanamadı!"); return 1; }

        string outPath = Path.Combine(
            Path.GetDirectoryName(Path.GetFullPath(dllPath))!,
            Path.GetFileNameWithoutExtension(dllPath) + ".patched.dll");

        winuiModule.Write(outPath, new ModuleWriterOptions(winuiModule)
        {
            MetadataOptions = { Flags = MetadataFlags.PreserveAll },
        });

        Console.WriteLine($"\n[+] Yazıldı: {outPath}");
        Console.WriteLine($"[+] Uygulamak için:");
        Console.WriteLine($"    copy \"{outPath}\" \"{Path.GetFullPath(dllPath)}\"");
        return 0;
    }

    // ─── wkj= state machine patch: generic builder, Task<T> SetResult ───────────

    static void PatchWithAuthResult(
        ModuleDef wm, ModuleDef cm, MethodDef method, TypeDef authResultType,
        bool isSuccess, int days, string plan)
    {
        var decl = method.DeclaringType;

        // <>t__builder : AsyncTaskMethodBuilder`1<AuthResult>
        var builderField = decl.Fields.FirstOrDefault(f =>
            f.Name.String == "<>t__builder" &&
            f.FieldType.FullName.Contains("AuthResult"));

        var stateField = decl.Fields.FirstOrDefault(f => f.Name.String == "<>1__state");

        if (builderField == null)
        {
            Console.Error.WriteLine($"  [!] builder field bulunamadı: {decl.FullName}");
            return;
        }

        var ctor             = wm.Import(authResultType.FindDefaultConstructor());
        var setIsSuccess     = wm.Import(FindSetter(authResultType, "IsSuccess")!);
        var setRemainingDays = FindSetter(authResultType, "RemainingDays");
        var setPlanType      = FindSetter(authResultType, "PlanType");

        var body = method.Body;
        body.Instructions.Clear();
        body.ExceptionHandlers.Clear();
        body.Variables.Clear();

        var local = new Local(wm.Import(authResultType).ToTypeSig());
        body.Variables.Add(local);

        var il = body.Instructions;

        // state = -2
        if (stateField != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldarg_0));
            il.Add(Instruction.Create(OpCodes.Ldc_I4, -2));
            il.Add(Instruction.Create(OpCodes.Stfld, stateField));
        }

        // var result = new AuthResult()
        il.Add(Instruction.Create(OpCodes.Newobj, ctor));
        il.Add(Instruction.Create(OpCodes.Stloc, local));

        // result.IsSuccess = true
        il.Add(Instruction.Create(OpCodes.Ldloc, local));
        il.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Add(Instruction.Create(OpCodes.Call, setIsSuccess));

        // result.RemainingDays = new int?(9999)
        if (setRemainingDays != null)
        {
            var nullableIntCtor = MakeNullableIntCtor(wm);
            il.Add(Instruction.Create(OpCodes.Ldloc, local));
            il.Add(Instruction.Create(OpCodes.Ldc_I4, days));
            if (nullableIntCtor != null)
                il.Add(Instruction.Create(OpCodes.Newobj, nullableIntCtor));
            il.Add(Instruction.Create(OpCodes.Call, wm.Import(setRemainingDays)));
        }

        // result.PlanType = "Enterprise"
        if (setPlanType != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldloc, local));
            il.Add(Instruction.Create(OpCodes.Ldstr, plan));
            il.Add(Instruction.Create(OpCodes.Call, wm.Import(setPlanType)));
        }

        // builder.SetResult(result)
        var setResult = ResolveSetResult(wm, builderField);
        if (setResult != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldarg_0));
            il.Add(Instruction.Create(OpCodes.Ldflda, builderField));
            il.Add(Instruction.Create(OpCodes.Ldloc, local));
            il.Add(Instruction.Create(OpCodes.Call, setResult));
        }

        il.Add(Instruction.Create(OpCodes.Ret));
        body.SimplifyBranches();
        Console.WriteLine($"  [+] AuthResult patched: IsSuccess=true, RemainingDays={days}, PlanType={plan}");
    }

    static void PatchWithBootstrap(
        ModuleDef wm, ModuleDef cm, MethodDef method, TypeDef bootstrapType)
    {
        var decl = method.DeclaringType;

        var builderField = decl.Fields.FirstOrDefault(f =>
            f.Name.String == "<>t__builder" &&
            f.FieldType.FullName.Contains("AuthBootstrap"));

        var stateField = decl.Fields.FirstOrDefault(f => f.Name.String == "<>1__state");

        if (builderField == null)
        {
            Console.Error.WriteLine($"  [!] builder field bulunamadı: {decl.FullName}");
            return;
        }

        var ctor              = wm.Import(bootstrapType.FindDefaultConstructor());
        var setIsReady        = wm.Import(FindSetter(bootstrapType, "IsReady")!);
        var setRequiresUpdate = FindSetter(bootstrapType, "RequiresUpdate");
        var setCachedLicense  = FindSetter(bootstrapType, "CachedLicense");
        var setMessage        = FindSetter(bootstrapType, "Message");

        var body = method.Body;
        body.Instructions.Clear();
        body.ExceptionHandlers.Clear();
        body.Variables.Clear();

        var local = new Local(wm.Import(bootstrapType).ToTypeSig());
        body.Variables.Add(local);

        var il = body.Instructions;

        if (stateField != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldarg_0));
            il.Add(Instruction.Create(OpCodes.Ldc_I4, -2));
            il.Add(Instruction.Create(OpCodes.Stfld, stateField));
        }

        il.Add(Instruction.Create(OpCodes.Newobj, ctor));
        il.Add(Instruction.Create(OpCodes.Stloc, local));

        il.Add(Instruction.Create(OpCodes.Ldloc, local));
        il.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Add(Instruction.Create(OpCodes.Call, setIsReady));

        if (setRequiresUpdate != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldloc, local));
            il.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(OpCodes.Call, wm.Import(setRequiresUpdate)));
        }

        if (setCachedLicense != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldloc, local));
            il.Add(Instruction.Create(OpCodes.Ldstr, "RIKA-0000-0000-0000"));
            il.Add(Instruction.Create(OpCodes.Call, wm.Import(setCachedLicense)));
        }

        if (setMessage != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldloc, local));
            il.Add(Instruction.Create(OpCodes.Ldnull));
            il.Add(Instruction.Create(OpCodes.Call, wm.Import(setMessage)));
        }

        var setResult = ResolveSetResult(wm, builderField);
        if (setResult != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldarg_0));
            il.Add(Instruction.Create(OpCodes.Ldflda, builderField));
            il.Add(Instruction.Create(OpCodes.Ldloc, local));
            il.Add(Instruction.Create(OpCodes.Call, setResult));
        }

        il.Add(Instruction.Create(OpCodes.Ret));
        body.SimplifyBranches();
        Console.WriteLine($"  [+] AuthBootstrapState patched: IsReady=true, CachedLicense=RIKA-0000-0000-0000");
    }

    // ─── LoginViewModel SM'leri: non-generic builder, async Task (void result) ───

    // LoginVM SignIn d__47: MoveNext → Task<AuthResult> awaiter kullanıyor
    // Builder non-generic (Task) — sadece SetResult() çağırır, result yok
    // Ama bu SM AuthResult döndürmüyor, void Task. Yapılacak: awaiter'ı bypass et,
    // doğrudan başarı olarak SetResult çağır.
    static void PatchLoginVMSignIn(
        ModuleDef wm, ModuleDef cm, MethodDef method, TypeDef smType, TypeDef authResultType)
    {
        var stateField = smType.Fields.FirstOrDefault(f => f.Name.String == "<>1__state");
        var builderField = smType.Fields.FirstOrDefault(f =>
            f.Name.String == "<>t__builder" &&
            f.FieldType.FullName.Contains("AsyncTaskMethodBuilder") &&
            !f.FieldType.FullName.Contains("`1")); // non-generic

        if (builderField == null)
        {
            Console.Error.WriteLine($"  [!] LoginVM SignIn builder bulunamadı.");
            // Fallback: MoveNext'i direkt temizle
            SimplePatchVoid(method);
            return;
        }

        var setResult = ResolveSetResultVoid(wm, builderField);

        var body = method.Body;
        body.Instructions.Clear();
        body.ExceptionHandlers.Clear();
        body.Variables.Clear();

        var il = body.Instructions;

        if (stateField != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldarg_0));
            il.Add(Instruction.Create(OpCodes.Ldc_I4, -2));
            il.Add(Instruction.Create(OpCodes.Stfld, stateField));
        }

        if (setResult != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldarg_0));
            il.Add(Instruction.Create(OpCodes.Ldflda, builderField));
            il.Add(Instruction.Create(OpCodes.Call, setResult));
        }

        il.Add(Instruction.Create(OpCodes.Ret));
        body.SimplifyBranches();
        Console.WriteLine($"  [+] LoginVM SignIn MoveNext patched → immediate SetResult");
    }

    static void PatchLoginVMInitialize(
        ModuleDef wm, ModuleDef cm, MethodDef method, TypeDef smType, TypeDef bootstrapType)
    {
        var stateField = smType.Fields.FirstOrDefault(f => f.Name.String == "<>1__state");
        var builderField = smType.Fields.FirstOrDefault(f =>
            f.Name.String == "<>t__builder" &&
            f.FieldType.FullName.Contains("AsyncTaskMethodBuilder") &&
            !f.FieldType.FullName.Contains("`1"));

        if (builderField == null)
        {
            SimplePatchVoid(method);
            return;
        }

        var setResult = ResolveSetResultVoid(wm, builderField);

        var body = method.Body;
        body.Instructions.Clear();
        body.ExceptionHandlers.Clear();
        body.Variables.Clear();

        var il = body.Instructions;

        if (stateField != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldarg_0));
            il.Add(Instruction.Create(OpCodes.Ldc_I4, -2));
            il.Add(Instruction.Create(OpCodes.Stfld, stateField));
        }

        if (setResult != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldarg_0));
            il.Add(Instruction.Create(OpCodes.Ldflda, builderField));
            il.Add(Instruction.Create(OpCodes.Call, setResult));
        }

        il.Add(Instruction.Create(OpCodes.Ret));
        body.SimplifyBranches();
        Console.WriteLine($"  [+] LoginVM Initialize MoveNext patched → immediate SetResult");
    }

    static void SimplePatchVoid(MethodDef method)
    {
        var body = method.Body;
        body.Instructions.Clear();
        body.ExceptionHandlers.Clear();
        body.Variables.Clear();
        body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        Console.WriteLine($"  [+] SimplePatchVoid applied");
    }

    // ─── Builder SetResult resolver ───────────────────────────────────────────

    // Generic builder: AsyncTaskMethodBuilder`1<T>.SetResult(T)
    static IMethod? ResolveSetResult(ModuleDef module, FieldDef builderField)
    {
        try
        {
            var genInstSig = builderField.FieldType as GenericInstSig;
            if (genInstSig == null) return null;

            var builderTypeDef = genInstSig.GenericType.TypeDefOrRef.ResolveTypeDef();
            if (builderTypeDef == null) return null;

            var setResultDef = builderTypeDef.Methods.FirstOrDefault(m => m.Name == "SetResult");
            if (setResultDef == null) return null;

            // MemberRef ile instantiate et: AsyncTaskMethodBuilder`1<T>.SetResult(T result)
            var declRef = new TypeRefUser(module,
                builderTypeDef.Namespace, builderTypeDef.Name,
                module.CorLibTypes.AssemblyRef);

            var genInst = new GenericInstSig(new ClassSig(declRef), genInstSig.GenericArguments[0]);
            var declRefInst = new TypeSpecUser(genInst);

            var sig = MethodSig.CreateInstance(module.CorLibTypes.Void,
                genInstSig.GenericArguments[0]);

            var memberRef = new MemberRefUser(module, "SetResult", sig, declRefInst);
            return memberRef;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"  [!] SetResult resolve hatası: {ex.Message}");
            return null;
        }
    }

    // Non-generic builder: AsyncTaskMethodBuilder.SetResult()
    static IMethod? ResolveSetResultVoid(ModuleDef module, FieldDef builderField)
    {
        try
        {
            var classSig = builderField.FieldType.ToClassOrValueTypeSig();
            if (classSig == null) return null;

            var builderTypeDef = classSig.TypeDefOrRef.ResolveTypeDef();
            if (builderTypeDef == null) return null;

            var setResultDef = builderTypeDef.Methods.FirstOrDefault(m =>
                m.Name == "SetResult" && m.Parameters.Count == 1 /* this */ );
            if (setResultDef == null) return null;

            return module.Import(setResultDef);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"  [!] SetResultVoid resolve hatası: {ex.Message}");
            return null;
        }
    }

    static IMethod? MakeNullableIntCtor(ModuleDef module)
    {
        try
        {
            var nullableRef = module.CorLibTypes.GetTypeRef("System", "Nullable`1");
            var intSig = module.CorLibTypes.Int32;
            var genInst = new GenericInstSig(new ValueTypeSig(nullableRef), intSig);
            var spec = new TypeSpecUser(genInst);
            var sig = MethodSig.CreateInstance(module.CorLibTypes.Void, intSig);
            return new MemberRefUser(module, ".ctor", sig, spec);
        }
        catch { return null; }
    }

    static TypeDef? FindType(ModuleDef module, string fullName) =>
        module.GetTypes().FirstOrDefault(t => t.FullName == fullName);

    static MethodDef? FindSetter(TypeDef type, string propName) =>
        type.Methods.FirstOrDefault(m => m.Name.String == $"set_{propName}");
}

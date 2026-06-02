// RikaNET.WinUI.dll License Patcher
// Keşif sonuçlarına göre hedef metodlar:
//   wkj=.Dhr=/<SignInAsync>d__14::MoveNext
//   wkj=.Dhr=/<InitializeAsync>d__13::MoveNext
//   wkj=.Dhr=/<RikaNET-Core-Services-IAuthenticationService-ResetHardwareIdAsync>d__29::MoveNext
//   LoginViewModel/<SignInAsync>d__47::<her adı ne olursa>

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

        // WinUI DLL'i hedef — implementasyonlar burada
        string dllPath = args.Length > 0
            ? args[0]
            : Path.Combine("..", "Rika Inc", "Rika.NET", "RikaNET.WinUI.dll");

        // Core DLL — model tipleri için referans
        string coreDllPath = args.Length > 1
            ? args[1]
            : Path.Combine(Path.GetDirectoryName(dllPath)!, "RikaNET.Core.dll");

        if (!File.Exists(dllPath))
        {
            Console.Error.WriteLine($"[!] WinUI DLL bulunamadı: {dllPath}");
            return 1;
        }
        if (!File.Exists(coreDllPath))
        {
            Console.Error.WriteLine($"[!] Core DLL bulunamadı: {coreDllPath}");
            return 1;
        }

        Console.WriteLine($"[*] WinUI yükleniyor: {dllPath}");
        Console.WriteLine($"[*] Core yükleniyor:  {coreDllPath}");

        var resolver = new AssemblyResolver();
        resolver.DefaultModuleContext = new ModuleContext(resolver);
        resolver.AddToCache(ModuleDefMD.Load(coreDllPath, resolver.DefaultModuleContext));

        var ctx = new ModuleContext(resolver);
        resolver.DefaultModuleContext = ctx;

        var module = ModuleDefMD.Load(dllPath, ctx);

        // Core modülünden tip referanslarını al
        var coreModule = resolver.Resolve(
            new AssemblyNameInfo("RikaNET.Core"),
            module)?.ManifestModule;

        if (coreModule == null)
        {
            // Fallback: doğrudan yükle
            coreModule = ModuleDefMD.Load(coreDllPath);
        }

        var authResultType = FindType(coreModule, "RikaNET.Core.Models.AuthResult");
        var bootstrapType = FindType(coreModule, "RikaNET.Core.Models.AuthBootstrapState");

        if (authResultType == null)
        {
            Console.Error.WriteLine("[!] AuthResult tipi bulunamadı.");
            return 1;
        }
        if (bootstrapType == null)
        {
            Console.Error.WriteLine("[!] AuthBootstrapState tipi bulunamadı.");
            return 1;
        }

        int patchCount = 0;

        foreach (var type in module.GetTypes())
        {
            string typeName = type.FullName;

            // --- SignInAsync state machine ---
            if (typeName.Contains("SignInAsync") && typeName.Contains("d__"))
            {
                foreach (var method in type.Methods.Where(m => m.HasBody))
                {
                    if (IsSignInStateMachine(method, type))
                    {
                        Console.WriteLine($"[*] SignIn SM bulundu: {typeName}::{method.Name}");
                        PatchSignInStateMachine(module, coreModule, method, authResultType);
                        patchCount++;
                    }
                }
            }

            // --- InitializeAsync state machine ---
            if (typeName.Contains("InitializeAsync") && typeName.Contains("d__"))
            {
                foreach (var method in type.Methods.Where(m => m.HasBody))
                {
                    if (method.Name == "MoveNext")
                    {
                        Console.WriteLine($"[*] Initialize SM bulundu: {typeName}::{method.Name}");
                        PatchInitializeStateMachine(module, coreModule, method, bootstrapType);
                        patchCount++;
                    }
                }
            }

            // --- ResetHardwareId state machine ---
            if (typeName.Contains("ResetHardware") && typeName.Contains("d__"))
            {
                foreach (var method in type.Methods.Where(m => m.HasBody && m.Name == "MoveNext"))
                {
                    Console.WriteLine($"[*] ResetHWID SM bulundu: {typeName}::{method.Name}");
                    PatchResetHwidStateMachine(module, coreModule, method, authResultType);
                    patchCount++;
                }
            }

            // --- LoginViewModel SignInAsync (kısa metot) ---
            // Bu metot zaten AuthResult.get_IsSuccess çağırıyor, true döndürmeli
            if (typeName.Contains("LoginViewModel") && typeName.Contains("SignInAsync") && typeName.Contains("d__"))
            {
                foreach (var method in type.Methods.Where(m => m.HasBody))
                {
                    if (method.Body.Instructions.Count < 20 &&
                        method.Body.Instructions.Any(i =>
                            i.Operand is MemberRef mr && mr.Name.String.Contains("IsSuccess")))
                    {
                        Console.WriteLine($"[*] LoginVM SignIn kısa metot: {typeName}::{method.Name}");
                        // Bu metot sadece IsSuccess okuyup return ediyor — true döndür
                        PatchReturnTrue(method);
                        patchCount++;
                    }
                }
            }
        }

        Console.WriteLine($"\n[*] Toplam {patchCount} patch uygulandı.");

        if (patchCount == 0)
        {
            Console.Error.WriteLine("[!] Patch uygulanamadı!");
            return 1;
        }

        string outPath = Path.Combine(
            Path.GetDirectoryName(Path.GetFullPath(dllPath))!,
            Path.GetFileNameWithoutExtension(dllPath) + ".patched.dll");

        var opts = new ModuleWriterOptions(module)
        {
            MetadataOptions = { Flags = MetadataFlags.PreserveAll },
        };

        module.Write(outPath, opts);
        Console.WriteLine($"\n[+] Kaydedildi: {outPath}");
        Console.WriteLine($"[+] Orijinal ile değiştir:");
        Console.WriteLine($"    copy \"{outPath}\" \"{Path.GetFullPath(dllPath)}\"");

        return 0;
    }

    // SignIn state machine mi? MoveNext veya obfuscated tek method
    static bool IsSignInStateMachine(MethodDef method, TypeDef declaringType)
    {
        if (method.Name == "MoveNext") return true;

        // Obfuscated kısa isimli tek metot — doğrulama için AuthResult referansı ara
        if (method.Body.Instructions.Any(i =>
            i.Operand is MemberRef mr &&
            (mr.DeclaringType?.Name.String.Contains("AuthResult") == true ||
             mr.Name.String.Contains("IsSuccess"))))
            return true;

        // Task builder SetResult çağırıyorsa async SM
        if (method.Body.Instructions.Any(i =>
            i.Operand is MemberRef mr2 && mr2.Name.String.Contains("SetResult")))
            return true;

        return false;
    }

    // SignIn state machine'i patch et:
    // SetResult(new AuthResult { IsSuccess=true, RemainingDays=9999, PlanType="Enterprise" })
    static void PatchSignInStateMachine(
        ModuleDef winuiModule, ModuleDef coreModule,
        MethodDef method, TypeDef authResultType)
    {
        var body = method.Body;

        // Task<AuthResult> builder'ı bul — state field ve builder field
        var declaringType = method.DeclaringType;

        var builderField = declaringType.Fields.FirstOrDefault(f =>
            f.FieldType.TypeName.Contains("AsyncTaskMethodBuilder") &&
            f.FieldType.TypeName.Contains("AuthResult"));

        var stateField = declaringType.Fields.FirstOrDefault(f =>
            f.Name.String.Contains("state") || f.Name.String == "<>1__state");

        if (builderField == null)
        {
            Console.Error.WriteLine($"  [!] Builder field bulunamadı: {declaringType.FullName}");
            // Basit return true ile patch
            PatchReturnTrue(method);
            return;
        }

        var ctor = method.Module.Import(authResultType.FindDefaultConstructor());
        var isSuccessSetter = method.Module.Import(
            FindMethodByName(authResultType, "set_IsSuccess"));
        var remainingDaysSetter = FindMethodByName(authResultType, "set_RemainingDays");
        var planTypeSetter = FindMethodByName(authResultType, "set_PlanType");

        if (isSuccessSetter == null)
        {
            Console.Error.WriteLine($"  [!] set_IsSuccess bulunamadı.");
            return;
        }

        // SetResult metodunu bul (Task builder üzerinde)
        MethodDef? setResultMethod = null;
        foreach (var instr in body.Instructions)
        {
            if (instr.Operand is MemberRef mr && mr.Name.String.Contains("SetResult"))
            {
                setResultMethod = null; // MemberRef olarak bırak
                break;
            }
        }

        body.Instructions.Clear();
        body.ExceptionHandlers.Clear();

        var locals = body.Variables;
        locals.Clear();

        var authLocal = new Local(winuiModule.Import(authResultType).ToTypeSig());
        locals.Add(authLocal);

        var il = body.Instructions;

        // state = -2 (tamamlandı işareti)
        if (stateField != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldarg_0));
            il.Add(Instruction.Create(OpCodes.Ldc_I4, -2));
            il.Add(Instruction.Create(OpCodes.Stfld, stateField));
        }

        // AuthResult result = new AuthResult()
        il.Add(Instruction.Create(OpCodes.Newobj, ctor));
        il.Add(Instruction.Create(OpCodes.Stloc, authLocal));

        // result.IsSuccess = true
        il.Add(Instruction.Create(OpCodes.Ldloc, authLocal));
        il.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Add(Instruction.Create(OpCodes.Call, isSuccessSetter));

        // result.RemainingDays = 9999
        if (remainingDaysSetter != null)
        {
            var setter = winuiModule.Import(remainingDaysSetter);
            // Nullable<int> için box gerekiyor
            var nullableIntCtor = FindNullableIntCtor(winuiModule);
            il.Add(Instruction.Create(OpCodes.Ldloc, authLocal));
            if (nullableIntCtor != null)
            {
                il.Add(Instruction.Create(OpCodes.Ldc_I4, 9999));
                il.Add(Instruction.Create(OpCodes.Newobj, nullableIntCtor));
            }
            else
            {
                il.Add(Instruction.Create(OpCodes.Ldc_I4, 9999));
            }
            il.Add(Instruction.Create(OpCodes.Call, setter));
        }

        // result.PlanType = "Enterprise"
        if (planTypeSetter != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldloc, authLocal));
            il.Add(Instruction.Create(OpCodes.Ldstr, "Enterprise"));
            il.Add(Instruction.Create(OpCodes.Call, winuiModule.Import(planTypeSetter)));
        }

        // builder.SetResult(result) — builder field üzerinden
        il.Add(Instruction.Create(OpCodes.Ldarg_0));
        il.Add(Instruction.Create(OpCodes.Ldflda, builderField));
        il.Add(Instruction.Create(OpCodes.Ldloc, authLocal));

        // SetResult çağrısı için MemberRef oluştur
        var builderTypeSig = builderField.FieldType as GenericInstSig;
        if (builderTypeSig != null)
        {
            var setResultRef = BuildSetResultRef(winuiModule, builderField, authResultType);
            if (setResultRef != null)
                il.Add(Instruction.Create(OpCodes.Call, setResultRef));
        }

        il.Add(Instruction.Create(OpCodes.Ret));

        body.SimplifyBranches();
        body.OptimizeBranches();
        Console.WriteLine($"  [+] SignIn patched → IsSuccess=true, RemainingDays=9999, PlanType=Enterprise");
    }

    static IMethod? BuildSetResultRef(ModuleDef module, FieldDef builderField, TypeDef resultType)
    {
        try
        {
            var sig = builderField.FieldType as GenericInstSig;
            if (sig == null) return null;

            var builderTypeDef = sig.GenericType.TypeDefOrRef.ResolveTypeDef();
            if (builderTypeDef == null) return null;

            var setResultDef = builderTypeDef.Methods.FirstOrDefault(m =>
                m.Name == "SetResult");
            if (setResultDef == null) return null;

            return module.Import(setResultDef);
        }
        catch
        {
            return null;
        }
    }

    static IMethod? FindNullableIntCtor(ModuleDef module)
    {
        try
        {
            var nullableType = module.CorLibTypes.GetTypeRef("System", "Nullable`1");
            var intSig = module.CorLibTypes.Int32;
            var nullableIntSig = new GenericInstSig(
                new ClassSig(nullableType), intSig);

            var memberRef = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void, intSig),
                nullableIntSig.ToTypeDefOrRef());

            return memberRef;
        }
        catch
        {
            return null;
        }
    }

    // InitializeAsync state machine patch
    static void PatchInitializeStateMachine(
        ModuleDef winuiModule, ModuleDef coreModule,
        MethodDef method, TypeDef bootstrapType)
    {
        var declaringType = method.DeclaringType;

        var builderField = declaringType.Fields.FirstOrDefault(f =>
            f.FieldType.TypeName.Contains("AsyncTaskMethodBuilder") &&
            f.FieldType.TypeName.Contains("AuthBootstrap"));

        var stateField = declaringType.Fields.FirstOrDefault(f =>
            f.Name.String.Contains("state") || f.Name.String == "<>1__state");

        if (builderField == null)
        {
            Console.Error.WriteLine($"  [!] InitializeAsync builder field bulunamadı.");
            return;
        }

        var ctor = winuiModule.Import(bootstrapType.FindDefaultConstructor());
        var isReadySetter = winuiModule.Import(FindMethodByName(bootstrapType, "set_IsReady"));
        var requiresUpdateSetter = FindMethodByName(bootstrapType, "set_RequiresUpdate");
        var cachedLicenseSetter = FindMethodByName(bootstrapType, "set_CachedLicense");
        var messageSetter = FindMethodByName(bootstrapType, "set_Message");

        if (isReadySetter == null)
        {
            Console.Error.WriteLine($"  [!] set_IsReady bulunamadı.");
            return;
        }

        var body = method.Body;
        body.Instructions.Clear();
        body.ExceptionHandlers.Clear();
        body.Variables.Clear();

        var stateLocal = new Local(bootstrapType.ToTypeSig());
        body.Variables.Add(stateLocal);

        var il = body.Instructions;

        if (stateField != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldarg_0));
            il.Add(Instruction.Create(OpCodes.Ldc_I4, -2));
            il.Add(Instruction.Create(OpCodes.Stfld, stateField));
        }

        il.Add(Instruction.Create(OpCodes.Newobj, ctor));
        il.Add(Instruction.Create(OpCodes.Stloc, stateLocal));

        il.Add(Instruction.Create(OpCodes.Ldloc, stateLocal));
        il.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Add(Instruction.Create(OpCodes.Call, isReadySetter));

        if (requiresUpdateSetter != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldloc, stateLocal));
            il.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            il.Add(Instruction.Create(OpCodes.Call, winuiModule.Import(requiresUpdateSetter)));
        }

        if (cachedLicenseSetter != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldloc, stateLocal));
            il.Add(Instruction.Create(OpCodes.Ldstr, "RIKA-0000-0000-0000"));
            il.Add(Instruction.Create(OpCodes.Call, winuiModule.Import(cachedLicenseSetter)));
        }

        if (messageSetter != null)
        {
            il.Add(Instruction.Create(OpCodes.Ldloc, stateLocal));
            il.Add(Instruction.Create(OpCodes.Ldnull));
            il.Add(Instruction.Create(OpCodes.Call, winuiModule.Import(messageSetter)));
        }

        il.Add(Instruction.Create(OpCodes.Ldarg_0));
        il.Add(Instruction.Create(OpCodes.Ldflda, builderField));
        il.Add(Instruction.Create(OpCodes.Ldloc, stateLocal));

        var setResultRef = BuildSetResultRef(winuiModule, builderField, bootstrapType);
        if (setResultRef != null)
            il.Add(Instruction.Create(OpCodes.Call, setResultRef));

        il.Add(Instruction.Create(OpCodes.Ret));

        body.SimplifyBranches();
        body.OptimizeBranches();
        Console.WriteLine($"  [+] Initialize patched → IsReady=true, CachedLicense=RIKA-0000-0000-0000");
    }

    static void PatchResetHwidStateMachine(
        ModuleDef winuiModule, ModuleDef coreModule,
        MethodDef method, TypeDef authResultType)
    {
        var declaringType = method.DeclaringType;

        var builderField = declaringType.Fields.FirstOrDefault(f =>
            f.FieldType.TypeName.Contains("AsyncTaskMethodBuilder") &&
            f.FieldType.TypeName.Contains("AuthResult"));

        var stateField = declaringType.Fields.FirstOrDefault(f =>
            f.Name.String == "<>1__state");

        if (builderField == null)
        {
            Console.Error.WriteLine($"  [!] ResetHWID builder field bulunamadı.");
            return;
        }

        var ctor = winuiModule.Import(authResultType.FindDefaultConstructor());
        var isSuccessSetter = winuiModule.Import(FindMethodByName(authResultType, "set_IsSuccess"));
        if (isSuccessSetter == null) return;

        var body = method.Body;
        body.Instructions.Clear();
        body.ExceptionHandlers.Clear();
        body.Variables.Clear();

        var local = new Local(authResultType.ToTypeSig());
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
        il.Add(Instruction.Create(OpCodes.Call, isSuccessSetter));

        il.Add(Instruction.Create(OpCodes.Ldarg_0));
        il.Add(Instruction.Create(OpCodes.Ldflda, builderField));
        il.Add(Instruction.Create(OpCodes.Ldloc, local));

        var setResultRef = BuildSetResultRef(winuiModule, builderField, authResultType);
        if (setResultRef != null)
            il.Add(Instruction.Create(OpCodes.Call, setResultRef));

        il.Add(Instruction.Create(OpCodes.Ret));

        body.SimplifyBranches();
        body.OptimizeBranches();
        Console.WriteLine($"  [+] ResetHWID patched → IsSuccess=true");
    }

    // Metodu temizleyip ldc.i4.1 + ret ile replace et (bool dönen metodlar için)
    static void PatchReturnTrue(MethodDef method)
    {
        var body = method.Body;
        body.Instructions.Clear();
        body.ExceptionHandlers.Clear();
        body.Variables.Clear();

        body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        Console.WriteLine($"  [+] ReturnTrue patched");
    }

    static TypeDef? FindType(ModuleDef module, string fullName) =>
        module.GetTypes().FirstOrDefault(t => t.FullName == fullName);

    static MethodDef? FindMethodByName(TypeDef type, string name) =>
        type.Methods.FirstOrDefault(m => m.Name == name);
}

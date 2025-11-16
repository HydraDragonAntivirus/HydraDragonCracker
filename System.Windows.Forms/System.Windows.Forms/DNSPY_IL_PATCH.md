# dnSpy IL Level Patching

## Method: Wbj=.pKh=.HJF=()

### 1. dnSpy'da HJF=() methoduna sağ tık

### 2. "Edit IL Instructions..." seç (C# değil!)

### 3. Method'un EN BAŞINA şu IL kodunu ekle:

```il
// Load System.Drawing.Graphics type
ldtoken System.Drawing.Graphics
call class [mscorlib]System.Type [mscorlib]System.Type::GetTypeFromHandle(valuetype [mscorlib]System.RuntimeTypeHandle)
pop

// Load System.Drawing.Bitmap type
ldtoken System.Drawing.Bitmap
call class [mscorlib]System.Type [mscorlib]System.Type::GetTypeFromHandle(valuetype [mscorlib]System.RuntimeTypeHandle)
pop

// Sleep 100ms
ldc.i4.s 100
call void [mscorlib]System.Threading.Thread::Sleep(int32)
```

### 4. OK → File → Save Module

## Alternatif: Daha basit IL

```il
ldtoken System.Drawing.Graphics
call class [mscorlib]System.Type [mscorlib]System.Type::GetTypeFromHandle(valuetype [mscorlib]System.RuntimeTypeHandle)
pop
```

Bu tek satır bile yeterli - System.Drawing'i yükler!


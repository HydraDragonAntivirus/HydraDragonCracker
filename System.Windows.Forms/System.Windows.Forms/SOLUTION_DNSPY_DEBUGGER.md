# 🔓 RikaCrackme v1 - dnSpy Debugger Çözümü

## 📥 dnSpy İndir
https://github.com/dnSpy/dnSpy/releases/latest
- **dnSpy-netframework-win64.zip** indir

## 🎮 ADIM ADIM ÇÖZÜM

### 1. dnSpy'ı Başlat
```
dnSpy.exe
```

### 2. Debugger Ayarları
1. **Debug → Start Debugging... (F5)**
2. **Executable:** `RikaCrackmeV1.exe` seç
3. **Break at:** `Module Entrypoint` seç
4. **Start**

### 3. Breakpoint Koy
Crackme durduğunda:
1. **Ctrl+Shift+K** → Search Assemblies
2. Ara: `Click` (button click handler'ı bul)
3. Bulunan method'a **çift tıkla**
4. Method içinde **F9** ile breakpoint koy

### 4. Çalıştır ve Analiz Et
1. **F5** → Continue
2. Crackme'de password gir ve Login'e tıkla
3. Breakpoint'te dur
4. **F11** (Step Into) ile satır satır ilerle
5. **Locals** penceresinde değişkenleri izle

### 5. Şifreyi Bul

Tipik pattern'ler:
```csharp
// Pattern 1: Hardcoded
if (textBox1.Text == "SECRET_PASSWORD")

// Pattern 2: Comparison
if (input.Equals(correctPassword))

// Pattern 3: Hash
if (MD5(input) == "hash_value")
```

## 💡 İPUÇLARI

### String'leri Bul
1. **Edit → Search → Strings (Ctrl+Shift+S)**
2. Ara: `success`, `wrong`, `correct`, `invalid`
3. String'e çift tıkla → Hangi method kullanıyor?

### Obfuscation Bypass
GodMode obfuscation olsa bile:
- **String literals** görünür
- **Comparison operatörleri** görünür  
- **MessageBox.Show()** görünür
- **IL assembly** okunabilir

### Watch Window
Debugger'da:
1. **Debug → Windows → Watch**
2. Şüpheli değişkenleri watch'a ekle
3. Execution sırasında değerlerini gör

## 🚀 HIZLI YÖNTEM

```
1. dnSpy aç
2. RikaCrackmeV1.exe debug başlat
3. Ctrl+Shift+S → "success" ara
4. Success string'inin olduğu method'u aç
5. Orada password kontrolü var!
6. Breakpoint koy, çalıştır
7. Locals'da değişkenleri oku
```

## 📊 EXPECTED RESULT

Debugger ile:
- ✅ Password validation logic görünür
- ✅ Comparison değerleri görünür
- ✅ Doğru şifre bulunur

**5-10 dakika içinde çözülür!** 🎯


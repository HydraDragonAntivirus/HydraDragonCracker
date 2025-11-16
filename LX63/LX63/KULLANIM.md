# LX63 Proxy DLL - Kullanım Kılavuzu

## 📁 Dosyalar

### Ana Dosyalar
- **`dllmain_enhanced.cpp`** - Gelişmiş opsiyonlu proxy DLL kaynak kodu
- **`launcher.cpp`** - DLL injection başlatıcı program
- **`config.ini`** - Yapılandırma dosyası
- **`get_dll_imports.py`** - DLL import analiz scripti
- **`analyze_dll.py`** - DLL detaylı analiz scripti

## 🔧 Kurulum

### 1. DLL İmport Bilgilerini Çıkar
```bash
python get_dll_imports.py LX63.dll
```
Bu komut `LX63_imports.json` dosyası oluşturur.

### 2. Proxy DLL'i Derle

**Visual Studio ile:**
1. `dllmain_enhanced.cpp` dosyasını `dllmain.cpp` ile değiştir
2. Projeyi Release|x64 modunda derle
3. Çıktı: `LX63.dll`

**Manuel derleme:**
```bash
cl /LD /O2 /std:c++17 dllmain_enhanced.cpp /Fe:LX63.dll
```

### 3. Launcher'ı Derle
```bash
cl /O2 launcher.cpp /Fe:launcher.exe
```

## ⚙️ Yapılandırma (config.ini)

### Genel Ayarlar
```ini
[General]
EnableLogging=1          # Log tutmayı aç/kapat (1/0)
LogFile=proxy_log.txt    # Log dosya adı
DebugMode=0              # Debug modu
```

### DLL Ayarları
```ini
[DLL]
OriginalDLL=orig.dll     # Yüklenecek orijinal DLL
LoadMethod=0             # 0=Aynı dizin, 1=System32, 2=Özel yol
CustomPath=              # LoadMethod=2 ise özel yol
```

### Python Entegrasyonu
```ini
[Python]
EnablePython=1           # Python scriptlerini çalıştır (1/0)
ScriptPath=shader_extractor.py
PythonExecutable=python
RunAsync=1               # Asenkron çalıştır (beklemez)
```

### Hook Ayarları
```ini
[Hooks]
HookD3DCompile=1         # D3DCompile fonksiyonunu hook et
HookD3DPreprocess=0
HookD3DDisassemble=0
```

### Çıktı Ayarları
```ini
[Output]
SaveShaders=1                  # Shader dosyalarını kaydet
OutputDirectory=extracted_shaders
MaxFileSize=10485760           # 10MB limit
CompressOutput=0
```

## 🚀 Kullanım

### Yöntem 1: Çalışan Process'e Inject Et

**Process ismi ile:**
```bash
launcher.exe -p game.exe -d LX63.dll
```

**Process ID ile:**
```bash
launcher.exe -pid 1234 -d LX63.dll
```

### Yöntem 2: Yeni Process Başlat ve Inject Et

**Basit:**
```bash
launcher.exe -l "C:\Games\game.exe" -d LX63.dll
```

**Argümanlar ile:**
```bash
launcher.exe -l "C:\Games\game.exe" -d LX63.dll -args "-windowed -debug"
```

### Yöntem 3: Manuel DLL Replacement

1. Orijinal DLL'i yedekle:
   ```
   ren LX63.dll orig.dll
   ```

2. Proxy DLL'i yerleştir:
   ```
   copy yeni_LX63.dll LX63.dll
   ```

3. config.ini'yi aynı dizine koy

4. Programı normal şekilde çalıştır

## 📊 Log İnceleme

Log dosyası (`proxy_log.txt`) şunları içerir:
```
[2025-01-16 12:34:56.789] === Proxy DLL Initialized ===
[2025-01-16 12:34:56.790] DLL_PROCESS_ATTACH
[2025-01-16 12:34:56.791] Module: 0x00007FF8A0000000
[2025-01-16 12:34:56.792] Loading original DLL: C:\Games\orig.dll
[2025-01-16 12:34:56.810] Original DLL loaded successfully. D3DCompile: 0x00007FF8A0123456
[2025-01-16 12:34:57.123] D3DCompile called: Size=1024, Entry=main, Target=ps_5_0
[2025-01-16 12:34:57.125] Saved shader data: 1024 bytes
[2025-01-16 12:34:57.126] Executing: python shader_extractor.py extract_shader
```

## 🔍 DLL Analiz

### Detaylı Analiz
```bash
python analyze_dll.py LX63.dll
```

Çıktı:
- Entry point adresi
- Import/Export listesi
- Section bilgileri
- Mimari (x86/x64)

### Import Listesi
```bash
python get_dll_imports.py LX63.dll
```

JSON çıktısı:
```json
{
  "dll_name": "LX63.dll",
  "architecture": "x64",
  "entry_point": "0x16d8a4",
  "imports": {
    "KERNEL32.dll": [...],
    "USER32.dll": [...]
  }
}
```

## 🎯 Özellikler

### ✅ Yapılanlar
- [x] INI dosyası ile yapılandırma
- [x] Detaylı logging sistemi
- [x] Python script entegrasyonu
- [x] Orijinal DLL'e fonksiyon forwarding
- [x] DLL injection launcher
- [x] Process attach/launch desteği
- [x] Asenkron/senkron Python çalıştırma
- [x] Shader data extraction
- [x] Hata ayıklama modu

### 🎨 Kullanım Senaryoları

**1. Shader Extraction (Varsayılan):**
```ini
[Hooks]
HookD3DCompile=1
[Output]
SaveShaders=1
[Python]
EnablePython=1
```

**2. Sadece Logging:**
```ini
[General]
EnableLogging=1
[Python]
EnablePython=0
[Output]
SaveShaders=0
```

**3. Full Debug:**
```ini
[General]
EnableLogging=1
DebugMode=1
[Python]
EnablePython=1
RunAsync=0  # Python işlemini bekle
```

## 🛠️ Sorun Giderme

### DLL Yüklenmiyor
- `config.ini` dosyasının exe ile aynı dizinde olduğundan emin olun
- Log dosyasını kontrol edin
- `LoadMethod` değerini değiştirmeyi deneyin

### Python Çalışmıyor
- Python yüklü mü kontrol edin: `python --version`
- Script yolu doğru mu kontrol edin
- Log dosyasında Python hataları var mı bakın

### Injection Başarısız
- Yönetici (Administrator) olarak çalıştırın
- Antivirus'ü geçici olarak kapatın
- Process ID'nin doğru olduğundan emin olun

## 📝 Notlar

- DLL'i x64 uygulama için x64, x86 için x86 olarak derleyin
- `orig.dll` dosyası exe ile aynı dizinde olmalı (veya config'de path belirtin)
- Log dosyası sürekli büyüyebilir, periyodik olarak temizleyin
- Python scriptleri asenkron çalıştığı için performans etkisi minimum

## 🔐 Güvenlik

Bu araç **sadece yasal ve etik amaçlar** için kullanılmalıdır:
- ✅ Kendi geliştirdiğiniz uygulamalarda
- ✅ İzin aldığınız sistemlerde
- ✅ Eğitim/araştırma amaçlı
- ❌ Başkalarının yazılımlarını hacklemek için kullanmayın

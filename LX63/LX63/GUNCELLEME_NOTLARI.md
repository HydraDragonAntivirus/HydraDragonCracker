# 🔄 Proje Güncelleme Notları

## ✅ Yapılan Değişiklikler

### 1. **dllmain.cpp Güncellendi**
- ✅ **Yedek oluşturuldu**: `dllmain_old_backup.cpp`
- ✅ **Yeni versiyon**: Gelişmiş özelliklerle güncellendi
- ✅ **Özellikler**:
  - INI dosyası yapılandırma sistemi
  - Detaylı logging (timestamp'li)
  - Hata ayıklama modu
  - Python async/sync çalıştırma seçenekleri
  - Esnek DLL yükleme (3 farklı yöntem)

### 2. **Visual Studio Projesi (.vcxproj) Güncellendi**
- ✅ **Tüm konfigürasyonlarda** C++17 desteği eklendi
- ✅ **shlwapi.lib** kütüphanesi eklendi (tüm build konfigürasyonları)
- ✅ Debug|Win32, Release|Win32, Debug|x64, Release|x64

### 3. **pch.h (Precompiled Header) Güncellendi**
- ✅ `<string>` eklendi
- ✅ `<filesystem>` eklendi (C++17)
- ✅ `<fstream>` eklendi

### 4. **Yeni Dosyalar Eklendi**

#### Python Araçları:
- ✅ **`dll_launcher.py`** - DLL analiz ve başlatma aracı
- ✅ **`get_dll_imports.py`** - Import bilgilerini JSON'a çıkarır
- ✅ **`analyze_dll.py`** - Detaylı DLL analizi

#### Yapılandırma:
- ✅ **`config.ini`** - DLL yapılandırma dosyası
- ✅ **`launcher_usage.txt`** - Python launcher kullanım kılavuzu
- ✅ **`KULLANIM.md`** - Türkçe detaylı kullanım kılavuzu

#### C++ (Opsiyonel):
- ✅ **`launcher.cpp`** - C++ DLL injector (isteğe bağlı)

---

## 🚀 Kullanıma Başla

### Adım 1: Projeyi Derle
```
Visual Studio'da:
1. Projeyi aç
2. Release | x64 seçimi yap
3. Build > Build Solution (Ctrl+Shift+B)
```

### Adım 2: config.ini'yi Ayarla
`config.ini` dosyası **derlenmiş DLL ile aynı dizinde** olmalı.

**Varsayılan ayarlar:**
```ini
[General]
EnableLogging=1              # Log dosyası oluştur
LogFile=proxy_log.txt        # Log dosya adı

[DLL]
OriginalDLL=orig.dll         # Yüklenecek orijinal DLL

[Python]
EnablePython=1               # Python scriptlerini çalıştır
RunAsync=1                   # Asenkron (oyunu yavaşlatmaz)

[Hooks]
HookD3DCompile=1             # D3DCompile fonksiyonunu yakala

[Output]
SaveShaders=1                # Shader'ları kaydet
```

### Adım 3: Python Launcher Kullan

**DLL'i analiz et:**
```bash
python dll_launcher.py LX63.dll -a
```

**Çalışan process'e inject et:**
```bash
python dll_launcher.py LX63.dll -i game.exe
```

**Yeni process başlat:**
```bash
python dll_launcher.py LX63.dll -e "C:\Games\game.exe"
```

---

## 📊 Dosya Yapısı

```
LX63/
├── dllmain.cpp                  ← GÜNCEL (gelişmiş versiyon)
├── dllmain_old_backup.cpp       ← Yedek (eski basit versiyon)
├── dllmain_enhanced.cpp         ← Kaynak (referans)
├── pch.h                        ← Güncellendi (C++17 headers)
├── pch.cpp
├── framework.h
├── LX63.vcxproj                 ← Güncellendi (shlwapi.lib)
├── LX63.def
├── config.ini                   ← YENİ (yapılandırma)
│
├── Python Araçları:
│   ├── dll_launcher.py          ← YENİ (ana başlatıcı)
│   ├── analyze_dll.py           ← YENİ (analiz)
│   ├── get_dll_imports.py       ← YENİ (import çıkar)
│   ├── extract_exports.py       ← Mevcut
│   └── shader_extractor.py      ← (varsa kullanıcının scripti)
│
└── Dokümantasyon:
    ├── GUNCELLEME_NOTLARI.md    ← Bu dosya
    ├── KULLANIM.md              ← Detaylı kılavuz
    └── launcher_usage.txt       ← Python launcher örnekleri
```

---

## 🔍 Önemli Değişiklikler

### ❌ Eski Sistem (dllmain_old_backup.cpp):
- Sabit kodlanmış ayarlar
- Log yok
- Hata ayıklama zor
- Python her zaman async

### ✅ Yeni Sistem (dllmain.cpp):
- config.ini ile ayarlanabilir
- Detaylı log sistemi
- Debug mode
- Python sync/async seçimi
- 3 farklı DLL yükleme yöntemi
- Thread-safe logging

---

## 🛠️ Sorun Giderme

### "LNK2019: unresolved external symbol" hatası
**Çözüm:** shlwapi.lib eklendi mi kontrol et
```
Proje > Properties > Linker > Input > Additional Dependencies
shlwapi.lib olmalı
```

### "Cannot open config.ini" uyarısı
**Çözüm:** config.ini'yi exe yanına koy
```
Game/
├── game.exe
├── LX63.dll
└── config.ini    ← Burası!
```

### DLL yüklenmiyor
**Çözüm:** Log dosyasına bak
```
proxy_log.txt dosyasını aç, hata mesajlarını oku
```

---

## 📝 Test Checklist

- [ ] Proje derlendi (Release|x64)
- [ ] LX63.dll oluşturuldu
- [ ] config.ini exe yanında
- [ ] Python launcher test edildi
- [ ] Log dosyası oluşuyor
- [ ] DLL injection çalışıyor

---

## 🔙 Geri Dönüş (Eski Versiyona)

Eski basit versiyona dönmek için:
```bash
cp dllmain_old_backup.cpp dllmain.cpp
```

Sonra projeyi tekrar derle.

---

## 💡 İpuçları

1. **İlk test için Debug modda derle** - daha detaylı hata mesajları
2. **config.ini'de EnableLogging=1 yap** - her şeyi logla
3. **Python launcher ile test et** - C++ derlemeden analiz yap
4. **Log dosyasını kontrol et** - her sorun orada görünür

---

## 📞 Yardım

Sorun mu var?
1. `proxy_log.txt` dosyasını kontrol et
2. `python dll_launcher.py LX63.dll -a` ile DLL'i analiz et
3. config.ini ayarlarını kontrol et

---

**Güncelleme Tarihi:** Kasım 16, 2025
**Versiyon:** 2.0 (Enhanced)

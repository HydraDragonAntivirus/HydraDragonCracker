# RikaCrackme v1 - System.Windows.Forms Proxy DLL

## 🎯 Projenin Amacı
RikaCrackmeV1.exe çalıştırıldığında System.Windows.Forms.dll yerine bizim proxy DLL'imizi yükleyerek uygulamanın davranışını analiz etmek.

## ❌ Orijinal Hata
```
Olay Adı: APPCRASH
Hata Kodu: c0000005 (ACCESS_VIOLATION)
Hata Kaynağı: clr.dll (Common Language Runtime)
```

## ✅ Düzeltilen Sorunlar

### 1. Assembly İmzalama Sorunu
- **Sorun:** `SignAssembly=true` ama key dosyası yoktu
- **Çözüm:** `SignAssembly=false` yapıldı

### 2. Assembly Loading Hatası
- **Sorun:** `Assembly.Load(byte[])` binding issues yaratıyordu
- **Çözüm:** `Assembly.LoadFrom()` kullanıldı

### 3. Type Forwarding Çakışması
- **Sorun:** Application stub ile TypeForwarder çakışması
- **Çözüm:** Application stub'ı ayrı dosyada tanımlandı, TypeForwarders'da kaldırıldı

### 4. Control Sınıfı Çakışması
- **Sorun:** Stub Control sınıfı TypeForwarder ile çakışıyordu
- **Çözüm:** Control stubını kaldırıp TypeForwarder olarak bırakıldı

## 🛠️ Çalışan DLL
Proxy DLL başarıyla oluşturuldu ve test edildi:
- ✅ ProxyBootstrap çalışıyor
- ✅ Gerçek System.Windows.Forms GAC'den yükleniyor
- ✅ Application.EnableVisualStyles() başarılı
- ✅ TestLoader.exe ile doğrulandı

## 🔐 Kalan Sorun: Strong-Name Verification

### Problem
RikaCrackmeV1.exe şu referansı kullanıyor:
```
System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
```

Bizim DLL unsigned olduğu için CLR onu reddediyor ve GAC'deki signed versiyonu yüklüyor.

### Çözüm (Administrator Yetkisi Gerekli)

#### Yöntem 1: Batch Dosyası (Önerilen)
1. `DisableStrongNameVerification.bat` dosyasına sağ tıklayın
2. "Run as Administrator" seçin
3. Devam etmek için bir tuşa basın

#### Yöntem 2: Manuel Komut
PowerShell'i Administrator olarak açın ve şu komutu çalıştırın:
```powershell
& "C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\sn.exe" -Vr System.Windows.Forms,b77a5c561934e089
```

### Verification'ı Geri Açmak (Opsiyonel)
Eğer test bittiğinde verification'ı geri açmak isterseniz:
```powershell
& "C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\sn.exe" -Vu System.Windows.Forms,b77a5c561934e089
```

## 🚀 Kullanım

1. Strong-name verification'ı devre dışı bırakın (yukarıdaki adımlar)
2. `RikaCrackmeV1.exe` dosyasını çalıştırın
3. `proxy_log.txt` dosyasını kontrol edin:
   ```
   [Timestamp] ProxyBootstrap initialized.
   [Timestamp] Pre-loading real assembly from: ...
   [Timestamp] Real assembly loaded: ...
   [Timestamp] Analysis timer started (5 second delay)...
   [Timestamp] === Loaded Assemblies ===
   [Timestamp]   - Assembly details...
   ```

## 📁 Dosya Yapısı
```
System.Windows.Forms/
├── System.Windows.Forms.cs          # Application stub + ProxyBootstrap
├── TypeForwarders.cs                # Type forwarding definitions
├── System.Windows.Forms.csproj      # Proje dosyası
├── orig.dll                         # Orijinal System.Windows.Forms (reference)
├── System.Windows.Forms.dll         # Bizim proxy DLL
├── RikaCrackmeV1.exe                # Hedef crackme
├── RikaCrackmeV1.exe.config         # Assembly binding config
├── DisableStrongNameVerification.bat # Strong-name bypass script
└── proxy_log.txt                    # Runtime log (çalışma sonrası oluşur)
```

## 🔍 Proxy Nasıl Çalışır?

1. **Application Stub:** RikaCrackmeV1.exe ilk `System.Windows.Forms.Application` kullanımında bizim stub'ımız yüklenir
2. **ProxyBootstrap.Touch():** Static constructor tetiklenir ve bootstrap başlar
3. **Real Assembly Loading:** GAC'deki gerçek System.Windows.Forms yüklenir
4. **AssemblyResolve Handler:** Future type resolutions için handler kaydedilir
5. **Analysis Timer:** 5 saniye sonra uygulama analiz edilir
6. **Type Forwarding:** Diğer tüm tipler TypeForwarder ile gerçek assembly'e yönlendirilir

## 📊 Log Analizi
`proxy_log.txt` dosyasında görebileceğiniz bilgiler:
- Bootstrap zamanlaması
- Yüklenen assembly yolu
- Loaded assemblies listesi
- Analysis sonuçları

## ⚠️ Dikkat Edilmesi Gerekenler
- Strong-name verification devre dışı bırakıldığında sistem genelinde etki eder
- Güvenlik riski oluşturabilir (sadece development ortamında kullanın)
- Test bittiğinde verification'ı geri açmayı düşünün
- Administrator yetkisi gereklidir

## 🎓 Öğrenilenler
1. .NET Assembly Loading mekanizması
2. Strong-name verification ve bypass teknikleri
3. Type forwarding with extern aliases
4. AssemblyResolve event handling
5. CLR assembly binding order
6. DLL hijacking/proxying teknikleri

---
**Oluşturulma Tarihi:** 14 Kasım 2025
**Versiyon:** 1.0


# ENTRYPOINT PATCH GUIDE

## 1. dnSpy'da RikaCrackmeV1.exe aç

Zaten açık olmalı!

## 2. Main() Method'unu Bul

- Sol panelde **RikaCrackmeV1** assembly'yi expand et
- İçindeki **namespace**'leri aç
- **Program** class'ını bul (veya obfuscated ise ilk class)
- **Main()** method'unu bul ve çift tıkla

## 3. Edit Method

- Main() method'una **sağ tık**
- **"Edit Method (C#)..."** seç

## 4. En Başa Sahte Dependency Ekle

Main() içeriğinin **EN BAŞINA** şunu ekle:

```csharp
// Force load System.Drawing proxy
try 
{
    var _ = typeof(System.Drawing.Graphics);
    var __ = typeof(System.Drawing.Bitmap);
    System.Threading.Thread.Sleep(500); // Give proxy time to initialize
} 
catch { }
```

## 5. Compile & Save

- **Compile** butonuna tıkla
- Hata varsa düzelt
- **File > Save Module...** 
- Kaydet!

## 6. Test Et

```powershell
.\RikaCrackmeV1.exe
```

Proxy log dosyaları oluşmalı!


# 🔓 RikaCrackme v1 - Çözüm Rehberi

## 📥 Gereksinimler
- **dnSpy**: https://github.com/dnSpy/dnSpy/releases (dnSpy-netframework-win64.zip)

## 🚀 Hızlı Çözüm (5 Dakika)

### 1. dnSpy'ı İndir ve Aç
```powershell
# İndirme linki
https://github.com/dnSpy/dnSpy/releases/latest

# Zip'i extract et, dnSpy.exe'yi çalıştır
```

### 2. RikaCrackmeV1.exe'yi Yükle
- File → Open → `RikaCrackmeV1.exe` seç

### 3. Form'u Bul
Sol panelde:
```
RikaCrackmeV1
  └── {} (sınıflar)
      └── [obfuscated isim] (Form sınıfı)
          └── InitializeComponent() ← Buraya çift tıkla
```

### 4. Button Click Handler'ını Bul
`InitializeComponent()` içinde:
```csharp
this.button1.Click += new EventHandler(this.button1_Click);
```

`button1_Click`'e sağ tıkla → "Go to Definition"

### 5. Şifre Kontrolünü Oku
Tipik pattern:
```csharp
private void button1_Click(object sender, EventArgs e)
{
    if (this.textBox1.Text == "ŞIFRE_BURADA")  // ← ŞİFRE!
    {
        MessageBox.Show("Success!");
    }
    else
    {
        MessageBox.Show("Wrong password!");
    }
}
```

---

## 🔍 ALTERNATİF: String Search

dnSpy'da:
1. **Ctrl+Shift+K** (Search Assemblies)
2. **"Success"** veya **"Wrong"** ara
3. Bulunan string'e çift tıkla
4. Hangi fonksiyon kullanıyor? → O fonksiyonu oku

---

## 💡 İpuçları

### Şifre Hardcoded Değilse?
Şunları kontrol et:
```csharp
// MD5/SHA hash karşılaştırması?
if (ComputeHash(input) == "hash_value")

// String reverse/XOR?
if (Reverse(input) == "...")
if (XOR(input, key) == "...")

// Length check?
if (input.Length == 16 && ...)
```

### Obfuscation Çok Fazlaysa?
```powershell
# de4dot ile temizle
de4dot.exe RikaCrackmeV1.exe
# Sonra RikaCrackmeV1-cleaned.exe'yi dnSpy'da aç
```

---

## 🎮 HEMEN DENEYELİM

1. **dnSpy aç**
2. **RikaCrackmeV1.exe yükle**
3. **Sol panelde Form sınıfını bul**
4. **Button click handler'ını aç**
5. **Şifre kontrolünü oku**

**5 dakika içinde şifreyi bulacaksın!** 🎯


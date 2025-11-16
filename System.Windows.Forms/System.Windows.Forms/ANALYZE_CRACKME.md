# RikaCrackme v1 - Statik Analiz Rehberi

## 🔍 dnSpy ile Analiz

### Adım 1: dnSpy'ı İndir
https://github.com/dnSpy/dnSpy/releases

### Adım 2: RikaCrackmeV1.exe'yi Aç
1. dnSpy'ı çalıştır
2. File → Open → RikaCrackmeV1.exe

### Adım 3: Entry Point'i Bul
1. Sol panelde: RikaCrackmeV1 → {} → entry point
2. Ya da: Edit → Search → Search Assembly (Ctrl+Shift+K)
   - "Main" ara

### Adım 4: Login Fonksiyonunu Bul

Aranacak kelimeler:
- `Password`
- `CheckPassword`
- `ValidateLogin`
- `btnLogin_Click`
- `Button_Click`
- `TextBox` (textbox kontrollerini bul)

### Adım 5: String'leri Kontrol Et

1. Edit → Search → Search Strings
2. Filtre: Password, Serial, Key, Success, Wrong
3. String'e çift tıkla → hangi fonksiyon kullanıyor?

### Adım 6: Hardcoded Password'u Bul

Tipik patternler:
```csharp
if (textBox1.Text == "SECRET_PASSWORD")
if (input.Equals("12345"))
string correctPassword = "...";
```

---

## 🎮 HIZLI BAŞLANGIÇ

1. **dnSpy aç**
2. **RikaCrackmeV1.exe yükle**
3. **Ctrl+Shift+K** (Search)
4. **"password"** ara (case-insensitive)
5. **Her sonuca tıkla, kodu oku**

---

## 💡 İPUÇLARI

### Obfuscated ise?
- de4dot kullan: `de4dot.exe RikaCrackmeV1.exe`
- Sonra dnSpy'da tekrar aç

### Form Designer Varsa?
- Resources → .resx dosyalarına bak
- InitializeComponent() methodunu incele

### Button Click Handler Bul
```csharp
// Tipik pattern:
private void button1_Click(object sender, EventArgs e)
{
    if (textBox1.Text == correctPassword)
        MessageBox.Show("Success!");
}
```

---

## 🚀 HEMEN ŞİMDİ DENEYELİM!

Aşağıdaki PowerShell script'i crackme'yi otomatik analiz eder:


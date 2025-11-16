# dnSpy Debugger ile Crackme'yi Çöz (Anti-Tamper Bypass)

## PATCHING FORBIDDEN? Sorun değil!

Anti-tamper koruması dnSpy debugger'ı engellemez!

## ADIMLAR:

### 1. dnSpy Debugger Başlat

- dnSpy'da: **Debug** → **Start Debugging** (F5)
- Veya: **Debug** → **Attach to Process...** (Ctrl+Alt+P)

### 2. Breakpoint Koy

**Seçenek A: Form Load Event**
- Assembly'de `Form` veya `MainForm` ara
- Constructor veya `Load` event'e breakpoint koy

**Seçenek B: Button Click**
- "Check", "Login", "Validate" gibi button event'leri ara
- Click handler'a breakpoint koy

**Seçenek C: String Search**
- **Edit** → **Search Assemblies** (Ctrl+Shift+K)
- Ara: "Success", "Correct", "Invalid", "Wrong", etc.
- Bu string'i kullanan method'u bul
- Breakpoint koy

### 3. Runtime'da Inspect Et

Breakpoint'te durduktan sonra:
- **Locals** window → değişkenleri gör
- **Watch** window → `textBox1.Text`, `txtPassword.Text` gibi expressions yaz
- **Call Stack** → nereden geldiğini gör

### 4. Password/Serial Bul

- TextBox değerlerini oku
- Karşılaştırma yapılan değişkeni bul
- Doğru password/serial'i görürsün!

## Alternatif: Memory Dump

Eğer debugging de forbidden ise:
- Process Hacker kullan
- Memory'den string'leri dump et
- "Success", "Correct" mesajlarına yakın password'ü ara

---

## HEMEN ŞİMDİ DENE:

1. dnSpy'da **Debug → Start Debugging** (F5)
2. Crackme açılınca herhangi bir text yaz ve butona tıkla
3. Crash ederse → **exception caught** → exception details'de bilgi olabilir!


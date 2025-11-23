#!/usr/bin/env python3
"""
DLL Ne İşe Yarar? - DLL'in ne olduğunu ve nasıl çalıştırılacağını anla
"""
import pefile
import os
import sys
import struct
from pathlib import Path

class DLLAnalyzer:
    def __init__(self, dll_path):
        self.dll_path = Path(dll_path)
        self.pe = None
        self.dll_type = "Unknown"
        self.purpose = []

    def analyze(self):
        """DLL'i tamamen analiz et"""
        print("=" * 80)
        print(f"  DLL ANALİZİ: {self.dll_path.name}")
        print("=" * 80)

        if not self.dll_path.exists():
            print(f"[-] Dosya bulunamadı: {self.dll_path}")
            return False

        try:
            self.pe = pefile.PE(str(self.dll_path))

            # 1. Temel bilgiler
            self.print_basic_info()

            # 2. Ne işe yaradığını anla
            self.identify_purpose()

            # 3. String'leri analiz et
            self.analyze_strings()

            # 4. Resource'ları kontrol et
            self.check_resources()

            # 5. Export/Import'ları analiz et
            self.analyze_exports_imports()

            # 6. Nasıl çalıştırılır?
            self.how_to_run()

            self.pe.close()
            return True

        except Exception as e:
            print(f"[-] Analiz hatası: {e}")
            import traceback
            traceback.print_exc()
            return False

    def print_basic_info(self):
        """Temel DLL bilgileri"""
        print("\n[1] TEMEL BİLGİLER")
        print("-" * 80)

        # Dosya boyutu
        size_mb = self.dll_path.stat().st_size / (1024 * 1024)
        print(f"Dosya boyutu: {size_mb:.2f} MB")

        # Mimari
        machine = self.pe.FILE_HEADER.Machine
        arch = "x64 (64-bit)" if machine == 0x8664 else "x86 (32-bit)" if machine == 0x14c else f"Unknown ({hex(machine)})"
        print(f"Mimari: {arch}")

        # Subsystem
        subsystem = self.pe.OPTIONAL_HEADER.Subsystem
        subsystem_names = {
            2: "Windows GUI",
            3: "Windows Console",
            9: "Windows CE",
            10: "EFI Application"
        }
        print(f"Subsystem: {subsystem_names.get(subsystem, f'Unknown ({subsystem})')}")

        # Compile zamanı
        from datetime import datetime
        timestamp = self.pe.FILE_HEADER.TimeDateStamp
        compile_time = datetime.fromtimestamp(timestamp)
        print(f"Derlenme zamanı: {compile_time}")

        # Entry Point
        print(f"Entry Point: {hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")

    def identify_purpose(self):
        """DLL'in ne işe yaradığını belirle"""
        print("\n[2] DLL'İN AMACI NE?")
        print("-" * 80)

        # Export'lara bak
        export_names = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    export_names.append(exp.name.decode('utf-8'))

        # Import'lara bak
        import_dlls = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                import_dlls.append(entry.dll.decode('utf-8'))

        # Amaç tespiti
        purposes = []

        # D3D/DirectX
        if any('d3d' in name.lower() or 'direct' in name.lower() for name in export_names):
            purposes.append("[Graphics] DirectX/D3D Graphics API")
            self.dll_type = "Graphics API"
        if any('d3d' in dll.lower() for dll in import_dlls):
            purposes.append("[Graphics] DirectX kullanan grafik DLL'i")

        # OpenGL
        if any('gl' in name.lower() or 'opengl' in name.lower() for name in export_names):
            purposes.append("[Graphics] OpenGL Graphics API")
            self.dll_type = "Graphics API"

        # Networking
        if 'WS2_32.dll' in import_dlls or 'WININET.dll' in import_dlls:
            purposes.append("[Network] Internet/Network islemleri yapiyor")

        # Crypto
        if 'bcrypt.dll' in import_dlls or 'CRYPT32.dll' in import_dlls:
            purposes.append("[Crypto] Sifreleme/Kriptografi kullaniyor")

        # LDAP
        if 'WLDAP32.dll' in import_dlls:
            purposes.append("[LDAP] Directory islemleri")

        # C++ Runtime
        if any('MSVCP' in dll or 'VCRUNTIME' in dll for dll in import_dlls):
            purposes.append("[Language] C++ ile yazilmis")

        # .NET
        if 'mscoree.dll' in import_dlls or 'clr.dll' in import_dlls:
            purposes.append("[.NET] CLR kullaniyor")
            self.dll_type = ".NET Assembly"

        # Export yok = Executable
        if not export_names:
            purposes.append("[!] Export YOK - Bu bir kutuphane DLL'i DEGIL!")
            purposes.append("    Muhtemelen bir executable'in .dll uzantili hali")
            self.dll_type = "Executable (renamed)"

        if purposes:
            for purpose in purposes:
                print(f"  {purpose}")
        else:
            print("  [?] Belirli bir amac tespit edilemedi")
            print("  [*] Genel amacli bir DLL veya ozel bir uygulama")

        self.purpose = purposes

    def analyze_strings(self):
        """DLL içindeki string'leri analiz et"""
        print("\n[3] ÖNEMLİ STRING'LER")
        print("-" * 80)

        # Binary'den string çıkar
        strings = self.extract_strings()

        # İlginç string'leri filtrele
        interesting = {
            'Paths': [],
            'URLs': [],
            'APIs': [],
            'Errors': [],
            'Other': []
        }

        for s in strings:
            s_lower = s.lower()
            if '://' in s or 'http' in s_lower or 'www.' in s_lower:
                interesting['URLs'].append(s)
            elif '\\' in s and ('.' in s or ':' in s):
                interesting['Paths'].append(s)
            elif 'error' in s_lower or 'fail' in s_lower or 'exception' in s_lower:
                interesting['Errors'].append(s[:100])
            elif any(api in s for api in ['D3D', 'OpenGL', 'Vulkan', 'DirectX']):
                interesting['APIs'].append(s)
            elif len(s) > 10 and len(s) < 100:
                interesting['Other'].append(s)

        # Göster
        for category, items in interesting.items():
            if items:
                print(f"\n  {category}:")
                for item in items[:10]:  # İlk 10
                    print(f"    - {item}")
                if len(items) > 10:
                    print(f"    ... ve {len(items) - 10} tane daha")

    def extract_strings(self, min_length=4):
        """Binary'den ASCII string'leri çıkar"""
        with open(self.dll_path, 'rb') as f:
            data = f.read()

        strings = []
        current = b''

        for byte in data:
            if 32 <= byte < 127:  # Yazdırılabilir ASCII
                current += bytes([byte])
            else:
                if len(current) >= min_length:
                    try:
                        strings.append(current.decode('ascii'))
                    except:
                        pass
                current = b''

        return strings

    def check_resources(self):
        """Resource'ları kontrol et"""
        print("\n[4] RESOURCE'LAR")
        print("-" * 80)

        if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            resource_types = {
                1: 'Cursor',
                2: 'Bitmap',
                3: 'Icon',
                4: 'Menu',
                5: 'Dialog',
                6: 'String Table',
                10: 'RC Data',
                16: 'Version Info',
                24: 'Manifest'
            }

            resources = {}
            for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                res_type = resource_types.get(entry.id, f'Type {entry.id}')
                resources[res_type] = resources.get(res_type, 0) + 1

            if resources:
                print("  DLL içinde resource'lar var:")
                for res_type, count in resources.items():
                    print(f"    - {res_type}: {count} adet")
            else:
                print("  ℹ️  Resource bulunamadı")
        else:
            print("  ℹ️  Resource directory yok")

    def analyze_exports_imports(self):
        """Export ve Import detayları"""
        print("\n[5] EXPORT/IMPORT ANALİZİ")
        print("-" * 80)

        # Exports
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            exports = []
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode('utf-8'))

            print(f"\n  [>>] EXPORTS: {len(exports)} fonksiyon")
            if exports:
                print(f"       Ilk 10 export:")
                for exp in exports[:10]:
                    print(f"         - {exp}")
                if len(exports) > 10:
                    print(f"         ... ve {len(exports) - 10} tane daha")
        else:
            print("\n  [>>] EXPORTS: YOK!")
            print("       [!] Bu DLL baska programlar tarafindan kullanilamaz!")

        # Imports
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            print(f"\n  [<<] IMPORTS: {len(self.pe.DIRECTORY_ENTRY_IMPORT)} DLL'den fonksiyon aliyor")

            # En çok import edilen DLL'ler
            import_counts = []
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8')
                count = len(entry.imports)
                import_counts.append((dll_name, count))

            import_counts.sort(key=lambda x: x[1], reverse=True)

            print("       En cok bagimli oldugu DLL'ler:")
            for dll, count in import_counts[:10]:
                print(f"         - {dll}: {count} fonksiyon")

    def how_to_run(self):
        """DLL nasıl çalıştırılır?"""
        print("\n[6] NASIL KULLANILIR / ÇALIŞTIRILIR?")
        print("=" * 80)

        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            print("\n[+] BU BIR KUTUPHANE DLL'I")
            print("\n    Kullanim yontemleri:")
            print("    [1] Baska bir programdan LoadLibrary() ile yukle")
            print("    [2] Python ile yukle:")
            print(f"        python dll_launcher.py {self.dll_path.name} -l")
            print("    [3] rundll32 ile calistir:")
            print(f"        rundll32 {self.dll_path.name},<fonksiyon_adi>")

        else:
            print("\n[-] BU BIR KUTUPHANE DLL'I DEGIL!")
            print("\n    Bu dosya muhtemelen:")
            print("      - Bir executable'in .dll uzantili hali")
            print("      - Bir oyunun/programin data dosyasi")
            print("      - Resource-only DLL")
            print("\n    Nasil kullanilir:")
            print("    [1] Orijinal programla birlikte kullanilmali")
            print("    [2] .exe uzantisina cevirip calistir (eger executable ise):")
            print(f"        copy {self.dll_path.name} test.exe")
            print("        test.exe")
            print("    [3] Hangi programin bu DLL'i kullandigini bul:")
            print(f"        python find_dll_usage.py {self.dll_path.name}")

        print("\n" + "=" * 80)

        # Özet
        print("\n[OZET]")
        print(f"   DLL Tipi: {self.dll_type}")
        if self.purpose:
            print("   Amaci:")
            for p in self.purpose[:5]:
                print(f"     {p}")

def main():
    if len(sys.argv) < 2:
        print("Kullanım: python understand_dll.py <dll_dosyası>")
        print("Örnek: python understand_dll.py orig.dll")
        return 1

    dll_path = sys.argv[1]
    analyzer = DLLAnalyzer(dll_path)

    if analyzer.analyze():
        print("\n[+] Analiz tamamlandi!")
        return 0
    else:
        print("\n[-] Analiz basarisiz!")
        return 1

if __name__ == "__main__":
    sys.exit(main())

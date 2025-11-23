#!/usr/bin/env python3
"""
DLL Kullanım Bulucu - Hangi program hangi DLL'i kullanıyor bul
"""
import psutil
import os
import sys
from pathlib import Path
import json

def find_processes_using_dll(dll_name):
    """Belirtilen DLL'i kullanan tüm processleri bul"""
    dll_name_lower = dll_name.lower()
    results = []

    print(f"[*] Aranan DLL: {dll_name}")
    print(f"[*] Çalışan processleri tarıyorum...\n")

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            # Process bilgilerini al
            pid = proc.info['pid']
            name = proc.info['name']
            exe = proc.info['exe']

            # Process'in yüklediği modülleri kontrol et
            try:
                for dll in proc.memory_maps():
                    dll_path = dll.path
                    if dll_path and dll_name_lower in dll_path.lower():
                        result = {
                            'pid': pid,
                            'process_name': name,
                            'process_path': exe,
                            'dll_path': dll_path
                        }
                        results.append(result)
                        print(f"[+] BULUNDU!")
                        print(f"    Process: {name} (PID: {pid})")
                        print(f"    EXE: {exe}")
                        print(f"    DLL: {dll_path}\n")
                        break  # Bu process için bulundu, diğer modüllere bakmaya gerek yok
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

        except (psutil.AccessDenied, psutil.NoSuchProcess, SystemError):
            continue

    return results

def analyze_dll_location(dll_path):
    """DLL'in bulunduğu dizindeki diğer DLL'leri ve exe'leri bul"""
    dll_path = Path(dll_path)
    dll_dir = dll_path.parent

    print(f"\n[*] DLL Dizini Analizi: {dll_dir}")
    print("=" * 70)

    # Aynı dizindeki dosyalar
    dlls = []
    exes = []

    for file in dll_dir.glob("*"):
        if file.is_file():
            if file.suffix.lower() == '.dll':
                dlls.append(file.name)
            elif file.suffix.lower() == '.exe':
                exes.append(file.name)

    print(f"\n[*] Aynı dizindeki EXE dosyaları ({len(exes)}):")
    for exe in sorted(exes):
        print(f"    - {exe}")

    print(f"\n[*] Aynı dizindeki DLL dosyaları ({len(dlls)}):")
    for dll in sorted(dlls)[:20]:  # İlk 20'yi göster
        print(f"    - {dll}")

    if len(dlls) > 20:
        print(f"    ... ve {len(dlls) - 20} tane daha")

    return {
        'directory': str(dll_dir),
        'exe_files': exes,
        'dll_files': dlls
    }

def find_dll_dependencies(dll_path):
    """DLL'in import ettiği diğer DLL'leri bul"""
    try:
        import pefile

        pe = pefile.PE(dll_path)
        imports = {}

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8')
                imports[dll_name] = len(entry.imports)

        pe.close()

        if imports:
            print(f"\n[*] {Path(dll_path).name} Import Ettiği DLL'ler:")
            print("=" * 70)
            for dll, count in sorted(imports.items(), key=lambda x: x[1], reverse=True):
                print(f"    {dll:30s} : {count:4d} fonksiyon")

        return imports

    except ImportError:
        print("[!] pefile modülü bulunamadı. Import analizi yapılamıyor.")
        print("[*] Yüklemek için: pip install pefile")
        return {}
    except Exception as e:
        print(f"[!] Import analizi hatası: {e}")
        return {}

def monitor_dll_calls(dll_path, process_pid):
    """DLL fonksiyon çağrılarını izle (requires Frida)"""
    try:
        import frida

        print(f"\n[*] DLL Fonksiyon İzleme Başlatılıyor...")
        print(f"    Process PID: {process_pid}")
        print(f"    DLL: {dll_path}")
        print("=" * 70)

        session = frida.attach(process_pid)

        script_code = """
        var moduleName = "%s";
        var module = Process.getModuleByName(moduleName);

        console.log("[*] Module loaded at: " + module.base);
        console.log("[*] Module size: " + module.size);

        var exports = module.enumerateExports();
        console.log("[*] Exported functions: " + exports.length);

        exports.forEach(function(exp) {
            if (exp.type === 'function') {
                Interceptor.attach(exp.address, {
                    onEnter: function(args) {
                        console.log("[CALL] " + exp.name + " called");
                    }
                });
            }
        });
        """ % Path(dll_path).name

        script = session.create_script(script_code)
        script.load()

        print("[*] İzleme başladı. Durdurmak için Ctrl+C...")
        sys.stdin.read()

    except ImportError:
        print("[!] Frida modülü bulunamadı.")
        print("[*] Yüklemek için: pip install frida frida-tools")
    except Exception as e:
        print(f"[!] İzleme hatası: {e}")

def main():
    import argparse

    parser = argparse.ArgumentParser(description='DLL Kullanım Bulucu')
    parser.add_argument('dll', help='Aranacak DLL adı (örn: LX63.dll veya orig.dll)')
    parser.add_argument('-a', '--analyze', action='store_true', help='DLL dizinini ve bağımlılıklarını analiz et')
    parser.add_argument('-m', '--monitor', type=int, metavar='PID', help='Process içinde DLL çağrılarını izle')
    parser.add_argument('-s', '--save', metavar='FILE', help='Sonuçları JSON dosyasına kaydet')

    args = parser.parse_args()

    print("=" * 70)
    print("  DLL Kullanım Bulucu v1.0")
    print("=" * 70)
    print()

    # DLL'i kullanan processleri bul
    results = find_processes_using_dll(args.dll)

    if not results:
        print(f"[-] {args.dll} kullanılıyor bulunamadı.")
        print("[*] İpucu: DLL'in tam yolunu da deneyebilirsin")

        # Eğer DLL dosya olarak varsa, dizinini analiz et
        if os.path.exists(args.dll):
            print(f"\n[*] {args.dll} dosyası bulundu, dizin analizi yapılıyor...")
            analyze_dll_location(args.dll)
            find_dll_dependencies(args.dll)
    else:
        print(f"[+] Toplam {len(results)} process bulundu\n")

        # İlk bulunan DLL'in analizi
        if args.analyze and results:
            dll_path = results[0]['dll_path']
            analyze_dll_location(dll_path)
            find_dll_dependencies(dll_path)

        # Monitoring
        if args.monitor:
            if results:
                dll_path = results[0]['dll_path']
                monitor_dll_calls(dll_path, args.monitor)

        # Sonuçları kaydet
        if args.save:
            output = {
                'dll_searched': args.dll,
                'processes_found': results,
                'total_count': len(results)
            }

            with open(args.save, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2)
            print(f"\n[+] Sonuçlar kaydedildi: {args.save}")

    return 0 if results else 1

if __name__ == "__main__":
    sys.exit(main())

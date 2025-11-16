#!/usr/bin/env python3
"""
DLL Monitoring - DLL yüklendiğinde ne yaptığını izle
"""
import ctypes
import os
import sys
import time
import threading
from pathlib import Path
import socket

class DLLMonitor:
    def __init__(self, dll_path):
        self.dll_path = Path(dll_path)
        self.dll_handle = None
        self.monitoring = False
        self.logs = []

    def log(self, message):
        """Log mesajı kaydet"""
        timestamp = time.strftime("%H:%M:%S")
        msg = f"[{timestamp}] {message}"
        print(msg)
        self.logs.append(msg)

    def check_files_created(self, directory=None):
        """Yeni oluşturulan dosyaları kontrol et"""
        if directory is None:
            directory = self.dll_path.parent

        before = set()
        for file in Path(directory).glob("*"):
            before.add(file.name)

        self.log(f"[Monitor] Dizinde {len(before)} dosya var")

        # DLL'i yükle
        self.load_dll()

        time.sleep(2)  # Biraz bekle

        # Sonraki durumu kontrol et
        after = set()
        for file in Path(directory).glob("*"):
            after.add(file.name)

        new_files = after - before
        if new_files:
            self.log("[+] YENİ DOSYALAR OLUŞTURULDU:")
            for f in new_files:
                full_path = directory / f
                size = full_path.stat().st_size
                self.log(f"    - {f} ({size} bytes)")
        else:
            self.log("[*] Yeni dosya oluşturulmadı")

        return new_files

    def check_network(self):
        """Network bağlantılarını kontrol et"""
        try:
            import psutil

            current_pid = os.getpid()
            proc = psutil.Process(current_pid)

            self.log("[Monitor] Network bağlantıları kontrol ediliyor...")

            # DLL'i yüklemeden önce
            before_conns = set()
            try:
                for conn in proc.connections():
                    before_conns.add((conn.laddr, conn.raddr if conn.raddr else None))
            except:
                pass

            # DLL'i yükle
            self.load_dll()

            time.sleep(2)

            # Sonraki durumu kontrol et
            after_conns = set()
            try:
                for conn in proc.connections():
                    after_conns.add((conn.laddr, conn.raddr if conn.raddr else None))
            except:
                pass

            new_conns = after_conns - before_conns
            if new_conns:
                self.log("[+] YENİ NETWORK BAĞLANTILARI:")
                for conn in new_conns:
                    self.log(f"    - {conn}")
            else:
                self.log("[*] Yeni network bağlantısı yok")

        except ImportError:
            self.log("[!] psutil modülü gerekli: pip install psutil")
        except Exception as e:
            self.log(f"[!] Network kontrol hatası: {e}")

    def check_threads(self):
        """Thread oluşturuldu mu kontrol et"""
        try:
            import psutil

            current_pid = os.getpid()
            proc = psutil.Process(current_pid)

            before_threads = proc.num_threads()
            self.log(f"[Monitor] Başlangıç thread sayısı: {before_threads}")

            # DLL'i yükle
            self.load_dll()

            time.sleep(1)

            after_threads = proc.num_threads()
            self.log(f"[Monitor] Sonraki thread sayısı: {after_threads}")

            if after_threads > before_threads:
                self.log(f"[+] {after_threads - before_threads} YENİ THREAD OLUŞTURULDU!")
            else:
                self.log("[*] Yeni thread oluşturulmadı")

        except ImportError:
            self.log("[!] psutil modülü gerekli: pip install psutil")
        except Exception as e:
            self.log(f"[!] Thread kontrol hatası: {e}")

    def check_memory_activity(self):
        """Bellek kullanımını izle"""
        try:
            import psutil

            proc = psutil.Process(os.getpid())

            before_mem = proc.memory_info().rss / (1024 * 1024)  # MB
            self.log(f"[Monitor] Başlangıç bellek: {before_mem:.2f} MB")

            # DLL'i yükle
            self.load_dll()

            time.sleep(1)

            after_mem = proc.memory_info().rss / (1024 * 1024)  # MB
            self.log(f"[Monitor] Sonraki bellek: {after_mem:.2f} MB")

            diff = after_mem - before_mem
            if diff > 1:  # 1 MB'den fazla artış
                self.log(f"[+] Bellek kullanımı arttı: +{diff:.2f} MB")
            else:
                self.log(f"[*] Bellek değişimi: {diff:.2f} MB")

        except ImportError:
            self.log("[!] psutil modülü gerekli")
        except Exception as e:
            self.log(f"[!] Bellek kontrol hatası: {e}")

    def scan_strings_in_memory(self):
        """DLL'in belleğindeki string'leri tara"""
        if not self.dll_handle:
            return

        try:
            # DLL base adresini al
            kernel32 = ctypes.windll.kernel32

            # MEMORY_BASIC_INFORMATION yapısı
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", ctypes.c_ulong),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", ctypes.c_ulong),
                    ("Protect", ctypes.c_ulong),
                    ("Type", ctypes.c_ulong),
                ]

            self.log("[Monitor] Bellekteki string'ler aranıyor...")

            # DLL'in base adresinden başla
            base_addr = self.dll_handle._handle
            self.log(f"[Monitor] DLL Base Address: {hex(base_addr)}")

        except Exception as e:
            self.log(f"[!] Bellek tarama hatası: {e}")

    def load_dll(self):
        """DLL'i yükle"""
        if self.dll_handle:
            return  # Zaten yüklü

        try:
            self.log(f"[*] DLL yükleniyor: {self.dll_path}")
            self.dll_handle = ctypes.WinDLL(str(self.dll_path.absolute()))
            self.log(f"[+] DLL yüklendi! Handle: {self.dll_handle._handle}")
            return True
        except Exception as e:
            self.log(f"[-] DLL yükleme hatası: {e}")
            return False

    def unload_dll(self):
        """DLL'i kaldır"""
        if self.dll_handle:
            try:
                ctypes.windll.kernel32.FreeLibrary(self.dll_handle._handle)
                self.dll_handle = None
                self.log("[+] DLL kaldırıldı")
            except Exception as e:
                self.log(f"[-] DLL kaldırma hatası: {e}")

    def full_monitor(self):
        """Tam monitoring - tüm kontrolleri yap"""
        print("=" * 70)
        print("  DLL MONITORING - Davranış Analizi")
        print("=" * 70)
        print()

        self.log("[*] Monitoring başlatılıyor...")
        self.log(f"[*] DLL: {self.dll_path.name}")
        print()

        # 1. Bellek kontrolü
        print("\n[1] BELLEK KULLANIMI")
        print("-" * 70)
        self.check_memory_activity()

        # Önceki handle'ı temizle
        if self.dll_handle:
            self.unload_dll()
            time.sleep(0.5)

        # 2. Thread kontrolü
        print("\n[2] THREAD OLUŞTURMA")
        print("-" * 70)
        self.check_threads()

        if self.dll_handle:
            self.unload_dll()
            time.sleep(0.5)

        # 3. Dosya kontrolü
        print("\n[3] DOSYA SİSTEMİ")
        print("-" * 70)
        self.check_files_created()

        if self.dll_handle:
            self.unload_dll()
            time.sleep(0.5)

        # 4. Network kontrolü
        print("\n[4] NETWORK AKTİVİTESİ")
        print("-" * 70)
        self.check_network()

        print("\n" + "=" * 70)
        print("\n[*] Monitoring tamamlandı!")

        # Log'ları kaydet
        log_file = self.dll_path.stem + "_monitor_log.txt"
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(self.logs))
        print(f"[+] Log kaydedildi: {log_file}")

    def interactive_monitor(self):
        """İnteraktif monitoring - kullanıcı kontrollü"""
        print("=" * 70)
        print("  DLL INTERACTIVE MONITORING")
        print("=" * 70)
        print()

        # DLL'i yükle
        if not self.load_dll():
            return

        print("\n[*] DLL yüklendi ve çalışıyor!")
        print("[*] İzleme başladı. Aşağıdaki komutları kullanabilirsin:")
        print()
        print("  Komutlar:")
        print("    files   - Yeni dosyaları listele")
        print("    net     - Network bağlantılarını göster")
        print("    mem     - Bellek kullanımını göster")
        print("    threads - Thread sayısını göster")
        print("    exit    - Çıkış")
        print()

        try:
            import psutil
            proc = psutil.Process(os.getpid())

            while True:
                cmd = input("[Monitor] > ").strip().lower()

                if cmd == 'exit':
                    break
                elif cmd == 'files':
                    directory = self.dll_path.parent
                    files = list(Path(directory).glob("*"))
                    self.log(f"Dizinde {len(files)} dosya var")
                    for f in sorted(files)[-10:]:  # Son 10
                        print(f"  - {f.name}")
                elif cmd == 'net':
                    try:
                        conns = proc.connections()
                        if conns:
                            self.log(f"{len(conns)} network bağlantısı:")
                            for conn in conns:
                                print(f"  {conn}")
                        else:
                            self.log("Network bağlantısı yok")
                    except:
                        self.log("Network bağlantıları okunamadı")
                elif cmd == 'mem':
                    mem = proc.memory_info().rss / (1024 * 1024)
                    self.log(f"Bellek kullanımı: {mem:.2f} MB")
                elif cmd == 'threads':
                    threads = proc.num_threads()
                    self.log(f"Thread sayısı: {threads}")
                else:
                    print("Geçersiz komut!")

        except ImportError:
            print("[!] psutil modülü gerekli: pip install psutil")
        except KeyboardInterrupt:
            print("\n[*] Monitoring durduruluyor...")
        finally:
            self.unload_dll()

def main():
    import argparse

    parser = argparse.ArgumentParser(description='DLL Behavior Monitor')
    parser.add_argument('dll', help='İzlenecek DLL dosyası')
    parser.add_argument('-f', '--full', action='store_true', help='Tam otomatik monitoring')
    parser.add_argument('-i', '--interactive', action='store_true', help='İnteraktif monitoring')

    args = parser.parse_args()

    if not os.path.exists(args.dll):
        print(f"[-] DLL bulunamadı: {args.dll}")
        return 1

    monitor = DLLMonitor(args.dll)

    if args.full:
        monitor.full_monitor()
    elif args.interactive:
        monitor.interactive_monitor()
    else:
        # Varsayılan: full monitoring
        monitor.full_monitor()

    return 0

if __name__ == "__main__":
    sys.exit(main())

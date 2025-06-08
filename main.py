import sys
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QPushButton, QLabel, QFileDialog, QProgressBar,
                           QComboBox, QSpinBox, QGroupBox, QHBoxLayout)
from PySide6.QtCore import Qt, QThread, Signal
import socket
import os
from scapy.all import *
from cryptography.fernet import Fernet
import hashlib
from security import SecurityManager
from network_utils import NetworkUtils
import time

CHUNK_SIZE = 1024 * 1024  # 1MB chunks

class FileTransferThread(QThread):
    progress = Signal(int)
    status = Signal(str)
    network_stats = Signal(dict)
    
    def __init__(self, file_path, host, port, is_sender=True, ttl=64, flags="DF"):
        super().__init__()
        self.file_path = file_path
        self.host = host
        self.port = port
        self.is_sender = is_sender
        self.security = SecurityManager()
        self.network = NetworkUtils()
        self.ttl = ttl
        self.flags = flags
        
    def run(self):
        if self.is_sender:
            self.send_file()
        else:
            self.receive_file()
    
    def send_file(self):
        try:
            self.status.emit("Dosya gönderme başlatılıyor...")
            print("Dosya gönderme başlatılıyor...") # Terminal çıktısı
            # Dosya boyutunu ve hash'ini hesapla
            file_size = os.path.getsize(self.file_path)
            file_hash = self.security.calculate_file_hash(self.file_path)
            
            # TCP soketi oluştur
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            self.status.emit(f"{self.host}:{self.port} adresine bağlanıldı.")
            
            # Header bilgilerini gönder
            file_name = os.path.basename(self.file_path)
            header = f"{file_name}|{file_size}|{file_hash}"
            sock.sendall(header.encode())
            self.status.emit("Dosya başlığı gönderildi.")
            
            # Dosyayı parçalara bölerek gönder
            sent = 0
            with open(self.file_path, 'rb') as f:
                while sent < file_size:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    # Chunk'ı şifrele
                    encrypted_chunk = self.security.encrypt_data(chunk)
                    
                    # IP başlığı oluştur (kullanıcı tarafından belirlenen TTL ve Flags ile)
                    # Burada Scapy ile doğrudan paketi göndermiyoruz, sadece soket üzerinden veri akışı sağlıyoruz
                    # IP başlığı manipülasyonu soket seviyesinde değil, daha düşük seviyede (RAW soket) gereklidir.
                    # Mevcut TCP soketi kullanımı bu tür bir manipülasyona izin vermez.
                    # Sadece gösterim amaçlı olarak IP başlığı oluşturma kısmı kalabilir.
                    # Gerçek bir düşük seviye IP başlığı manipülasyonu için RAW soket veya Scapy'nin send/sr fonksiyonları gerekir.
                    
                    # Örnek IP başlığı oluşturma (şu anki TCP soketi için doğrudan kullanılmaz)
                    # ip_header = IP(
                    #    src=sock.getsockname()[0], # Kendi IP adresimiz
                    #    dst=self.host,
                    #    ttl=self.ttl,
                    #    flags=self.flags if self.flags != "None" else ""
                    # )
                    
                    sock.sendall(encrypted_chunk)
                    
                    sent += len(chunk)
                    progress = int((sent / file_size) * 100)
                    self.progress.emit(progress)
                    print(f"Gönderilen: {progress}%") # Terminal çıktısı
            
            self.status.emit("Dosya başarıyla gönderildi!")
            print("Dosya başarıyla gönderildi!") # Terminal çıktısı
            sock.close()
            
        except socket.error as e:
            self.status.emit(f"Soket Hatası: {e}. Port kullanımda olabilir veya bağlantı sorunları var.")
            print(f"Soket Hatası (Gönderme): {e}") # Terminal çıktısı
        except Exception as e:
            self.status.emit(f"Gönderme Hatası: {str(e)}")
            print(f"Gönderme Hatası: {str(e)}") # Terminal çıktısı
    
    def receive_file(self):
        try:
            self.status.emit("Dosya alma başlatılıyor... Bağlantı bekleniyor.")
            print("Dosya alma başlatılıyor... Bağlantı bekleniyor.") # Terminal çıktısı
            # TCP soketi oluştur
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Portu tekrar kullanmayı dene
            sock.bind((self.host, self.port))
            sock.listen(1)
            
            self.status.emit(f"{self.host}:{self.port} adresinde bağlantı bekleniyor...")
            print(f"{self.host}:{self.port} adresinde bağlantı bekleniyor...") # Terminal çıktısı
            conn, addr = sock.accept()
            self.status.emit(f"{addr[0]}:{addr[1]} adresinden bağlantı kabul edildi.")
            print(f"{addr[0]}:{addr[1]} adresinden bağlantı kabul edildi.") # Terminal çıktısı
            
            # Header'ı al
            header = conn.recv(1024).decode()
            file_name, file_size, file_hash = header.split('|')
            file_size = int(file_size)
            self.status.emit(f"Alınacak dosya: {file_name} ({file_size} bytes)")
            print(f"Alınacak dosya: {file_name} ({file_size} bytes)") # Terminal çıktısı

            # Dosyayı proje klasörüne kaydet
            output_file_path = os.path.join(os.getcwd(), file_name)
            received = 0
            
            with open(output_file_path, 'wb') as f:
                while received < file_size:
                    # Şifrelenmiş chunk'ı al
                    encrypted_chunk = conn.recv(CHUNK_SIZE)
                    if not encrypted_chunk:
                        break
                    
                    # Chunk'ı çöz
                    chunk = self.security.decrypt_data(encrypted_chunk)
                    f.write(chunk)
                    
                    received += len(chunk)
                    progress = int((received / file_size) * 100)
                    self.progress.emit(progress)
                    print(f"Alınan: {progress}%") # Terminal çıktısı
            
            # Dosya bütünlüğünü kontrol et
            if self.security.verify_file_integrity(output_file_path, file_hash):
                self.status.emit(f"Dosya başarıyla alındı ve bütünlüğü doğrulandı: {file_name}")
                print(f"Dosya başarıyla alındı ve bütünlüğü doğrulandı: {file_name}") # Terminal çıktısı
                # Başarılı alım onayı için boş bir dosya oluştur
                with open(os.path.join(os.getcwd(), f"received_{file_name}.txt"), "w") as f:
                    f.write(f"Dosya {file_name} başarıyla alındı ve {time.ctime()} tarihinde kaydedildi.")
                print(f"Onay dosyası oluşturuldu: received_{file_name}.txt") # Terminal çıktısı
            else:
                os.remove(output_file_path) # Hatalı dosyayı sil
                self.status.emit("Dosya bütünlüğü doğrulanamadı! Dosya silindi.")
                print("Dosya bütünlüğü doğrulanamadı! Dosya silindi.") # Terminal çıktısı
            
            conn.close()
            sock.close()
            print("Soketler kapatıldı.") # Terminal çıktısı
            
        except socket.error as e:
            self.status.emit(f"Soket Hatası: {e}. Port kullanımda olabilir veya bağlantı sorunları var.")
            print(f"Soket Hatası (Alma): {e}") # Terminal çıktısı
        except Exception as e:
            self.status.emit(f"Alma Hatası: {str(e)}")
            print(f"Alma Hatası: {str(e)}") # Terminal çıktısı

class WorkerThread(QThread):
    status = Signal(str)
    network_stats_result = Signal(dict)
    mitm_result_signal = Signal(bool)

    def __init__(self, task_type, host=None, port=None, interface=None):
        super().__init__()
        self.task_type = task_type
        self.host = host
        self.port = port
        self.interface = interface
        self.network = NetworkUtils()

    def run(self):
        try:
            if self.task_type == "network_performance":
                self.status.emit("Ağ performans testi yapılıyor...")
                print("Ağ performans testi yapılıyor...") # Terminal çıktısı
                rtt = self.network.measure_rtt(self.host)
                self.status.emit("Bant genişliği ölçümü için iperf3 sunucusunun (iperf3 -s) çalışıyor olması gerekir.")
                print("Bant genişliği ölçümü için iperf3 sunucusunun (iperf3 -s) çalışıyor olması gerekir.") # Terminal çıktısı
                bandwidth = self.network.measure_bandwidth(self.host, self.port) 
                self.network_stats_result.emit({"rtt": rtt, "bandwidth": bandwidth})
                self.status.emit("Ağ performans testi tamamlandı.")
                print("Ağ performans testi tamamlandı.") # Terminal çıktısı
            elif self.task_type == "mitm_simulation":
                self.status.emit("MITM simülasyonu (ARP Zehirlenmesi Tespiti) başlatılıyor...")
                print("MITM simülasyonu (ARP Zehirlenmesi Tespiti) başlatılıyor...") # Terminal çıktısı
                is_spoofing_detected = self.network.detect_arp_spoofing(self.interface)
                self.mitm_result_signal.emit(is_spoofing_detected) # Sinyali emit et
                if is_spoofing_detected is True:
                    self.status.emit("MITM Simülasyonu: ARP Zehirlenmesi TESPIT EDILDI!")
                    print("MITM Simülasyonu: ARP Zehirlenmesi TESPIT EDILDI!") # Terminal çıktısı
                elif is_spoofing_detected is False:
                    self.status.emit("MITM Simülasyonu: ARP Zehirlenmesi TESPIT EDILMEDI.")
                    print("MITM Simülasyonu: ARP Zehirlenmesi TESPIT EDILMEDI.") # Terminal çıktısı
                else:
                    self.status.emit("MITM Simülasyonu: Tespit sırasında bir hata oluştu.")
                    print("MITM Simülasyonu: Tespit sırasında bir hata oluştu.") # Terminal çıktısı
        except Exception as e:
            self.status.emit(f"Çalışan İşlem Hatası: {str(e)}")
            print(f"Çalışan İşlem Hatası: {str(e)}") # Terminal çıktısı

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Dosya Aktarım Sistemi")
        self.setGeometry(100, 100, 800, 600)
        
        # Ana widget ve layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Dosya seçme grubu
        file_group = QGroupBox("Dosya İşlemleri")
        file_layout = QVBoxLayout()
        
        self.select_file_btn = QPushButton("Dosya Seç")
        self.select_file_btn.clicked.connect(self.select_file)
        file_layout.addWidget(self.select_file_btn)
        
        self.file_label = QLabel("Dosya seçilmedi")
        file_layout.addWidget(self.file_label)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Ağ ayarları grubu
        network_group = QGroupBox("Ağ Ayarları")
        network_layout = QVBoxLayout()
        
        # Host ve port seçimi
        host_port_layout = QHBoxLayout()
        self.host_input = QComboBox()
        self.host_input.addItems(["localhost", "127.0.0.1"])
        self.host_input.setEditable(True)
        host_port_layout.addWidget(QLabel("Host:"))
        host_port_layout.addWidget(self.host_input)
        
        self.port_input = QSpinBox()
        self.port_input.setRange(1024, 65535)
        self.port_input.setValue(5000)
        host_port_layout.addWidget(QLabel("Port:"))
        host_port_layout.addWidget(self.port_input)
        
        network_layout.addLayout(host_port_layout)
        
        # Ağ arayüzü seçimi
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(NetworkUtils.get_network_interfaces())
        network_layout.addWidget(QLabel("Ağ Arayüzü:"))
        network_layout.addWidget(self.interface_combo)
        
        network_group.setLayout(network_layout)
        layout.addWidget(network_group)
        
        # IP Başlığı Ayarları Grubu
        ip_header_group = QGroupBox("IP Başlığı Ayarları")
        ip_header_layout = QHBoxLayout()

        self.ttl_input = QSpinBox()
        self.ttl_input.setRange(1, 255)
        self.ttl_input.setValue(64)
        ip_header_layout.addWidget(QLabel("TTL:"))
        ip_header_layout.addWidget(self.ttl_input)

        self.flags_input = QComboBox()
        self.flags_input.addItems(["DF", "MF", "None"])
        ip_header_layout.addWidget(QLabel("Flags:"))
        ip_header_layout.addWidget(self.flags_input)

        ip_header_group.setLayout(ip_header_layout)
        layout.addWidget(ip_header_group)
        
        # Gönder/Al butonları
        button_layout = QHBoxLayout()
        self.send_btn = QPushButton("Gönder")
        self.send_btn.clicked.connect(self.send_file)
        button_layout.addWidget(self.send_btn)
        
        self.receive_btn = QPushButton("Al")
        self.receive_btn.clicked.connect(self.receive_file)
        button_layout.addWidget(self.receive_btn)

        self.test_network_btn = QPushButton("Ağ Performans Testi")
        self.test_network_btn.clicked.connect(self.test_network_performance)
        button_layout.addWidget(self.test_network_btn)

        self.mitm_sim_btn = QPushButton("MITM Simülasyonu")
        self.mitm_sim_btn.clicked.connect(self.test_mitm_simulation)
        button_layout.addWidget(self.mitm_sim_btn)
        
        layout.addLayout(button_layout)
        
        # İlerleme çubuğu
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        # Ağ istatistikleri
        stats_group = QGroupBox("Ağ İstatistikleri")
        stats_layout = QVBoxLayout()
        
        self.rtt_label = QLabel("RTT: -- ms")
        stats_layout.addWidget(self.rtt_label)
        
        self.bandwidth_label = QLabel("Bant Genişliği: -- Mbps")
        stats_layout.addWidget(self.bandwidth_label)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Durum etiketi
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)
        
        self.selected_file = None
        self.transfer_thread = None
        self.worker_thread = None # WorkerThread için referans
    
    def select_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Dosya Seç")
        if file_name:
            self.selected_file = file_name
            self.file_label.setText(f"Seçilen dosya: {os.path.basename(file_name)}")
    
    def send_file(self):
        if not self.selected_file:
            self.status_label.setText("Lütfen önce bir dosya seçin!")
            return
        
        # Dosya gönderim thread'ini başlat
        self.transfer_thread = FileTransferThread(
            self.selected_file,
            self.host_input.currentText(),
            self.port_input.value(),
            is_sender=True,
            ttl=self.ttl_input.value(),
            flags=self.flags_input.currentText()
        )
        self.transfer_thread.progress.connect(self.update_progress)
        self.transfer_thread.status.connect(self.update_status)
        # Ağ istatistiklerini sadece test butonu ile güncelleyelim
        # self.transfer_thread.network_stats.connect(self.update_network_stats)

        self.transfer_thread.start()
    
    def receive_file(self):
        self.transfer_thread = FileTransferThread(
            None, # Alıcı için dosya yolu başlangıçta gerekli değil
            self.host_input.currentText(),
            self.port_input.value(),
            is_sender=False
        )
        self.transfer_thread.progress.connect(self.update_progress)
        self.transfer_thread.status.connect(self.update_status)
        # self.transfer_thread.network_stats.connect(self.update_network_stats) # Alıcıda ağ istatistiği yok
        self.transfer_thread.start()
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def update_status(self, message):
        self.status_label.setText(message)
    
    def update_network_stats(self, stats):
        if stats["rtt"] is not None:
            self.rtt_label.setText(f"RTT: {stats['rtt']:.2f} ms")
        else:
            self.rtt_label.setText("RTT: -- ms (Hata/Hesaplanamadı)")

        if stats["bandwidth"] is not None:
            self.bandwidth_label.setText(f"Bant Genişliği: {stats['bandwidth']/1000000:.2f} Mbps")
        else:
            self.bandwidth_label.setText("Bant Genişliği: -- Mbps (Hata/Hesaplanamadı)")

    def test_network_performance(self):
        host = self.host_input.currentText()
        port = self.port_input.value()
        
        self.worker_thread = WorkerThread("network_performance", host=host, port=port)
        self.worker_thread.status.connect(self.update_status)
        self.worker_thread.network_stats_result.connect(self.update_network_stats)
        self.worker_thread.start()

    def test_mitm_simulation(self):
        interface = self.interface_combo.currentText()
        if not interface:
            self.status_label.setText("Lütfen bir ağ arayüzü seçin!")
            return
        
        self.worker_thread = WorkerThread("mitm_simulation", interface=interface)
        self.worker_thread.status.connect(self.update_status)
        # MITM sonuçlarını worker_thread içinden doğrudan gönderdiğimiz için burada ek bir işleme gerek yok.
        self.worker_thread.mitm_result_signal.connect(self._handle_mitm_result)
        self.worker_thread.start()

    def _handle_mitm_result(self, is_spoofing_detected):
        # WorkerThread'den gelen sinyali işler, mesaj WorkerThread içinde ayarlanmıştır.
        pass # Durum mesajı zaten WorkerThread tarafından ayarlandığı için burada ek bir işlem yapmıyoruz.

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec()) 
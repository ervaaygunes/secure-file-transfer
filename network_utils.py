import socket
import time
import subprocess
import sys
from scapy.all import *
import psutil
import struct
import re
import json

class NetworkUtils:
    @staticmethod
    def calculate_ip_checksum(header):
        """IP başlığı için sağlama toplamı hesapla"""
        # Sağlama toplamı alanını sıfırla
        header = header[:10] + b'\x00\x00' + header[12:]
        
        # 16-bit kelimelere böl
        words = struct.unpack('!10H', header)
        
        # Tüm kelimeleri topla
        total = sum(words)
        
        # Taşan bitleri ekle
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        
        # Tümleyeni al
        checksum = ~total & 0xFFFF
        
        return checksum
    
    @staticmethod
    def create_custom_ip_header(src_ip, dst_ip, ttl=64, flags="DF"):
        """Özelleştirilmiş IP başlığı oluştur"""
        # IP başlığı oluştur
        ip_header = IP(
            src=src_ip,
            dst=dst_ip,
            ttl=ttl,
            flags=flags
        )
        
        # Sağlama toplamını hesapla ve ayarla
        raw_header = bytes(ip_header)
        checksum = NetworkUtils.calculate_ip_checksum(raw_header)
        ip_header.chksum = checksum
        
        return ip_header
    
    @staticmethod
    def verify_ip_checksum(packet):
        """IP paketinin sağlama toplamını doğrula"""
        if not packet.haslayer(IP):
            return False
        
        # Orijinal sağlama toplamını sakla
        original_checksum = packet[IP].chksum
        
        # Sağlama toplamı alanını sıfırla
        packet[IP].chksum = 0
        
        # Yeni sağlama toplamını hesapla
        raw_header = bytes(packet[IP])
        calculated_checksum = NetworkUtils.calculate_ip_checksum(raw_header)
        
        # Orijinal sağlama toplamını geri yükle
        packet[IP].chksum = original_checksum
        
        return calculated_checksum == original_checksum
    
    @staticmethod
    def measure_rtt(host, count=4):
        """Round Trip Time (RTT) ölçümü yap"""
        if sys.modules['platform'].system().lower() == "windows":
            ping_cmd = ["ping", "-n", str(count), host]
        else:
            ping_cmd = ["ping", "-c", str(count), host]
        
        try:
            output = subprocess.check_output(ping_cmd, timeout=5).decode()
            # Ortalama RTT'yi düzenli ifade ile bul
            match = re.search(r'min/avg/max/stddev = [^/]+/([^/]+)/', output)
            if match:
                avg_rtt = float(match.group(1))
                return avg_rtt
            
            # Windows çıktısı için kontrol (eğer macOS üzerinde de çalışıyorsa)
            match = re.search(r'Average = (\d+\.\d+)ms', output)
            if match:
                avg_rtt = float(match.group(1))
                return avg_rtt
            
            return None # Eşleşme bulunamazsa
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None
        except Exception as e:
            print(f"RTT ölçümü hatası: {e}")
            return None
    
    @staticmethod
    def measure_bandwidth(host, port, duration=10):
        """Bant genişliği ölçümü yap"""
        try:
            cmd = ["iperf3", "-c", host, "-p", str(port), "-t", str(duration), "-J"] # JSON çıktısı için -J ekledim
            output_json = subprocess.check_output(cmd, timeout=duration + 5).decode()
            data = json.loads(output_json)
            
            # İletimden gelen bit hızını al
            # iperf3 çıktısında birimler değişebilir (bits/sec, Kbits/sec, Mbits/sec, Gbits/sec)
            # Tümünü Mbps cinsine çevirelim.
            if "end" in data and "sum_sent" in data["end"]:
                bits_per_second = data["end"]["sum_sent"]["bits_per_second"]
                # Gelen değer bit/s olduğu için Mbps'e çevirelim (1 Mbps = 1,000,000 bit/s)
                bandwidth_mbps = bits_per_second / 1_000_000
                return bandwidth_mbps
            return None
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None
        except Exception as e:
            print(f"Bant genişliği ölçümü hatası: {e}")
            return None
    
    @staticmethod
    def simulate_packet_loss(interface, loss_percentage):
        """Paket kaybı simülasyonu yap"""
        try:
            # tc komutu ile paket kaybı simülasyonu
            cmd = f"tc qdisc add dev {interface} root netem loss {loss_percentage}%"
            subprocess.run(cmd, shell=True)
            return True
        except:
            return False
    
    @staticmethod
    def remove_packet_loss(interface):
        """Paket kaybı simülasyonunu kaldır"""
        try:
            cmd = f"tc qdisc del dev {interface} root"
            subprocess.run(cmd, shell=True)
            return True
        except:
            return False
    
    @staticmethod
    def get_network_interfaces():
        """Ağ arayüzlerini listele"""
        interfaces = []
        for interface, addrs in psutil.net_if_addrs().items():
            interfaces.append(interface)
        return interfaces
    
    @staticmethod
    def capture_packets(interface, count=10):
        """Belirtilen arayüzden paket yakala"""
        try:
            packets = sniff(iface=interface, count=count)
            return packets
        except:
            return None
    
    @staticmethod
    def analyze_packet(packet):
        """Paket analizi yap"""
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            ttl = packet[IP].ttl
            flags = packet[IP].flags
            checksum = packet[IP].chksum
            
            return {
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "protocol": protocol,
                "ttl": ttl,
                "flags": flags,
                "checksum": checksum,
                "checksum_valid": NetworkUtils.verify_ip_checksum(packet)
            }
        return None
    
    @staticmethod
    def detect_arp_spoofing(interface, target_ip=None):
        """ARP zehirlenmesini tespit etmeye çalışır.
        
        Belirtilen arayüzde ARP istekleri gönderir ve yanıtları analiz eder.
        Aynı IP için birden fazla MAC adresi tespit edilirse True döner.
        """
        try:
            # Ağdaki tüm cihazları keşfetmek için ARP isteği gönder
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2, iface=interface, verbose=0)
            
            mac_ip_map = {}
            for s, r in ans:
                mac = r.hwsrc
                ip = r.psrc
                
                if ip in mac_ip_map:
                    if mac_ip_map[ip] != mac:
                        print(f"[UYARI] ARP Zehirlenmesi Tespit Edildi: {ip} için farklı MAC adresleri ({mac_ip_map[ip]} ve {mac})")
                        return True # ARP zehirlenmesi tespit edildi
                else:
                    mac_ip_map[ip] = mac
            
            return False # ARP zehirlenmesi tespit edilmedi
        except Exception as e:
            print(f"ARP zehirlenmesi tespiti sırasında hata: {e}")
            return None 
# Dosya Aktarım Sistemi

Bu proje, güvenli dosya aktarımı, ağ performans ölçümü ve güvenlik analizi özelliklerini içeren bir ağ programlama projesidir.

## Özellikler

- ✅ Dosya Aktarım Sistemi
  - Ağ üzerinden dosya gönderme ve alma
  - Büyük dosya aktarımları için parçalama
  - Hata tespit ve düzeltme

- ✅ Güvenlik Mekanizmaları
  - AES şifreleme
  - Kimlik doğrulama
  - SHA-256 bütünlük doğrulaması

- ✅ Ağ Performansı Ölçümü
  - Gecikme ölçümü (RTT)
  - Bant genişliği analizi
  - Paket kaybı simülasyonu

- ✅ Güvenlik Analizi
  - Paket yakalama ve analiz
  - MITM saldırı simülasyonu
  - Şifreleme doğrulama

## Kurulum

1. Sanal ortam oluşturup gerekli paketleri yüklüyoruz:
```bash
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
```

2. iperf3'ü yükleyin:
- Windows: https://iperf.fr/iperf-download.php
- Linux: `sudo apt-get install iperf3`
- macOS: `brew install iperf3`

## Kullanım

1. Programı başlatın:
```bash
python main.py
```

2. Arayüz üzerinden:
   - Dosya seçin
   - Gönder veya Al butonuna tıklayın
   - İlerlemeyi takip edin

## Güvenlik

- Tüm dosya aktarımları AES şifreleme ile korunur
- SHA-256 hash ile dosya bütünlüğü doğrulanır
- Kimlik doğrulama için güvenli şifre hash'leme kullanılır

## Geliştirici

Bu proje, ağ programlama ve güvenlik konularında pratik deneyim kazanmak için geliştirilmiştir. 
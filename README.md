# Dosya Aktarım Sistemi

Bu proje, güvenli dosya aktarımı, ağ performans ölçümü ve MITM simülasyonu özelliklerine sahip bir uygulamadır. Python ve PySide6 kullanılarak geliştirilmiştir.

## Özellikler

### 1. Güvenli Dosya Aktarımı
- Dosya şifreleme ve çözme
- SHA-256 ile dosya bütünlüğü kontrolü
- Parçalı dosya aktarımı (chunk-based transfer)
- İlerleme durumu gösterimi
- Otomatik onay dosyası oluşturma

### 2. Ağ Performans Ölçümü
- RTT (Round Trip Time) ölçümü
- Bant genişliği ölçümü (iperf3 entegrasyonu)
- Gerçek zamanlı ağ istatistikleri
- Performans raporlama

### 3. MITM Simülasyonu
- ARP zehirlenmesi tespiti
- Ağ güvenlik analizi
- Güvenlik uyarıları

### 4. Kullanıcı Arayüzü
- Modern ve kullanıcı dostu GUI
- Gerçek zamanlı ilerleme çubuğu
- Ağ ayarları yapılandırma
- IP başlığı manipülasyonu seçenekleri

## Sistem Gereksinimleri

- Python 3.x
- macOS, Linux veya Windows işletim sistemi
- Root/yönetici yetkileri (Scapy özellikleri için)

## Gerekli Paketler

```bash
pip install PySide6    # GUI için
pip install scapy      # Ağ paket manipülasyonu için
pip install cryptography # Şifreleme için
pip install psutil     # Sistem ve ağ bilgileri için
pip install iperf3     # Bant genişliği ölçümü için
```

## Kurulum

1. Projeyi klonlayın:
```bash
git clone [proje-url]
cd [proje-dizini]
```

2. Sanal ortam oluşturun ve aktifleştirin:
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# veya
.\venv\Scripts\activate  # Windows
```

3. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

## Kullanım

### 1. Dosya Aktarımı

#### Alıcı Tarafı:
```bash
source venv/bin/activate
sudo python3 main.py
```
1. Host olarak "localhost" veya "127.0.0.1" seçin
2. Port olarak 5201 seçin
3. "Al" butonuna tıklayın

#### Gönderici Tarafı:
```bash
source venv/bin/activate
sudo python3 main.py
```
1. "Dosya Seç" butonuna tıklayın
2. Host olarak "localhost" veya "127.0.0.1" seçin
3. Port olarak 5000 seçin
4. "Gönder" butonuna tıklayın

### 2. Ağ Performans Testi

1. iperf3 sunucusunu başlatın:
```bash
iperf3 -s
```

2. Uygulamada:
   - Host olarak "localhost" seçin
   - "Ağ Performans Testi" butonuna tıklayın
   - Sonuçlar ağ istatistikleri bölümünde görüntülenecek

### 3. MITM Simülasyonu

1. Ağ arayüzü seçin (genellikle "en0" veya "en1")
2. "MITM Simülasyonu" butonuna tıklayın
3. Sonuçlar durum çubuğunda görüntülenecek

## Güvenlik Özellikleri

1. **Dosya Aktarım Güvenliği**:
   - Fernet şifreleme (symmetric encryption)
   - SHA-256 hash doğrulama
   - Otomatik bütünlük kontrolü

2. **Ağ Güvenliği**:
   - ARP zehirlenmesi tespiti
   - IP başlığı manipülasyonu
   - Paket analizi

## Hata Giderme

### 1. "Permission denied" Hatası
- Uygulamayı sudo ile çalıştırdığınızdan emin olun
- macOS'ta paket yakalama izinlerini kontrol edin

### 2. Bağlantı Hataları
- Port numarasının doğru olduğundan emin olun
- Host adresinin doğru olduğundan emin olun
- Güvenlik duvarı ayarlarını kontrol edin

### 3. iperf3 Hataları
- iperf3'ün yüklü olduğundan emin olun
- Sunucunun çalıştığından emin olun
- Varsayılan port (5201) kullanılabilir olmalı

### 4. Dosya Bütünlüğü Hataları
- Şifreleme/çözme işlemlerinin doğru çalıştığından emin olun
- Dosya boyutunun doğru aktarıldığını kontrol edin
- Hash değerlerinin eşleştiğini kontrol edin

## Geliştirme

### Proje Yapısı
```
├── main.py           # Ana uygulama
├── security.py       # Güvenlik modülü
├── network_utils.py  # Ağ yardımcı fonksiyonları
├── requirements.txt  # Bağımlılıklar
└── README.md         # Dokümantasyon
```

### Katkıda Bulunma
1. Fork yapın
2. Feature branch oluşturun
3. Değişikliklerinizi commit edin
4. Branch'inizi push edin
5. Pull Request oluşturun



## İletişim

Sorularınız veya önerileriniz için ervaaygunes8@gmail.com adresine mail atabilirsiniz. 

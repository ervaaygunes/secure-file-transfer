Proje Gereksinimleri Dokümanı (PRD)
Proje Başlığı: Gelişmiş Güvenli Dosya Aktarım Sistemi: Şifreleme, Düşük Seviyeli IP İşleme ve Ağ Performans Analizi
Hazırlayan: Erva Aygüneş - 22360859027 Bursa Teknik Üniversitesi - Bilgisayar Mühendisliği

1. Giriş
Bu doküman, "Gelişmiş Güvenli Dosya Aktarım Sistemi" başlıklı dönem projesinin ayrıntılı gereksinimlerini, hedeflerini ve teknik özelliklerini tanımlar. Projenin amacı, ağ üzerinde şifreli, güvenli ve analiz edilebilir bir dosya aktarım sistemi geliştirmektir. Bu sistem, şu unsurları içerecektir: şifreleme, IP başlıklarının manuel işlenmesi ve ağ performansının çeşitli şartlarda analiz edilmesi.

2. Amaçlar
	•	AES/RSA şifreleme ve bütünlük kontrolü ile güvenli dosya aktarımı geliştirmek
	•	TTL, bayraklar, sağlama toplamı ve parçalama gibi IP paket bileşenlerini manuel olarak işlemek
	•	Gecikme, bant genişliği ve paket kaybı gibi metriklerle ağ performansını ölçmek ve analiz etmek
	•	MITM gibi siber saldırı senaryolarını simüle ederek sistemin dayanıklılığını test etmek

3. Kapsam
Bu proje aşağıdaki modülleri içermektedir:
	•	Şifreleme ve özetleme teknikleri ile güvenli dosya iletimi
	•	IP başlıklarının manuel oluşturulması ve ayrıştırılması
	•	Farklı ağ koşulları altında performans testleri
	•	Paket dinleme ve siber saldırı simülasyonları

4. Sistem Özellikleri
4.1 Temel Fonksiyonel Gereksinimler (Zorunlu)
Dosya Aktarım Sistemi
	•	Socket ile dosya gönderme ve alma
	•	Büyük dosyalar için manuel parçalama ve yeniden birleştirme
	•	Temel hata tespiti ve düzeltme mekanizmalarının uygulanması
Güvenlik Mekanizmaları
	•	AES ile simetrik şifreleme, RSA ile anahtar değişimi
	•	SHA-256 ile bütünlük kontrolü
	•	Aktarım öncesi istemci kimlik doğrulaması
IP Başlık İşleme
	•	TTL, bayraklar, parçalama biti ve sağlama toplamı içeren IP paketlerini manuel oluşturma
	•	Göndermeden önce sağlama toplamı doğrulaması
	•	Alıcı tarafında yeniden birleştirme ve kontrol
Ağ Performans Ölçümü
	•	Ping/RTT hesaplamaları ile gecikme ölçümü
	•	iPerf3 ile bant genişliği testi
	•	tc aracı ile paket kaybı simülasyonu
	•	Wi-Fi vs. Ethernet, yerel vs. uzak gibi senaryoların karşılaştırması
Güvenlik Analizi & Saldırı Simülasyonu
	•	Wireshark ile paketlerin yakalanması
	•	MITM ve paket enjeksiyonu gibi saldırı senaryolarının test edilmesi
	•	Paket içeriklerinin şifreli ve okunamaz olduğunun doğrulanması

5. Ekstra Özellikler (Bonus Puan)
	•	Performansa göre TCP/UDP protokol geçişi
	•	Dinamik tıkanıklık kontrolü ile uyarlanabilir aktarım hızı
	•	Dosya aktarımını görselleştiren basit GUI
	•	Gerçek zamanlı sınırlandırma ve saldırı tespiti

6. Teknoloji Yığını
	•	Programlama Dili: Python 3
	•	Kütüphaneler: socket, pycryptodome, hashlib, Scapy
	•	Ağ Araçları: Wireshark, iPerf3, netstat, ping, tc
	•	Şifreleme: AES (ECB/CBC), RSA

7. Proje Takvimi
Aşama
Açıklama
Tarih
Proje Önerisi
Belge ve planlama
31 Mart 2025
Ara Rapor
AES şifreli iletişim uygulaması
28 Nisan 2025
Final Raporu
Tüm sistemin tamamlanması ve analiz
9 Haziran 2025

8. Kullanım Senaryoları
	1	Yerel ağda şifreli dosya gönderimi
	2	Paket kaybı senaryolarında dayanıklılık testi
	3	Yüksek gecikmeli ortamlarda (VPN) test
	4	Paketlerin dinlenip şifrelemeye karşı test edilmesi

9. Değerlendirme Kriterleri
	•	Dosya aktarım doğruluğu ve performansı
	•	Şifreleme ve kimlik doğrulama kalitesi
	•	IP başlığı işlemenin doğruluğu
	•	Performans metriklerinin doğruluğu
	•	Saldırı tespit ve savunma becerisi
	•	Kod ve doküman kalitesi (40 puan)

10. Kısıtlamalar ve Gelecek Çalışmalar
	•	AES şifrelemede önceden paylaşılmış anahtarlar kullanılmakta
	•	Parçalama algoritması hız için geliştirilebilir
	•	GUI henüz uygulanmadı (planlanıyor)

11. Raporlama Kuralları
	•	Yazı formatı: 12 punto, 1.5 satır aralığı, iki yana yaslı
	•	Bölümler: Giriş, Teknik Detaylar, Kısıtlamalar, Sonuç, Kaynaklar
	•	Kaynak gösterimi APA formatında
	•	YouTube videosu bağlantısı zorunlu
	•	Final raporu ve video LinkedIn'de paylaşılmalı

12. Kaynaklar
	1	Tanenbaum, A. S. (2010). Computer Networks.
	2	Wireshark ve iPerf3 Belgeleri
	3	IEEE/ACM Ağ Güvenliği Makaleleri
	4	Python PyCryptodome Belgeleri

Belgenin Sonu

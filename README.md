# 🔍 Simple Port Scanner (Python)

A simple and educational TCP-UDP port scanner written in Python.  
This project is designed for beginners who want to learn basic networking concepts, socket programming, and introductory penetration testing techniques.

---

## 🚀 Features
- TCP port scanning
- UDP port scanning
- Custom port range support
- Configurable timeout
- Multithreaded scanning for better performance
- Service name detection (standard ports)
- Improved banner grabbing (HTTP & non-HTTP)
- Command-line interface (CLI)
- Clean and readable Python code
- JSON output support

---

## ⚠️ Warning
Using a high number of threads may significantly increase scan speed, but it can also trigger firewalls, intrusion detection systems (IDS/IPS), or cause network instability.  
It is recommended to use a moderate number of threads (e.g., 50–200) and only scan systems you own or have explicit permission to test.

## Why UDP Is Unreliable for Port Scanning

- UDP (User Datagram Protocol) is inherently unreliable for generic port scanning.
- Unlike TCP, UDP is connectionless and does not provide a built-in handshake or acknowledgment mechanism.
- This makes it impossible to reliably determine port state using simple request–response logic.

## TCP vs UDP: Fundamental Difference
- TCP
 - Uses a 3-way handshake (SYN → SYN/ACK → ACK)
 - Clear and deterministic port states:
 - Open
 - Closed
 - Filtered
- UDP
 - No handshake
 - No guaranteed response
 - Silence is ambiguous
As a result, no response from a UDP port does NOT mean the port is open.

---

## 🛠️ Requirements
- Python 3.x  
(No external dependencies required)

---

## ⚙️ Usage
python scanner.py target -p 1-65535 -t 1 -T 100 --udp -o output.json

---

## Arguments
target — Target IP address or domain name

-h, --help — Show the help message

-p, --ports — Port range to scan (default: 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8000, 8888)

-t, --timeout — Connection timeout in seconds (default: 1)

-T, --threads — Number of threads to use (default: 100)

-o, --output — Output JSON file name

--udp — Enable UDP port scanning

---

## 📌 Example Output
- [+] TCP 80 OPEN | http | HTTP/1.1 200 OK
- [+] TCP 22 OPEN | ssh | Banner not available
- [+] UDP 53 OPEN | domain | No response

---

## ⚠️ Disclaimer
This tool is intended for educational purposes only.
Use it only on systems you own or have explicit permission to test.
The author is not responsible for any misuse.

---

## 📜 License
This project is licensed under the MIT License.

---

### 🔍 Basit Port Tarayıcı (Python)
Python ile yazılmış basit ve öğretici bir TCP-UDP port tarayıcıdır.
Ağ temellerini, socket programlamayı ve giriş seviyesi siber güvenlik / penetrasyon testi kavramlarını öğrenmek isteyenler için hazırlanmıştır.

---

#### 🚀 Özellikler
- TCP port tarama
- UDP port tarama
- Özel port aralığı desteği
- Ayarlanabilir timeout süresi
- Çoklu iş parçacığı (multithreaded) tarama
- Servis adı tespiti (standart portlar)
- Geliştirilmiş banner grabbing
- Komut satırı (CLI) desteği
- Temiz ve okunabilir Python kodu
- JSON çıktı desteği


---

## ⚠️ Uyarı  
Yüksek sayıda iş parçacığı (thread) kullanımı tarama hızını ciddi şekilde artırabilir; ancak güvenlik duvarlarını, saldırı tespit/önleme sistemlerini (IDS/IPS) tetikleyebilir veya ağ kararsızlığına neden olabilir.  
Genellikle orta seviyede bir thread sayısı (örn. 50–200) kullanılması ve yalnızca sahibi olduğunuz veya açık izniniz bulunan sistemlerin taranması önerilir.

## UDP Port Taramasının Neden Güvenilir Olmadığı
- UDP (User Datagram Protocol), genel amaçlı port taraması için doğası gereği güvenilir değildir.
- TCP’nin aksine UDP bağlantısızdır (connectionless) ve yerleşik bir el sıkışma (handshake) veya onay (acknowledgment) mekanizması sunmaz.
- Bu durum, basit istek–cevap mantığıyla bir UDP portunun durumunu güvenilir şekilde belirlemeyi imkânsız hale getirir.
## TCP vs UDP: Temel Farklar
- TCP
 - 3 aşamalı el sıkışma (SYN → SYN/ACK → ACK) kullanır
 - Net ve deterministik port durumları vardır:
 - Açık (Open)
 - Kapalı (Closed)
 - Filtrelenmiş (Filtered)
- UDP
 - El sıkışma yoktur
 - Cevap garantisi yoktur
 - Sessizlik belirsizdir
Sonuç olarak, bir UDP portundan cevap alınmaması portun açık olduğu anlamına gelmez.

---

#### 🛠️ Gereklilikler
- Python 3.x  
(Harici Bağımlılık Gerekmez)

---

#### ⚙️ Kullanım
python scanner.py hedef -p 1-1000 -t 1 -T 100 --udp -o çıktı.json

---

#### Argümanlar
hedef — Hedef IP Adres yada alan adı

-h, --help — Yardım mesajını gösterir

-p, --ports — Taranıcak port aralığı (varsayılan: 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8000, 8888)

-t, --timeout — Zaman aşımı süresi (saniye, varsayılan: 1)

-T, --threads — Kullanılacak iş parçacığı sayısı (varsayılan: 100)

-o, --output — JSON uzantılı çıktı dosyasının ismi

--udp — UDP port taramasını aktif eder

---

#### 📌 Örnek Çıktı
- [+] TCP 80 OPEN | http | HTTP/1.1 200 OK
- [+] TCP 22 OPEN | ssh | Banner not available
- [+] UDP 53 OPEN | domain | No response

---

#### ⚠️ Uyarı
Bu araç yalnızca eğitim amaçlıdır.
Yalnızca sahibi olduğunuz veya test etmek için açık izniniz bulunan sistemlerde kullanınız.
Her türlü yanlış veya kötüye kullanımın sorumluluğu kullanıcıya aittir.

---

#### 📜 License
Bu proje MIT Lisansı ile lisanslanmıştır.


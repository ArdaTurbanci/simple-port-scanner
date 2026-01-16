# 🔍 Simple Port Scanner (Python)
A simple and educational TCP port scanner written in Python.  
This project is designed for beginners who want to learn basic networking concepts, socket programming, and introductory penetration testing techniques.

---

## 🚀 Features
- TCP port scanning
- Custom port range support
- Configurable timeout
- Basic banner grabbing
- Command-line interface (CLI)
- Clean and readable Python code
- Multithreaded scanning for better performance
- JSON output support


---

## ⚠️ Warning  
Using a high number of threads may significantly increase scan speed, but it can also trigger firewalls, intrusion detection systems (IDS/IPS), or cause network instability.  
It is recommended to use a moderate number of threads (e.g., 50–200) and only scan systems you own or have explicit permission to test.

---

## 🛠️ Requirements
- Python 3.x  
(No external dependencies required)

---

## ⚙️ Usage
python scanner.py target -p 1-65535 -t 1 -T 100 -o output.json

---

## Arguments
target — Target IP address or domain name

-h, --help — Show the help message

-p, --ports — Port range to scan (default: 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8000, 8888)

-t, --timeout — Connection timeout in seconds (default: 1)

-T, --threads — Number of threads to use (default: 100)

-o, --output — Output JSON file name (default:scan_result.json)

---

## 📌 Example Output
- [+] Port 80 OPEN | HTTP/1.1 200 OK
- [+] Port 443 OPEN | Banner not available

---

## ⚠️ Disclaimer
This tool is intended for educational purposes only.
Use it only on systems you own or have explicit permission to test.
The author is not responsible for any misuse.

---

## 🔧 Future Improvements
- Service name detection
- UDP port scanning
- Improved banner grabbing

---

## 📜 License
This project is licensed under the MIT License.

---

### 🔍 Basit Port Tarayıcı (Python)
Python ile yazılmış basit ve öğretici bir TCP port tarayıcıdır.
Ağ temellerini, socket programlamayı ve giriş seviyesi siber güvenlik / penetrasyon testi kavramlarını öğrenmek isteyenler için hazırlanmıştır.

---

#### 🚀 Özellikler
- Daha iyi performans için çoklu iş parçacığı (multithreaded) tarama
- TCP port tarama
- Özel port aralığı desteği
- Ayarlanabilir timeout süresi
- Basit banner grabbing
- Komut satırı (CLI) desteği
- Temiz ve okunabilir Python kodu
- JSON çıktı desteği


---

## ⚠️ Uyarı  
Yüksek sayıda iş parçacığı (thread) kullanımı tarama hızını ciddi şekilde artırabilir; ancak güvenlik duvarlarını, saldırı tespit/önleme sistemlerini (IDS/IPS) tetikleyebilir veya ağ kararsızlığına neden olabilir.  
Genellikle orta seviyede bir thread sayısı (örn. 50–200) kullanılması ve yalnızca sahibi olduğunuz veya açık izniniz bulunan sistemlerin taranması önerilir.

---

#### 🛠️ Gereklilikler
- Python 3.x  
(Harici Bağımlılık Gerekmez)

---

#### ⚙️ Kullanım
python scanner.py hedef -p 1-1000 -t 1 -T 100 -o çıktı.json

---

#### Argümanlar
hedef — Hedef IP Adres yada alan adı

-h, --help — Yardım mesajını gösterir

-p, --ports — Taranıcak port aralığı (varsayılan: 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8000, 8888)

-t, --timeout — Zaman aşımı süresi (saniye, varsayılan: 1)

-T, --threads — Kullanılacak iş parçacığı sayısı (varsayılan: 100)

-o, --output — JSON uzantılı çıktı dosyasının ismi (varsayılan:scan_result.json)

---

#### 📌 Örnek Çıktı
- [+] Port 80 OPEN | HTTP/1.1 200 OK
- [+] Port 443 OPEN | Banner not available

---

#### ⚠️ Uyarı
Bu araç yalnızca eğitim amaçlıdır.
Yalnızca sahibi olduğunuz veya test etmek için açık izniniz bulunan sistemlerde kullanınız.
Her türlü yanlış veya kötüye kullanımın sorumluluğu kullanıcıya aittir.

---

#### 🔧 Gelecekteki Geliştirmeler
- Servis adı tespiti
- UDP port tarama
- Geliştirilmiş banner alma (banner grabbing)

---

#### 📜 License
Bu proje MIT Lisansı ile lisanslanmıştır.


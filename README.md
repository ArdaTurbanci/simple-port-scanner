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

---

## 🛠️ Requirements
- Python 3.x  
(No external dependencies required)

---

## ⚙️ Usage
python scanner.py target -p 1-1000 -t 1

---

## Arguments
target — Target IP address or domain name

-p, --ports — Port range to scan (default: 1-1024)

-t, --timeout — Connection timeout in seconds (default: 1)

---

## 📌 Example Output
[+] Port 80 OPEN | HTTP/1.1 200 OK
[+] Port 443 OPEN | Banner not available

---

## ⚠️ Disclaimer
This tool is intended for educational purposes only.
Use it only on systems you own or have explicit permission to test.
The author is not responsible for any misuse.

---

## 🔧 Future Improvements
- Multithreaded scanning for better performance
- JSON / CSV output support
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
- TCP port tarama
- Özel port aralığı desteği
- Ayarlanabilir timeout süresi
- Basit banner grabbing
- Komut satırı (CLI) desteği
- Temiz ve okunabilir Python kodu
---

#### 🛠️ Gereklilikler
- Python 3.x  
(Harici Bağımlılık Gerekmez)

---

#### ⚙️ Kullanım
python scanner.py hedef -p 1-1000 -t 1

---

#### Argümanlar
hedef — Hedef IP Adres yada alan adı

-p, --ports — Taranıcak Port Aralığı (Varsayılan: 1-1024)

-t, --timeout — Zaman aşımı süresi (saniye, varsayılan: 1)

---

#### 📌 Örnek Çıktı
[+] Port 80 OPEN | HTTP/1.1 200 OK
[+] Port 443 OPEN | Banner not available

---

#### ⚠️ Uyarı
Bu araç yalnızca eğitim amaçlıdır.
Yalnızca sahibi olduğunuz veya test etmek için açık izniniz bulunan sistemlerde kullanınız.
Her türlü yanlış veya kötüye kullanımın sorumluluğu kullanıcıya aittir.

---

#### 🔧 Gelecekteki Geliştirmeler
- Daha iyi performans için çoklu iş parçacığı (multithreaded) tarama
- JSON / CSV çıktı desteği
- Servis adı tespiti
- UDP port tarama
- Geliştirilmiş banner alma (banner grabbing)

---

#### 📜 License
Bu proje MIT Lisansı ile lisanslanmıştır.


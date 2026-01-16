import socket
import argparse
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Commonly used TCP ports
# Yaygın olarak kullanılan TCP portları
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5900,
    8080, 8443, 8000, 8888
]


def detect_service(port, protocol="tcp"):
    """
    Detects service name based on port number.
    Port numarasına göre servis adını tespit eder.
    """
    try:
        # Example: 80 -> http, 22 -> ssh
        # Örnek: 80 -> http, 22 -> ssh
        return socket.getservbyport(port, protocol)
    except:
        # If service is unknown or non-standard
        # Servis bilinmiyorsa veya standart değilse
        return "unknown"


def get_banner(sock, port):
    """
    Attempts to grab a service banner from an open TCP port.
    Açık TCP porttan servis banner'ı almaya çalışır.
    """
    try:
        # If HTTP-like service, send HEAD request
        # HTTP benzeri servis ise HEAD isteği gönder
        if port in [80, 8080, 8000, 8443]:
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        else:
            # For non-HTTP services, send minimal payload
            # HTTP olmayan servisler için minimal veri gönder
            sock.sendall(b"\r\n")

        # Receive up to 1024 bytes
        # En fazla 1024 byte cevap al
        banner = sock.recv(1024)

        if banner:
            # Decode safely and return first line
            # Güvenli decode et ve ilk satırı döndür
            return banner.decode(errors="ignore").strip().split("\n")[0]

    except:
        # Any error means banner is unavailable
        # Herhangi bir hata banner alınamadı demektir
        pass

    return "Banner not available"


def scan_tcp_port(target, port, timeout):
    """
    Scans a single TCP port.
    Tek bir TCP portu tarar.
    """
    try:
        # Create TCP socket
        # TCP socket oluştur
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # connect_ex returns 0 if port is open
        # connect_ex başarılıysa (0) port açıktır
        if sock.connect_ex((target, port)) == 0:
            service = detect_service(port, "tcp")
            banner = get_banner(sock, port)
            sock.close()

            return {
                "port": port,
                "protocol": "tcp",
                "status": "open",
                "service": service,
                "banner": banner
            }
    except:
        pass

    return None


def scan_udp_port(target, port, timeout):
    """
    Scans a single UDP port.
    Tek bir UDP portu tarar.
    """
    try:
        # Create UDP socket
        # UDP socket oluştur
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Send empty UDP packet
        # UDP porta boş paket gönder
        sock.sendto(b"", (target, port))

        # Try to receive response
        # Cevap almaya çalış
        data, _ = sock.recvfrom(1024)

        # If response is received, port is OPEN
        # Cevap geldiyse port AÇIK kabul edilir
        return {
            "port": port,
            "protocol": "udp",
            "status": "open",
            "service": detect_service(port, "udp"),
            "banner": data.decode(errors="ignore") if data else "response received"
        }

    except socket.timeout:
        # No response → open|filtered (UDP behavior)
        # Cevap yok → open|filtered (UDP doğası)
        return {
            "port": port,
            "protocol": "udp",
            "status": "open|filtered",
            "service": detect_service(port, "udp"),
            "banner": "no response"
        }

    except OSError:
        # ICMP unreachable → closed
        # ICMP unreachable → port kapalı
        return {
            "port": port,
            "protocol": "udp",
            "status": "closed",
            "service": detect_service(port, "udp"),
            "banner": "icmp unreachable"
        }


def parse_ports(port_range):
    """
    Parses port range like 1-65535.
    1-65535 gibi port aralığını ayrıştırır.
    """
    try:
        start, end = port_range.split("-")
        return list(range(int(start), int(end) + 1))
    except:
        print("[-] Invalid port range format / Geçersiz port aralığı")
        exit(1)


def save_json(results, filename, target):
    """
    Saves scan results to JSON file.
    Tarama sonuçlarını JSON dosyasına kaydeder.
    """
    output = {
        "target": target,
        "scan_time": datetime.now().isoformat(),
        "results": results
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)


def main():
    # CLI argument parser
    # Komut satırı argümanlarını tanımlar
    parser = argparse.ArgumentParser(description="Simple Port Scanner")

    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument("-p", "--ports", help="Port range (e.g. 1-65535)")
    parser.add_argument("-t", "--timeout", type=float, default=1)
    parser.add_argument("-T", "--threads", type=int, default=100)
    parser.add_argument("-o", "--output", default="scan_result.json")
    parser.add_argument("--udp", action="store_true", help="Enable UDP scan")

    args = parser.parse_args()

    # Determine port list
    # Taranacak portları belirle
    ports = parse_ports(args.ports) if args.ports else COMMON_PORTS
    results = []

    print(f"Target: {args.target}")
    print(f"Ports: {len(ports)}")
    print(f"UDP Scan: {'Enabled' if args.udp else 'Disabled'}")
    print("-" * 50)

    # Separate futures to avoid TCP/UDP mixing
    # TCP ve UDP sonuçlarının karışmaması için ayır
    tcp_futures = []
    udp_futures = []

    # Thread pool for concurrent scanning
    # Eşzamanlı tarama için thread pool
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for port in ports:
            # Submit TCP scan task
            # TCP tarama görevi ekle
            tcp_futures.append(
                executor.submit(scan_tcp_port, args.target, port, args.timeout)
            )

            # Submit UDP scan task if enabled
            # UDP açıksa UDP tarama görevi ekle
            if args.udp:
                udp_futures.append(
                    executor.submit(scan_udp_port, args.target, port, args.timeout)
                )

        # Process TCP scan results
        # TCP tarama sonuçlarını işle
        for future in as_completed(tcp_futures):
            result = future.result()
            if not result:
                continue

            results.append(result)

            print(
                f"[+] TCP {result['port']} OPEN | "
                f"{result['service']} | {result['banner']}"
            )

        # Process UDP scan results
        # UDP tarama sonuçlarını işle
        for future in as_completed(udp_futures):
            result = future.result()
            if not result:
                continue

            results.append(result)

            status = result["status"].upper()
            if status == "OPEN":
                prefix = "[+]"
            elif status == "OPEN|FILTERED":
                prefix = "[?]"
            else:
                prefix = "[-]"

            print(
                f"{prefix} UDP {result['port']} {status} | "
                f"{result['service']} | {result['banner']}"
            )

    # Save results
    # Sonuçları kaydet
    save_json(results, args.output, args.target)
    print(f"[+] Results saved to {args.output}")


# Program entry point
# Programın başlangıç noktası
if __name__ == "__main__":
    main()

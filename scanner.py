import socket
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Commonly used TCP ports
# Yaygın TCP portları
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995,
    1723, 3306, 3389, 5900,
    8080, 8443, 8000, 8888
]


def scan_port(target, port, timeout):
    """
    Scans a single TCP port on the target host.
    Belirtilen hedefte tek bir TCP portu tarar.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Check if the port is open
        # Port açık mı kontrol et
        if sock.connect_ex((target, port)) == 0:
            banner = get_banner(sock)
            return f"[+] Port {port} OPEN | {banner}"

        sock.close()
    except:
        pass

    return None


def get_banner(sock):
    """
    Attempts to retrieve a service banner from the open port.
    Açık porttan servis banner’ını almaya çalışır.
    """
    try:
        sock.sendall(b"HEAD / HTTP/1.1\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner.split("\n")[0] if banner else "Banner not available / Banner alınamadı"
    except:
        return "Banner not available / Banner alınamadı"


def parse_ports(port_range):
    """
    Parses a port range string (e.g. 1-1000).
    Port aralığını ayrıştırır (örn: 1-1000).
    """
    try:
        start, end = port_range.split("-")
        return list(range(int(start), int(end) + 1))
    except:
        print("[-] Invalid port range format / Geçersiz port aralığı formatı. Example: 1-1000")
        exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="TCP Port Scanner (Default ports)"
    )

    parser.add_argument(
        "target",
        help="Target IP address or domain name"
    )

    parser.add_argument(
        "-p", "--ports",
        help="Port range to scan (e.g. 1-1000). If not provided, common ports will be scanned."
    )

    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1,
        help="Connection timeout in seconds (default: 1)"
    )

    parser.add_argument(
        "-T", "--threads",
        type=int,
        default=100,
        help="Number of threads to use (default: 100)"
    )

    args = parser.parse_args()

    # Select ports
    # Portları belirle
    if args.ports:
        ports = parse_ports(args.ports)
        print("[*] Using custom port range / Özel port aralığı kullanılıyor")
    else:
        ports = COMMON_PORTS
        print("[*] Using common ports / Yaygın portlar kullanılıyor")

    print("-" * 60)
    print(f"Target / Hedef: {args.target}")
    print(f"Scan started at / Tarama başlangıcı: {datetime.now()}")
    print(f"Ports to scan / Taranacak port sayısı: {len(ports)}")
    print(f"Threads / İş parçacığı sayısı: {args.threads}")
    print("-" * 60)

    # Multithreaded scanning
    # Çoklu iş parçacığı ile tarama
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_port, args.target, port, args.timeout) for port in ports]

        for future in as_completed(futures):
            result = future.result()
            if result:
                print(result)


if __name__ == "__main__":
    main()

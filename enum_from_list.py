#!/usr/bin/env python3
import socket
import ssl
import concurrent.futures
import requests
from datetime import datetime

INPUT_FILE = "hosts.txt"
OUTPUT_FILE = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
TIMEOUT = 3  # seconds per connection
MAX_THREADS = 50


def test_port(host, port):
    """Try to connect to a host:port and return status + banner or title."""
    port = int(port)
    try:
        # Try a raw TCP connection first
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            # Basic service detection
            if port in [80, 8000, 8008, 8080, 8888]:
                try:
                    r = requests.get(f"http://{host}:{port}", timeout=TIMEOUT)
                    return (host, port, "OPEN", f"HTTP {r.status_code} {r.reason}", r.url)
                except Exception as e:
                    return (host, port, "OPEN", f"HTTP Fail: {type(e).__name__}", "")
            elif port == 443:
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    return (host, port, "OPEN", "HTTPS", cert.get("subject", ""))
            else:
                try:
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                    return (host, port, "OPEN", f"Banner: {banner[:60]}", "")
                except:
                    return (host, port, "OPEN", "No banner", "")
    except Exception as e:
        return (host, port, "CLOSED", str(e), "")


def main():
    with open(INPUT_FILE, "r") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    targets = []
    for line in lines:
        if ":" in line:
            host, port = line.split(":")
            targets.append((host.strip(), port.strip()))

    print(f"[+] Loaded {len(targets)} targets from {INPUT_FILE}")
    print("[*] Scanning...\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for res in executor.map(lambda t: test_port(*t), targets):
            results.append(res)
            host, port, status, info, extra = res
            print(f"{host}:{port} -> {status} | {info}")

    # Save results
    with open(OUTPUT_FILE, "w") as f:
        for host, port, status, info, extra in results:
            f.write(f"{host}:{port}\t{status}\t{info}\t{extra}\n")

    print(f"\n[✔] Scan complete. Results saved in: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

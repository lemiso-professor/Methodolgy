#!/usr/bin/env python3
"""
port_recon_extended.py

- Reads an input file of host:port lines OR common open-ports.txt/CSV styles.
- Tests TCP connect for each host:port.
- On OPEN ports:
    - grabs small banner,
    - runs httpx (if available) for HTTP ports,
    - runs nmap -sV (if available),
    - optional: run ffuf for directory fuzzing on HTTP (if --fuzz)
    - optional: run sqlmap on discovered URLs with query strings (if --sqlmap)

Usage:
  python3 port_recon_extended.py -i hosts.txt
  python3 port_recon_extended.py -i open-ports.txt --fuzz --wordlist /path/to/wordlist.txt
  python3 port_recon_extended.py -i hosts.txt --sqlmap

Caveats:
 - Active flags (--fuzz and --sqlmap) will run intrusive tests; use only with authorization.
 - Script looks for binaries nmap, httpx, ffuf, sqlmap on PATH.
"""
import argparse
import socket
import subprocess
import os
import csv
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from shutil import which

# ---- Config ----
TIMEOUT = 4
THREADS = 30
HTTP_PORTS = {80, 8000, 8008, 8080, 8443, 443}
DEFAULT_OUTBASE = "recon_results"
FFUF_TIMEOUT = 300      # seconds per ffuf run
SQLMAP_TIMEOUT = 600    # seconds per sqlmap run
NMAP_TIMEOUT = 180

# ---- Helpers ----
def ensure_outdir(base=None):
    base = base or DEFAULT_OUTBASE
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = f"{base}_{ts}"
    os.makedirs(outdir, exist_ok=True)
    return outdir

def parse_input_file(path):
    """
    Accepts:
      - lines like host:port
      - csv-like host,port
      - tab-separated host<tab>port
      - nmap-like "host:port/service"
    Returns list of (host, port) tuples.
    """
    targets = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # try common separators
            # host:port (preferred)
            if ":" in line and not line.count(":") > 1:  # avoid IPv6 mishaps (basic)
                # remove trailing / paths if any
                token = line.split()[0]
                # handle "host:port/service" by taking before slash
                token = token.split("/", 1)[0]
                host, port = token.rsplit(":", 1)
                if port.isdigit():
                    targets.append((host.strip(), int(port)))
                    continue
            # try comma
            if "," in line:
                parts = [p.strip() for p in line.split(",") if p.strip()]
                if len(parts) >= 2 and parts[1].isdigit():
                    targets.append((parts[0], int(parts[1])))
                    continue
            # try whitespace-separated (host port)
            parts = re.split(r'\s+', line)
            if len(parts) >= 2 and parts[1].isdigit():
                targets.append((parts[0], int(parts[1])))
                continue
            # If none matched, skip
    return targets

def tcp_connect(host, port, timeout=TIMEOUT):
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except Exception:
        return False, None
    for family, socktype, proto, canonname, sockaddr in infos:
        s = socket.socket(family, socktype, proto)
        s.settimeout(timeout)
        try:
            s.connect(sockaddr)
            return True, s
        except Exception:
            s.close()
            continue
    return False, None

def close_socket(s):
    try:
        s.close()
    except Exception:
        pass

def run_subprocess(cmd_list, outfile=None, timeout=60):
    try:
        if outfile:
            with open(outfile, "w") as fh:
                subprocess.run(cmd_list, stdout=fh, stderr=subprocess.STDOUT, text=True, timeout=timeout)
            return 0
        else:
            proc = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
            return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired:
        return -1, None
    except Exception as e:
        return -2, str(e)

# ---- Recon actions ----
def grab_banner(sock):
    try:
        sock.settimeout(1.0)
        try:
            sock.sendall(b"\r\n")
        except Exception:
            pass
        data = sock.recv(2048)
        text = data.decode(errors="ignore").strip()
        return text[:200]
    except Exception:
        return ""

def run_nmap(host, port, outdir):
    if which("nmap") is None:
        return ""
    outfile = os.path.join(outdir, f"nmap_{host}_{port}.txt")
    cmd = ["nmap", "-sV", "-p", str(port), "-oN", outfile, host]
    # write output using nmap's -oN
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=NMAP_TIMEOUT)
        return outfile
    except Exception:
        return ""

def run_httpx(host, port, outdir):
    httpx_bin = which("httpx")
    if not httpx_bin:
        return ""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}"
    outfile = os.path.join(outdir, f"httpx_{host}_{port}.txt")
    cmd = [httpx_bin, "-silent", "-no-color", "-url", url, "-status-code", "-title", "-location", "-o", outfile]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
        return outfile
    except Exception:
        return ""

def run_ffuf(host, port, outdir, wordlist, threads=40):
    ffuf_bin = which("ffuf")
    if not ffuf_bin:
        return ""
    scheme = "https" if port in (443, 8443) else "http"
    target = f"{scheme}://{host}:{port}/FUZZ"
    outfile = os.path.join(outdir, f"ffuf_{host}_{port}.txt")
    cmd = [ffuf_bin, "-u", target, "-w", wordlist, "-t", str(threads), "-o", outfile, "-mc", "200,301,302,401,403"]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=FFUF_TIMEOUT)
        return outfile
    except Exception:
        return ""

def discover_urls_from_httpx_file(httpx_file):
    """Return list of URLs (strings) found in httpx output file"""
    if not httpx_file or not os.path.exists(httpx_file):
        return []
    urls = []
    with open(httpx_file, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # httpx output often contains the URL as first token; try extract http(s)://...
            m = re.search(r'(https?://[^\s]+)', line)
            if m:
                urls.append(m.group(1))
    return urls

def run_sqlmap_on_urls(urls, outdir):
    sqlmap_bin = which("sqlmap")
    if not sqlmap_bin or not urls:
        return []
    results = []
    for url in urls:
        if "?" not in url:
            continue
        safe_name = re.sub(r'[:/\\?&=]', '_', url)[:120]
        outpath = os.path.join(outdir, f"sqlmap_{safe_name}.txt")
        cmd = [sqlmap_bin, "-u", url, "--batch", "--output-dir", outdir]
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=SQLMAP_TIMEOUT)
            results.append(outpath)
        except Exception:
            continue
    return results

# ---- Worker ----
def handle_target(host, port, base_outdir, do_fuzz=False, wordlist=None, do_sqlmap=False):
    hostdir = os.path.join(base_outdir, host)
    os.makedirs(hostdir, exist_ok=True)

    result = {
        "host": host,
        "port": port,
        "open": False,
        "banner": "",
        "nmap": "",
        "httpx": "",
        "ffuf": "",
        "sqlmap": "",
        "error": ""
    }

    ok, sock = tcp_connect(host, port)
    if not ok:
        return result

    result["open"] = True
    try:
        result["banner"] = grab_banner(sock)

        # run httpx if available and port looks like web
        if port in HTTP_PORTS and which("httpx"):
            result["httpx"] = run_httpx(host, port, hostdir)

        # always run nmap if available
        if which("nmap"):
            result["nmap"] = run_nmap(host, port, hostdir)

        # run ffuf if requested and port is HTTP
        if do_fuzz and port in HTTP_PORTS and wordlist:
            if which("ffuf"):
                result["ffuf"] = run_ffuf(host, port, hostdir, wordlist)
            else:
                result["ffuf"] = ""

        # run sqlmap if requested: discover query-URLs from httpx results
        if do_sqlmap and result["httpx"]:
            urls = discover_urls_from_httpx_file(result["httpx"])
            sqlpaths = run_sqlmap_on_urls(urls, hostdir)
            if sqlpaths:
                result["sqlmap"] = ";".join(os.path.basename(p) for p in sqlpaths)

    except Exception as e:
        result["error"] = str(e)
    finally:
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            close_socket(sock)

    return result

# ---- Main ----
def main():
    p = argparse.ArgumentParser(description="Port recon with optional ffuf/sqlmap (active tests require flags).")
    p.add_argument("-i", "--input", required=True, help="Input file (host:port lines or various open-ports/CSV formats)")
    p.add_argument("-o", "--outdir", default=None, help="Output base directory")
    p.add_argument("--fuzz", action="store_true", help="Run ffuf on HTTP ports (active testing)")
    p.add_argument("--sqlmap", action="store_true", help="Run sqlmap on discovered URLs with query strings (active testing)")
    p.add_argument("--wordlist", default=None, help="Wordlist for ffuf (required if --fuzz).")
    p.add_argument("-t", "--threads", type=int, default=THREADS, help="Concurrency")
    args = p.parse_args()

    targets = parse_input_file(args.input)
    if not targets:
        print("[!] No valid host:port entries parsed from the input file.")
        return

    if args.fuzz and not args.wordlist:
        print("[!] --fuzz requires --wordlist to be specified. Provide a path to your ffuf wordlist.")
        return

    outdir = ensure_outdir(args.outdir)
    print(f"[+] Targets: {len(targets)}  Outdir: {outdir}")
    print(f"[+] Tools on PATH: nmap={'yes' if which('nmap') else 'no'} httpx={'yes' if which('httpx') else 'no'} ffuf={'yes' if which('ffuf') else 'no'} sqlmap={'yes' if which('sqlmap') else 'no'}")
    if args.fuzz:
        print(f"[+] ffuf wordlist: {args.wordlist}")

    summary = []
    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = {exe.submit(handle_target, h, p, outdir, args.fuzz, args.wordlist, args.sqlmap): (h, p) for h, p in targets}
        for fut in as_completed(futures):
            h, p = futures[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = {"host": h, "port": p, "open": False, "banner": "", "nmap": "", "httpx": "", "ffuf": "", "sqlmap": "", "error": str(e)}
            status = "OPEN" if res["open"] else "CLOSED"
            print(f"{h}:{p}\t{status}\tbanner={res['banner'][:80]}\tnmap={'yes' if res['nmap'] else 'no'}\thttpx={'yes' if res['httpx'] else 'no'} ffuf={'yes' if res['ffuf'] else 'no'} sqlmap={'yes' if res['sqlmap'] else 'no'} err={res['error']}")
            summary.append(res)

    csvfile = os.path.join(outdir, f"results_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    with open(csvfile, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=["host","port","open","banner","nmap","httpx","ffuf","sqlmap","error"])
        writer.writeheader()
        for row in summary:
            writer.writerow({
                "host": row["host"],
                "port": row["port"],
                "open": row["open"],
                "banner": row["banner"],
                "nmap": os.path.basename(row["nmap"]) if row["nmap"] else "",
                "httpx": os.path.basename(row["httpx"]) if row["httpx"] else "",
                "ffuf": os.path.basename(row["ffuf"]) if row["ffuf"] else "",
                "sqlmap": row["sqlmap"],
                "error": row["error"]
            })

    print(f"[✔] Done. Summary CSV: {csvfile}")
    print(f"[✔] Full output directory: {outdir}")

if __name__ == "__main__":
    main()

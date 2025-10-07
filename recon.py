#!/usr/bin/env python3
import os
import subprocess
import datetime
import sys

# === CONFIG ===
DOMAIN = "rwbaird.com"   # <-- change this to your target domain
WORDLIST = "/home/sony/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"
RESOLVERS = "/home/sony/resolvers.txt"

# Ensure output folder with timestamp
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
OUTDIR = f"recon_{DOMAIN}_{timestamp}"
os.makedirs(OUTDIR, exist_ok=True)

def run_cmd(command, outfile=None, shell=False):
    """Run a shell/list command, save output if file given. Raises on non-zero exit."""
    print(f"\n[+] Running: {command if shell else ' '.join(command)}")
    if outfile:
        with open(outfile, "w") as f:
            res = subprocess.run(command, stdout=f, stderr=subprocess.STDOUT, shell=shell, text=True)
    else:
        res = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=shell, text=True)
        print(res.stdout)
    if res.returncode != 0:
        print(f"[!] Command exited with code {res.returncode}", file=sys.stderr)
    return res.returncode

# === PIPELINE ===

# 1. subfinder (passive)
run_cmd(["subfinder", "-d", DOMAIN, "-o", f"{OUTDIR}/subfinder.txt"])

# 2. shuffledns (bruteforce)
run_cmd([
    "shuffledns",
    "-d", DOMAIN,
    "-w", WORDLIST,
    "-r", RESOLVERS,
    "-t", "100",
    "-mode", "bruteforce",
    "-o", f"{OUTDIR}/shuffledns.txt",
    "-v"
])

# 3. alterx (permutations) - produce subdomains-dnsx.txt
# using shell pipeline to keep same behavior as your original
run_cmd(f"cat {OUTDIR}/shuffledns.txt | alterx > {OUTDIR}/subdomains-dnsx.txt", shell=True, outfile=None)

# 4. dnsx (resolving)
run_cmd(f"cat {OUTDIR}/subdomains-dnsx.txt | dnsx > {OUTDIR}/dnsx_results.txt", shell=True)

# 5. naabu (ports)  <-- FIXED: use -top-ports without -p
# feed hosts from dnsx_results.txt via stdin, scan top 100 ports, exclude port 22 (use -ep or -exclude-ports)
run_cmd(f"cat {OUTDIR}/dnsx_results.txt | naabu -top-ports 100 -ep 22 > {OUTDIR}/open-ports.txt", shell=True)

# 6. httpx (HTTP probing)
run_cmd(f"cat {OUTDIR}/open-ports.txt | httpx -title -sc -cl -location -h -fr > {OUTDIR}/httpx.txt", shell=True)

# 7. katana (crawl endpoints)
run_cmd(f"cat {OUTDIR}/shuffledns.txt | katana -jsl > {OUTDIR}/katana_endpoints.txt", shell=True)

print(f"\n[✔] Recon completed. Results saved in: {OUTDIR}")

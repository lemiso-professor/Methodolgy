#!/usr/bin/env python3
import os
import subprocess
import datetime

# === CONFIG ===
DOMAIN = "example.com"   # <-- change this to your target domain
WORDLIST = "/path/to/SecLists/Discovery/DNS/subdomains-top1million-20000.txt"
RESOLVERS = "/path/to/resolvers.txt"

# Ensure output folder with timestamp
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
OUTDIR = f"recon_{DOMAIN}_{timestamp}"
os.makedirs(OUTDIR, exist_ok=True)

def run_cmd(command, outfile=None):
    """Run a shell command, save output if file given"""
    print(f"\n[+] Running: {' '.join(command)}")
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as proc:
        if outfile:
            with open(outfile, "w") as f:
                for line in proc.stdout:
                    print(line.strip())
                    f.write(line)
        else:
            for line in proc.stdout:
                print(line.strip())

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

# 3. alterx (permutations)
with open(f"{OUTDIR}/subdomains-dnsx.txt", "w") as f:
    subprocess.run(f"cat {OUTDIR}/shuffledns.txt | alterx", shell=True, stdout=f)

# 4. dnsx (resolving)
with open(f"{OUTDIR}/dnsx_results.txt", "w") as f:
    subprocess.run(f"cat {OUTDIR}/subdomains-dnsx.txt | dnsx", shell=True, stdout=f)

# 5. naabu (ports)
with open(f"{OUTDIR}/open-ports.txt", "w") as f:
    subprocess.run(f"cat {OUTDIR}/dnsx_results.txt | naabu -p -top-ports 100 -ep 22", shell=True, stdout=f)

# 6. httpx (HTTP probing)
with open(f"{OUTDIR}/httpx.txt", "w") as f:
    subprocess.run(f"cat {OUTDIR}/open-ports.txt | httpx -title -sc -cl -location -h -fr", shell=True, stdout=f)

# 7. katana (crawl endpoints)
with open(f"{OUTDIR}/katana_endpoints.txt", "w") as f:
    subprocess.run(f"cat {OUTDIR}/shuffledns.txt | katana -jsl", shell=True, stdout=f)

print(f"\n[✔] Recon completed. Results saved in: {OUTDIR}")

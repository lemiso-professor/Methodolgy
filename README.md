# Domain Recon & Network Enumeration README

This README documents a recommended reconnaissance pipeline using ProjectDiscovery tools and other common utilities. It's optimized for speed, reproducibility, and clarity. Use responsibly — always have written permission before testing any target.

---

## Prerequisites

* Linux (Kali, Ubuntu, or similar)
* Go installed (for `go install`) and `$GOPATH/bin` or `~/go/bin` in your PATH
* `massdns` installed and compiled
* Wordlists (e.g. SecLists). Example: `SecLists/Discovery/DNS/subdomains-top1million-20000.txt`
* Resolver list (e.g. `resolvers.txt`) — use reliable public resolvers or your own
* Tools used in this pipeline (install via `go install` or package manager):

  * `subfinder` (projectdiscovery)
  * `shuffledns` (projectdiscovery/pdtm installation provides `pdtm` and `shuffledns` binary)
  * `dnsx` (projectdiscovery)
  * `naabu` (projectdiscovery)
  * `httpx` (projectdiscovery)
  * `katana` (crawler)
  * `alterx` (permutation/alteration helper)

---

## Quick install (example)

```bash
# install pdtm (includes some ProjectDiscovery tools)
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest

# ensure your go bin is available
export PATH="$PATH:$(go env GOPATH)/bin"
# or for local installs
export PATH="$PATH:~/.pdtm/go/bin"
```

Install other ProjectDiscovery tools (if you prefer individually):

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# katana install instructions: check its repo for latest instructions
```

Install `massdns` per its repo instructions and get a resolvers list (or use a curated one like `resolvers.txt`).

---

## Pipeline (recommended)

1. **Passive discovery (subfinder)**

```bash
subfinder -d example.com -o subfinder.txt
```

2. **Bruteforce with shuffledns**

Use an absolute path to the `shuffledns` binary and to your resolvers/wordlist to avoid PATH/resolver ambiguity.

```bash
~/.pdtm/go/bin/shuffledns \
  -d example.com \
  -w /path/to/SecLists/Discovery/DNS/subdomains-top1million-20000.txt \
  -r /path/to/resolvers.txt \
  -t 100 \
  -mode bruteforce \
  -o shuffledns.txt \
  -v
```

3. **Permutations / Alterations**

```bash
cat shuffledns.txt | alterx > permutations.txt
# or append to a growing pool
cat shuffledns.txt | alterx | tee -a subdomains-dnsx.txt
```

4. **Resolve / Filter with dnsx**

```bash
cat permutations.txt | dnsx -a -resp -r /path/to/resolvers.txt -t 100 -o dnsx_results.txt
```

5. **Port scanning with naabu**

```bash
# Basic usage
cat dnsx_results.txt | naabu -l -o naabu_all.txt

# Top 100 ports and exclude port 22 example
cat dnsx_results.txt | naabu -l -p -top-ports 100 -ep 22 -o open-ports.txt
```

6. **HTTP probing with httpx**

```bash
cat open-ports.txt | httpx -title -status-code -content-length -location -h -fr -o httpx.txt
```

7. **Crawling with Katana (for endpoints & JS)**

```bash
katana -u https://example.com
katana -u https://example.com -jc           # crawl and output JS/JS-based endpoints
katana -u https://example.com -jsl -d 5     # limit depth

# When authenticated (example using a cookie header)
katana -u https://example.com/ -H 'Cookie: SUPPORTSESSID=<COOKIE>' -xhr -jsl -aff | httpx -ct -cl -sc
```

---

## Example combined one-liners

Resolve + top 100 port scan:

```bash
cat shuffledns.txt | alterx | dnsx | naabu -p -top-ports 100 -o open-ports.txt
```

Full pipeline to HTTP probe:

```bash
cat shuffledns.txt | alterx | dnsx | naabu -p -top-ports 100 -o open-ports.txt && \
cat open-ports.txt | httpx -title -sc -cl -location -h -fr -o httpx.txt
```

Katana for enumerating endpoints from discovered subdomains:

```bash
cat shuffledns.txt | katana -jsl > katana_endpoints.txt
```

---

## Output files (common names)

* `subfinder.txt` - passive results
* `shuffledns.txt` - bruteforce results
* `subdomains-dnsx.txt` - permutations fed into dnsx
* `dnsx_results.txt` - resolved hosts with answers
* `open-ports.txt` / `naabu_all.txt` - port scan results
* `httpx.txt` - HTTP probe results
* `katana_endpoints.txt` - crawled endpoints / JS findings

---

## Performance tips

* Increase `-t` / `-threads` carefully depending on your network and resolver limits.
* Use curated resolver lists (fast, reliable) and avoid overloading public resolvers.
* Cache intermediate outputs so you can resume at a step instead of re-running earlier stages.
* Consider running heavy scans from a VPS with higher bandwidth and lower latency when authorized.

---

## Troubleshooting

* `shuffledns` shows no findings while `subfinder` finds subdomains:

  * Check that the wordlist is valid and not empty.
  * Ensure `resolvers.txt` contains working resolver IPs.
  * Consider lowering thread count (`-t`) to avoid packet loss or rate-limiting.

* `SyntaxError` when running a script: ensure the file has correct shebang (`#!/usr/bin/env bash`) and is executed as a shell script (`bash script.sh` or `chmod +x script.sh`). Don’t run a bash script with `python`.

* Port scanning returns few open ports: ensure `naabu` is receiving hostnames/IPs correctly (use `-list` or `-l`) and consider scanning top ports first.

---

## Ethics & Legal

Always have explicit permission to test a target. Unauthorized scanning and exploitation is illegal in many jurisdictions. Maintain clear rules of engagement, scope, and reporting mechanisms with the target owner.

---

## Contribution / Notes

If you'd like this README tailored to a specific repo structure or to produce a script that runs the entire pipeline and saves outputs to a timestamped folder, tell me what automation you'd like and I can add a ready-to-run script.

Happy recon — use responsibly.

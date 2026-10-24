# 🐍 Python Security Tools

Custom Python scripts I've written for pentesting, reconnaissance, and automation. Built and tested on Mobile devices (Termux + Kali NetHunter).

## Tools

| Script | Purpose |
|--------|---------|
| `odoo_bruteforcer.py` | Threaded XML-RPC brute forcer for Odoo instances (authorized labs only) |
| `subdomain_enum.py` | Multi-source subdomain enumeration (HackerTarget, CertSpotter, AlienVault) |
| `crt_fetcher.py` | Robust crt.sh subdomain fetcher with retries (because crt.sh is unreliable) |
| `link_scraper.py` | Extracts unique, absolute URLs from a target webpage for OSINT and recon |
| ### Chain of Custody & Evidence Hashing

The `vuln_logger.py` tool is built for professional engagements. It does not just log text; it enforces ★chain of custody★. 

When you attach an evidence file (like an `nmap` output or a `headers.json` capture), the tool computes its SHA-256 hash and stores it in the SQLite database. 

To verify that your evidence has not been altered or corrupted since capture, run:
`python3 vuln_logger.py verify`

If a single byte has changed, it will flag the file as `[TAMPERED]` and exit with code `1`. |

## Installation

```bash
pip install requests

# Run any script with --help
python3 odoo_bruteforcer.py --help
python3 subdomain_enum.py --help
python3 crt_fetcher.py --help
```

## ⚠️ Disclaimer

These tools are for authorized testing only. Never run them against systems you don't own or have explicit written permission to test. Unauthorized use is illegal.

## Philosophy

Tools internal. Data on SD. Slow is smooth. Smooth is fast.



# 🐍 Python Security Tools

Custom Python scripts I've written for pentesting, reconnaissance, and automation. Built and tested on Mobile devices (Termux + Kali NetHunter).

## Tools

| Script | Purpose |
|--------|---------|
| `odoo_bruteforcer.py` | Threaded XML-RPC brute forcer for Odoo instances (authorized labs only) |
| `subdomain_enum.py` | Multi-source subdomain enumeration (HackerTarget, CertSpotter, AlienVault) |
| `crt_fetcher.py` | Robust crt.sh subdomain fetcher with retries (because crt.sh is unreliable) |
| `link_scraper.py` | Extracts unique, absolute URLs from a target webpage for OSINT and recon |
| `vuln_logger.py` | A lightweight SQLite-based CLI tool to log, track, and export penetration testing findings to Markdown |

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



# 🐍 Python Security Tools

Custom Python scripts I've written for pentesting, reconnaissance, and automation. Built and tested on Mobile devices (Termux + Kali NetHunter).

## Tools

| Script | Purpose |
|--------|---------|
| `vuln_logger.py` | SQLite findings DB with SHA-256 evidence hashing, scope enforcement, and Markdown reporting |
| `headers.py` | HTTP & TLS fingerprinting, missing security headers, and cookie flag auditing |
| `subdomain_enum.py` | Multi-source passive subdomain enumeration (HackerTarget, CertSpotter, AlienVault) |
| `crt_fetcher.py` | Robust crt.sh subdomain fetcher with retry logic and memory limits |
| `link_scraper.py` | Extracts unique, absolute URLs (links, scripts, forms) for attack surface mapping |
| `auth_resilience_tester.py` | Threaded XML-RPC auth tester for authorized Odoo instances |

## Tool Details

### `headers.py` — HTTP & TLS Fingerprinting
A lightweight, single-request auditor for web applications. It evaluates the server's fingerprint, TLS configuration, missing security headers, and cookie flags without firing a scanner or crashing a mobile device.

**Usage:**
```bash
python3 headers.py https://target.lab/ --insecure
python3 headers.py https://target.lab/ --json > headers.json
```
vuln_logger.py — Chain of Custody & Evidence Hashing

Built for professional engagements. It does not just log text; it enforces chain of custody. When you attach an evidence file (like an nmap output or a headers.json capture), the tool computes its SHA-256 hash and stores it in the SQLite database.

To verify that your evidence has not been altered or corrupted since capture:

```bash
python3 vuln_logger.py verify
```

If a single byte has changed, it will flag the file as [TAMPERED] and exit with code 1.

Installation

```bash
pip install requests beautifulsoup4
```

Philosophy

Tools internal. Data on SD. Slow is smooth. Smooth is fast.

⚠️ Disclaimer

These tools are for authorized testing only. Never run them against systems you don't own or have explicit written permission to test. Unauthorized use is illegal.


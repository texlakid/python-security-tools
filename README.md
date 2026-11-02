# 🐍 Python Security Tools

Custom Python scripts written for penetration testing, reconnaissance, and automation. 
Built and optimized for **Mobile first environments** (Termux + Kali NetHunter) 

## 📖 Philosophy
> *"Tools internal. Data on SD. Slow is smooth. Smooth is fast."*

## 🛠️ The Arsenal

| Script | Purpose |
| :--- | :--- |
| [`vuln_logger.py`](./vuln_logger.py) | SQLite findings DB with SHA-256 evidence hashing, scope enforcement, and Markdown reporting. |
| [`headers.py`](./headers.py) | HTTP & TLS fingerprinting. Identifies missing security headers without crashing mobile devices. |
| [`subdomain_enum.py`](./subdomain_enum.py) | Multi-source passive subdomain enumeration (HackerTarget, CertSpotter, AlienVault). |
| [`crt_fetcher.py`](./crt_fetcher.py) | Robust crt.sh subdomain fetcher with retry logic and memory limits. |
| [`link_scraper.py`](./link_scraper.py) | Extracts unique, absolute links (scripts/forms) for attack surface mapping. |
| [`auth_resilience_tester.py`](./auth_resilience_tester.py) | Threaded XML-RPC tester for authorized Odoo instances. |

---

## 🔍 Tool Details

### `vuln_logger.py` — Chain of Custody & Evidence Hashing (v3.0)
Built for professional engagements. It does not just log text; it enforces **chain of custody**. When you attach an evidence file (like an `nmap` output or a `headers.json` capture), the tool computes its SHA-256 hash and stores it in a highly-concurrent SQLite database (WAL mode enabled). 

**Key Features:**
*   **Scope Enforcement:** Refuses to log findings outside your defined engagement scope (e.g., `10.10.10.*`).
*   **Forensic Verification:** Run `verify` to recompute hashes. If a single byte has changed, it will flag the file as `[TAMPERED]` and exit with code 1.
*   **JSON Export:** Use `list --json` to feed findings into other tools or dashboards.
*   **Automated Markdown Reports:** Generates professional reports filtered by specific engagement IDs.

**Usage:**
```bash
# Initialize DB
python3 vuln_logger.py init

# Create an engagement
python3 vuln_logger.py engagement add --name "Client-X" --scope "192.168.1.*"

# Log a finding
python3 vuln_logger.py add --engagement 1 --host 192.168.1.5 --phase Exploit --title "SMBv1 Enabled" --severity High --evidence-file ./nmap.txt

# Verify integrity
python3 vuln_logger.py verify

# Generate Report
python3 vuln_logger.py report -o client_report.md --engagement 1
```
headers.py — HTTP & TLS Fingerprinting

A lightweight, single-request auditor for web applications. It evaluates the server's fingerprint, TLS configuration, missing security headers, and cookie flags without firing a heavy scanner or exhausting mobile RAM.

Usage:

```bash
python3 headers.py https://target.com
python3 headers.py https://target.com --json > headers_output.json
```

---

🚀 Quick Start (Termux / Linux)

1. Clone the repository:
   ```bash
   git clone https://github.com/texlakid/python-security-tools.git
   cd python-security-tools
   ```
2. Install dependencies:
   ```bash
   pip install requests beautifulsoup4
   ```
3. Make scripts executable:
   ```bash
   chmod +x *.py
   ```

---

⚠️ Disclaimer

These tools are for authorized testing only. Never run them against systems you don't own or have explicit written permission to test. Unauthorized use is illegal. The author assumes no liability for misuse.

```




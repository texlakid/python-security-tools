#!/usr/bin/env python3
"""
Robust crt.sh Subdomain Fetcher with Retries
crt.sh is often slow or returns 502. This script retries and handles errors.

Usage:
    python3 crt_fetcher.py target.com --output crt_subs.txt
"""

import argparse
import json
import requests
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {"User-Agent": "Mozilla/5.0"}

def fetch_crt(domain, retries=3, delay=5):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, headers=HEADERS, timeout=60, verify=False)
            if r.status_code == 200 and r.text.strip().startswith("["):
                return json.loads(r.text)
            else:
                print(f"  [!] Attempt {attempt}: HTTP {r.status_code}, retrying in {delay}s...")
        except Exception as e:
            print(f"  [!] Attempt {attempt}: {type(e).__name__}, retrying in {delay}s...")
        time.sleep(delay)
    return None

def main():
    parser = argparse.ArgumentParser(description="Robust crt.sh subdomain fetcher")
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument("--output", default="crt_subs.txt", help="Output file (default: crt_subs.txt)")
    args = parser.parse_args()

    print(f"[*] Fetching crt.sh for {args.domain}")
    data = fetch_crt(args.domain)

    if not data:
        print("[-] crt.sh failed after all retries. Try subdomain_enum.py instead.")
        return

    subs = set()
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            if name.strip():
                subs.add(name.strip().lower())

    clean = sorted(s for s in subs if args.domain in s)

    with open(args.output, "w") as f:
        f.write("\n".join(clean))

    print(f"\n[+] Found {len(clean)} subdomains")
    print(f"[+] Saved to: {args.output}")

if __name__ == "__main__":
    main()

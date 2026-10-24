#!/usr/bin/env python3
"""
crt_fetcher.py -- Robust crt.sh Subdomain Fetcher.
Handles crt.sh instability with retries and size limits.

Usage:
    python3 crt_fetcher.py target.com --authorized
"""

import argparse
import json
import sys
import time
import requests

HEADERS = {"User-Agent": "Mozilla/5.0 (Android; Termux)"}
MAX_JSON_SIZE = 15 * 1024 * 1024  

def fetch_crt(domain, retries=3, delay=5):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    for attempt in range(1, retries + 1):
        try:
            with requests.get(url, headers=HEADERS, timeout=60, stream=True) as r:
                if r.status_code == 200:
                    
                    content_length = int(r.headers.get('Content-Length', 0))
                    if content_length > MAX_JSON_SIZE:
                        print(f"  [!] Response too large ({content_length} bytes). Aborting.")
                        return None
                    
                    
                    content = r.content[:MAX_JSON_SIZE]
                    if content.strip().startswith(b"["):
                        try:
                            return json.loads(content)
                        except json.JSONDecodeError:
                            print(f"  [!] Attempt {attempt}: JSON truncated or invalid.")
                    else:
                        print(f"  [!] Attempt {attempt}: Not valid JSON.")
                else:
                    print(f"  [!] Attempt {attempt}: HTTP {r.status_code}")
        except requests.RequestException as e:
            print(f"  [!] Attempt {attempt}: {type(e).__name__}")
            
        if attempt < retries:
            print(f"      Retrying in {delay}s...")
            time.sleep(delay)
    return None

def main():
    parser = argparse.ArgumentParser(description="Robust crt.sh subdomain fetcher")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("--output", default="crt_subs.txt", help="Output file")
    parser.add_argument("--authorized", action="store_true", required=True,
                        help="Confirm authorization to enumerate this domain")
    args = parser.parse_args()

    domain = args.domain.lower().replace("http://", "").replace("https://", "").split("/")[0]
    
    print(f"[*] Fetching crt.sh for {domain} (this may take 30-60 seconds)...")
    data = fetch_crt(domain)

    if not data:
        print("[-] crt.sh failed after all retries.")
        sys.exit(1)

    subs = set()
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().rstrip(".")
            if name and (name == domain or name.endswith("." + domain)):
                subs.add(name)

    if not subs:
        print("[-] No subdomains found in crt.sh response.")
        sys.exit(0)

    sorted_subs = sorted(subs)
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted_subs) + "\n")
        print(f"\n[+] Found {len(sorted_subs)} valid subdomains")
        print(f"[+] Saved to: {args.output}")
    except OSError as e:
        print(f"[-] Could not write to file: {e}")

if __name__ == "__main__":
    main()

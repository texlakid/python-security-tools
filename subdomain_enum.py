#!/usr/bin/env python3
"""
subdomain_enum.py -- Multi-Source Passive Subdomain Enumerator.
Combines HackerTarget, CertSpotter, and AlienVault OTX.

Usage:
    python3 subdomain_enum.py target.com --authorized --output subs.txt
"""

import argparse
import json
import sys
import requests

HEADERS = {"User-Agent": "Mozilla/5.0 (Android; Termux)"}

def hackertarget(domain):
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                         headers=HEADERS, timeout=15)
        r.raise_for_status()
     
        if "error" in r.text.lower() or "exceeded" in r.text.lower():
            return []
        return [line.split(",")[0] for line in r.text.splitlines() if "," in line]
    except requests.RequestException:
        return []

def certspotter(domain):
    try:
        r = requests.get(
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
            headers=HEADERS, timeout=15)
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and "detail" in data:
            return [] # API error/rate limit
        subs = []
        for entry in data:
            if isinstance(entry, dict):
                subs.extend(entry.get("dns_names", []))
        return subs
    except (requests.RequestException, json.JSONDecodeError):
        return []

def alienvault(domain):
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            headers=HEADERS, timeout=15)
        r.raise_for_status()
        data = r.json()
        return [e.get("hostname") for e in data.get("passive_dns", []) if e.get("hostname")]
    except (requests.RequestException, json.JSONDecodeError):
        return []

def main():
    parser = argparse.ArgumentParser(description="Passive subdomain enumerator")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("--output", default="subs.txt", help="Output file")
    parser.add_argument("--authorized", action="store_true", required=True,
                        help="Confirm authorization to enumerate this domain")
    args = parser.parse_args()

    
    domain = args.domain.lower().replace("http://", "").replace("https://", "").split("/")[0]
    
    print(f"[*] Enumerating subdomains for: {domain}")
    all_subs = set()
    
    ht = hackertarget(domain)
    all_subs.update(ht)
    print(f"  [+] HackerTarget:  {len(ht)} found")
    
    cs = certspotter(domain)
    all_subs.update(cs)
    print(f"  [+] CertSpotter:   {len(cs)} found")
    
    av = alienvault(domain)
    all_subs.update(av)
    print(f"  [+] AlienVault:    {len(av)} found")

   
    clean = set()
    for sub in all_subs:
        if not sub: continue
        sub = sub.strip().lower().rstrip(".")
        # Must be exactly the domain, or end with .domain (prevents notexample.com)
        if sub == domain or sub.endswith("." + domain):
            clean.add(sub)

    if not clean:
        print("\n[-] No subdomains found (or all APIs failed/rate-limited).")
        sys.exit(1)

    sorted_clean = sorted(clean)
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted_clean) + "\n")
        print(f"\n[+] Total unique subdomains: {len(sorted_clean)}")
        print(f"[+] Saved to: {args.output}")
    except OSError as e:
        print(f"\n[-] Failed to write to {args.output}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

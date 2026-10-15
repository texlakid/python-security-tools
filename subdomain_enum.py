#!/usr/bin/env python3
"""
Multi-Source Subdomain Enumerator
Combines HackerTarget, CertSpotter, and AlienVault OTX.

Usage:
    python3 subdomain_enum.py target.com --output subs.txt
"""

import argparse
import json
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {"User-Agent": "Mozilla/5.0"}

def hackertarget(domain):
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                         headers=HEADERS, timeout=20)
        return [line.split(",")[0] for line in r.text.splitlines() if "," in line]
    except Exception:
        return []

def certspotter(domain):
    try:
        r = requests.get(
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
            headers=HEADERS, timeout=20)
        data = r.json()
        subs = []
        for entry in data:
            subs.extend(entry.get("dns_names", []))
        return subs
    except Exception:
        return []

def alienvault(domain):
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            headers=HEADERS, timeout=20)
        data = r.json()
        return [e["hostname"] for e in data.get("passive_dns", [])]
    except Exception:
        return []

def main():
    parser = argparse.ArgumentParser(description="Multi-source subdomain enumerator")
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument("--output", default="subs.txt", help="Output file (default: subs.txt)")
    args = parser.parse_args()

    print(f"[*] Enumerating subdomains for {args.domain}")
    all_subs = set()
    all_subs.update(hackertarget(args.domain))
    print(f"  [+] HackerTarget: {len(all_subs)} unique so far")
    all_subs.update(certspotter(args.domain))
    print(f"  [+] CertSpotter: {len(all_subs)} unique so far")
    all_subs.update(alienvault(args.domain))
    print(f"  [+] AlienVault: {len(all_subs)} unique so far")

    # Clean and filter
    clean = sorted(set(s.strip().lower() for s in all_subs if s and args.domain in s))

    with open(args.output, "w") as f:
        f.write("\n".join(clean))

    print(f"\n[+] Total unique subdomains: {len(clean)}")
    print(f"[+] Saved to: {args.output}")

if __name__ == "__main__":
    main()

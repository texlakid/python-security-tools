#!/usr/bin/env python3
"""
Vulnerability Logger
A lightweight SQLite database tool to log findings during an engagement.

Usage:
    python3 vuln_logger.py init
    python3 vuln_logger.py add --host 10.10.10.10 --phase Recon --title "Exposed Git" --severity High
    python3 vuln_logger.py list
    python3 vuln_logger.py list --host 10.10.10.10
"""

import sqlite3
import datetime
import argparse
import sys
import os

DB_FILE = "findings.db"

def init_db():
    con = sqlite3.connect(DB_FILE)
    con.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            host TEXT NOT NULL,
            phase TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            evidence TEXT,
            remediation TEXT
        )
    """)
    con.commit()
    con.close()
    print(f"[+] Database initialized: {DB_FILE}")

def add_finding(con, host, phase, title, severity, evidence="", remediation=""):
    ts = datetime.datetime.now().isoformat()
    query = """
        INSERT INTO findings (ts, host, phase, title, severity, evidence, remediation)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """
    con.execute(query, (ts, host, phase, title, severity, evidence, remediation))
    con.commit()
    print(f"[+] Logged: [{severity.upper()}] {title} on {host}")

def list_findings(con, host=None):
    if host:
        cursor = con.execute("SELECT ts, host, phase, title, severity FROM findings WHERE host = ? ORDER BY ts DESC", (host,))
    else:
        cursor = con.execute("SELECT ts, host, phase, title, severity FROM findings ORDER BY ts DESC")
    
    rows = cursor.fetchall()
    if not rows:
        print("[-] No findings logged yet.")
        return

    print(f"\n{'='*80}")
    print(f"{'TIMESTAMP':<20} | {'HOST':<15} | {'SEV':<8} | {'TITLE'}")
    print(f"{'='*80}")
    for row in rows:
        ts, host, phase, title, sev = row
   
        title_short = (title[:35] + '..') if len(title) > 37 else title
        print(f"{ts[:19]:<20} | {host:<15} | {sev.upper():<8} | {title_short}")
    print(f"{'='*80}\n")

def main():
    parser = argparse.ArgumentParser(description="Pentest Finding Logger")
    subparsers = parser.add_subparsers(dest="command", required=True)

 
    subparsers.add_parser("init", help="Initialize the database")

 
    add_parser = subparsers.add_parser("add", help="Add a new finding")
    add_parser.add_argument("--host", required=True, help="Target IP or domain")
    add_parser.add_argument("--phase", required=True, help="Phase (e.g., Recon, Exploitation)")
    add_parser.add_argument("--title", required=True, help="Finding title")
    add_parser.add_argument("--severity", required=True, choices=["Critical", "High", "Medium", "Low", "Info"], help="Severity level")
    add_parser.add_argument("--evidence", default="", help="Evidence/PoC")
    add_parser.add_argument("--remediation", default="", help="Remediation advice")

 
    list_parser = subparsers.add_parser("list", help="List findings")
    list_parser.add_argument("--host", help="Filter by specific host")

    args = parser.parse_args()

    if args.command == "init":
        init_db()
    elif args.command == "add":
        if not os.path.exists(DB_FILE):
            print("[-] Database not found. Run 'python3 vuln_logger.py init' first.")
            sys.exit(1)
        con = sqlite3.connect(DB_FILE)
        add_finding(con, args.host, args.phase, args.title, args.severity, args.evidence, args.remediation)
        con.close()
    elif args.command == "list":
        if not os.path.exists(DB_FILE):
            print("[-] Database not found. Run 'python3 vuln_logger.py init' first.")
            sys.exit(1)
        con = sqlite3.connect(DB_FILE)
        list_findings(con, args.host)
        con.close()

if __name__ == "__main__":
    main()

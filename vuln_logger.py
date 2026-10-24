#!/usr/bin/env python3
"""
Vulnerability Logger -- SQLite findings DB for authorized engagements.

Usage:
    python3 vuln_logger.py init
    python3 vuln_logger.py add --host 10.10.10.10 --phase Recon \
        --title "Exposed Git" --severity High --evidence "GET /.git/ -> 200" \
        --remediation "Remove /.git from webroot; deny in nginx."
    python3 vuln_logger.py list
    python3 vuln_logger.py list --host 10.10.10.10 --severity High
    python3 vuln_logger.py show --id 1
    python3 vuln_logger.py report -o report.md
"""

import argparse
import datetime
import os
import sqlite3
import stat
import sys

DB_FILE = "findings.db"
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    host        TEXT NOT NULL,
    phase       TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    evidence    TEXT,
    remediation TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host);
CREATE INDEX IF NOT EXISTS idx_findings_sev  ON findings(severity);
"""


def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def lock_down(path: str) -> None:
    """Best-effort 0600. Fails silently on /sdcard (no POSIX perms)."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:
        print(f"[!] Could not chmod {path} to 0600: {exc}", file=sys.stderr)


def init_db() -> None:
    existed = os.path.exists(DB_FILE)
    con = sqlite3.connect(DB_FILE)
    try:
        con.executescript(SCHEMA)
        con.commit()
    finally:
        con.close()
    lock_down(DB_FILE)
    print(f"[+] Database {'updated' if existed else 'created'}: {DB_FILE}")


def open_db() -> sqlite3.Connection:
    """Open the findings DB, verifying the schema exists."""
    if not os.path.exists(DB_FILE):
        sys.exit(f"[!] {DB_FILE} not found. Run: {sys.argv[0]} init")
    try:
        con = sqlite3.connect(DB_FILE)
        row = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='findings'"
        ).fetchone()
    except sqlite3.DatabaseError as exc:
        sys.exit(f"[!] Cannot open {DB_FILE}: {exc}")
    if row is None:
        con.close()
        sys.exit(f"[!] {DB_FILE} exists but is not initialized. "
                 f"Run: {sys.argv[0]} init")
    return con


def add_finding(con, host, phase, title, severity, evidence="", remediation=""):
    sev = severity.strip().title()
    if sev not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    con.execute(
        "INSERT INTO findings (ts, host, phase, title, severity, evidence, remediation) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (now_utc(), host, phase, title, sev, evidence, remediation),
    )
    con.commit()
    print(f"[+] Logged: [{sev.upper()}] {title} on {host}")


def list_findings(con, host=None, severity=None):
    q = "SELECT id, ts, host, phase, title, severity FROM findings WHERE 1=1"
    params = []
    if host:
        q += " AND host = ?"
        params.append(host)
    if severity:
        q += " AND severity = ?"
        params.append(severity.strip().title())
    q += " ORDER BY ts DESC"
    rows = con.execute(q, params).fetchall()
    if not rows:
        print("[-] No findings match.")
        return
    print()
    print(f"{'ID':>4} | {'TIMESTAMP (UTC)':<20} | {'HOST':<15} | {'SEV':<8} | TITLE")
    print("-" * 90)
    for rid, ts, h, phase, title, sev in rows:
        short = title if len(title) <= 40 else title[:37] + "..."
        print(f"{rid:>4} | {ts[:19]:<20} | {h:<15} | {sev.upper():<8} | {short}")
    print()


def show_finding(con, finding_id: int):
    row = con.execute(
        "SELECT id, ts, host, phase, title, severity, evidence, remediation "
        "FROM findings WHERE id = ?", (finding_id,),
    ).fetchone()
    if row is None:
        print(f"[-] No finding with id={finding_id}")
        return
    rid, ts, h, phase, title, sev, ev, rem = row
    print(f"ID          : {rid}")
    print(f"Timestamp   : {ts}")
    print(f"Host        : {h}")
    print(f"Phase       : {phase}")
    print(f"Severity    : {sev}")
    print(f"Title       : {title}")
    print(f"Evidence    : {ev or '(none)'}")
    print(f"Remediation : {rem or '(none)'}")


def to_markdown(con, out_path: str) -> None:
    rows = con.execute(
        "SELECT id, ts, host, phase, title, severity, evidence, remediation "
        "FROM findings ORDER BY "
        "CASE severity "
        "WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 "
        "WHEN 'Low' THEN 3 ELSE 4 END, ts DESC"
    ).fetchall()
    if not rows:
        print("[-] Nothing to export.")
        return

    counts = {s: 0 for s in SEVERITIES}
    for r in rows:
        counts[r[5]] = counts.get(r[5], 0) + 1

    lines = ["# Engagement Findings", "", f"_Generated: {now_utc()}_", ""]
    lines += ["## Summary", "", "| Severity | Count |", "|----------|-------|"]
    for sev in SEVERITIES:
        if counts[sev]:
            lines.append(f"| {sev} | {counts[sev]} |")
    lines.append("")

    for rid, ts, h, phase, title, sev, ev, rem in rows:
        lines += [
            f"## [{sev}] {title}", "",
            f"- **ID**: {rid}",
            f"- **Host**: `{h}`",
            f"- **Phase**: {phase}",
            f"- **Logged (UTC)**: {ts}",
            "",
        ]
        if ev:
            lines += ["**Evidence**", "", "```", ev, "```", ""]
        if rem:
            lines += ["**Remediation**", "", rem, ""]

    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
    except OSError as exc:
        sys.exit(f"[!] Could not write {out_path}: {exc}")
    print(f"[+] Report written: {out_path} ({len(rows)} findings)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Pentest finding logger")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Initialize or migrate the database")

    p = sub.add_parser("add", help="Log a finding")
    p.add_argument("--host", required=True)
    p.add_argument("--phase", required=True)
    p.add_argument("--title", required=True)
    p.add_argument("--severity", required=True, choices=SEVERITIES)
    p.add_argument("--evidence", default="")
    p.add_argument("--remediation", default="")

    p = sub.add_parser("list", help="List findings")
    p.add_argument("--host")
    p.add_argument("--severity", choices=SEVERITIES)

    p = sub.add_parser("show", help="Show one finding in full")
    p.add_argument("--id", type=int, required=True)

    p = sub.add_parser("report", help="Export findings to Markdown")
    p.add_argument("-o", "--output", default="report.md")

    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.command == "init":
        init_db()
        return 0

    con = open_db()
    try:
        if args.command == "add":
            add_finding(con, args.host, args.phase, args.title,
                        args.severity, args.evidence, args.remediation)
        elif args.command == "list":
            list_findings(con, args.host, args.severity)
        elif args.command == "show":
            show_finding(con, args.id)
        elif args.command == "report":
            to_markdown(con, args.output)
    except sqlite3.OperationalError as exc:
        print(f"[!] Database error: {exc}", file=sys.stderr)
        return 1
    finally:
        con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
vuln_logger.py v3.0 -- SQLite findings DB with evidence hashing & scope enforcement.

Features:
  * Engagements table with scope globs; add/import refuse out-of-scope hosts.
  * Evidence-as-file: --evidence-file stores absolute path + SHA-256.
  * Verify: recompute hashes, report OK / TAMPERED / MISSING, exit 1 on drift.
  * Import: consume headers.py --json output, one finding per missing header.
  * JSON Output: export findings in JSON format for tool chaining.
  * WAL Mode: SQLite Write-Ahead Logging enabled for concurrent read/writes.
  
Built for lightweight, mobile-first reconnaissance and  penetration testing.

Author  : Alexander Anthony (Texla Kid)
GitHub  : https://github.com/Texlakid
Version : 3.0
Date    : 2026-10-31

WARNING:Do not use against targets without 
explicit, written authorization.
"""

import argparse
import datetime
import fnmatch
import hashlib
import json
import os
import sqlite3
import stat
import sys
from urllib.parse import urlparse


C_GREEN = '\033[92m'
C_RED = '\033[91m'
C_YELLOW = '\033[93m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

DATA_DIR = "texlakit_data"
DB_FILE = os.path.join(DATA_DIR, "findings.db")
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
HASH_CHUNK = 65536

SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    scope      TEXT NOT NULL,
    created_ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id   INTEGER REFERENCES engagements(id),
    ts              TEXT NOT NULL,
    host            TEXT NOT NULL,
    phase           TEXT NOT NULL,
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL,
    evidence        TEXT,
    evidence_path   TEXT,
    evidence_sha256 TEXT,
    remediation     TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_host   ON findings(host);
CREATE INDEX IF NOT EXISTS idx_findings_sev    ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_eng    ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_dedupe ON findings(host, title, evidence_sha256);
"""

# ---------------------------------------------------------------- utilities

def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

def ensure_data_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        try: os.chmod(DATA_DIR, stat.S_IRWXU)
        except OSError: pass

def lock_down(path: str) -> None:
    try: os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError: pass

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(HASH_CHUNK), b""):
            h.update(block)
    return h.hexdigest()

def open_db() -> sqlite3.Connection:
    if not os.path.exists(DB_FILE):
        sys.exit(f"{C_RED}[!] {DB_FILE} not found. Run: {sys.argv[0]} init{C_RESET}")
    try:
        con = sqlite3.connect(DB_FILE)
        con.execute("PRAGMA journal_mode=WAL;")
        row = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='findings'"
        ).fetchone()
    except sqlite3.DatabaseError as exc:
        sys.exit(f"{C_RED}[!] cannot open {DB_FILE}: {exc}{C_RESET}")
    if row is None:
        con.close()
        sys.exit(f"{C_RED}[!] {DB_FILE} exists but is not initialized. Run: {sys.argv[0]} init{C_RESET}")
    return con

# ---------------------------------------------------------------- schema

def init_db() -> None:
    ensure_data_dir()
    existed = os.path.exists(DB_FILE)
    con = sqlite3.connect(DB_FILE)
    con.execute("PRAGMA journal_mode=WAL;")
    try:
        con.executescript(SCHEMA)
        cols = {r[1] for r in con.execute("PRAGMA table_info(findings)")}
        for col, ddl in (("engagement_id", "INTEGER"),
                         ("evidence_path", "TEXT"),
                         ("evidence_sha256", "TEXT")):
            if col not in cols:
                con.execute(f"ALTER TABLE findings ADD COLUMN {col} {ddl}")
                print(f"{C_YELLOW}[*] migrated: added findings.{col}{C_RESET}")
        con.commit()
    finally:
        con.close()
    lock_down(DB_FILE)
    print(f"{C_GREEN}[+] Database {'updated' if existed else 'created'}: {DB_FILE}{C_RESET}")

# ---------------------------------------------------------------- scope

def scope_globs(con, engagement_id: int):
    row = con.execute("SELECT scope FROM engagements WHERE id=?", (engagement_id,)).fetchone()
    if row is None:
        sys.exit(f"{C_RED}[!] no engagement with id={engagement_id}{C_RESET}")
    return [g.strip().lower() for g in row[0].split(",") if g.strip()]

def enforce_scope(con, engagement_id: int, host: str) -> None:
    host = host.strip().lower()
    globs = scope_globs(con, engagement_id)
    if not any(fnmatch.fnmatch(host, g) for g in globs):
        sys.exit(f"{C_RED}[!] host {host!r} is OUT OF SCOPE for engagement {engagement_id}\n"
                 f"    scope: {globs}\n"
                 f"    refusal is deliberate. Fix scope or fix target.{C_RESET}")

def add_engagement(con, name: str, scope: str) -> None:
    try:
        con.execute(
            "INSERT INTO engagements (name, scope, created_ts) VALUES (?,?,?)",
            (name, scope, now_utc()),
        )
        con.commit()
    except sqlite3.IntegrityError:
        sys.exit(f"{C_RED}[!] engagement {name!r} already exists{C_RESET}")
    print(f"{C_GREEN}[+] Engagement created: {name}  scope={scope}{C_RESET}")

# ---------------------------------------------------------------- findings

def resolve_evidence(inline, path):
    if path:
        abs_path = os.path.abspath(path)
        if not os.path.isfile(abs_path):
            sys.exit(f"{C_RED}[!] evidence file not found: {abs_path}{C_RESET}")
        try:
            digest = sha256_file(abs_path)
        except OSError as exc:
            sys.exit(f"{C_RED}[!] cannot hash {abs_path}: {exc}{C_RESET}")
        return (inline or f"see {abs_path}", abs_path, digest)
    return (inline or "", None, None)

def add_finding(con, host, phase, title, severity, evidence="",
                evidence_file=None, remediation="", engagement_id=None):
    sev = severity.strip().title()
    if sev not in SEVERITIES:
        sys.exit(f"{C_RED}[!] severity must be one of {SEVERITIES}{C_RESET}")
    
    host = host.strip().lower() 
    if engagement_id is not None:
        enforce_scope(con, engagement_id, host)

    text, path, digest = resolve_evidence(evidence, evidence_file)
    con.execute(
        "INSERT INTO findings (engagement_id, ts, host, phase, title, severity,"
        " evidence, evidence_path, evidence_sha256, remediation)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (engagement_id, now_utc(), host, phase, title, sev,
         text, path, digest, remediation),
    )
    con.commit()
    tail = f"  [sha256 {digest[:12]}...]" if digest else ""
    color = C_RED if sev in ("Critical", "High") else C_YELLOW if sev == "Medium" else C_CYAN
    print(f"{C_GREEN}[+] Logged:{C_RESET} {color}[{sev.upper()}]{C_RESET} {title} on {host}{tail}")

def list_findings(con, host=None, severity=None, as_json=False):
    q = ("SELECT id, ts, host, phase, title, severity,"
         " substr(evidence_sha256,1,12) FROM findings WHERE 1=1")
    params = []
    if host:
        q += " AND host = ?"; params.append(host.strip().lower())
    if severity:
        q += " AND severity = ?"; params.append(severity.strip().title())
    q += " ORDER BY ts DESC"
    rows = con.execute(q, params).fetchall()
    
    if not rows:
        print(f"{C_YELLOW}[-] No findings match.{C_RESET}")
        return

    if as_json:
        keys = ["id", "timestamp", "host", "phase", "title", "severity", "sha256"]
        data = [dict(zip(keys, row)) for row in rows]
        print(json.dumps(data, indent=4))
        return

    print(f"\n{C_CYAN}{'ID':>4} | {'TIMESTAMP (UTC)':<20} | {'HOST':<15} | {'SEV':<8} | {'SHA256':<12} | TITLE{C_RESET}")
    print("-" * 110)
    for rid, ts, h, phase, title, sev, sha in rows:
        short = title if len(title) <= 36 else title[:33] + "..."
        color = C_RED if sev in ("Critical", "High") else C_YELLOW if sev == "Medium" else C_CYAN
        print(f"{rid:>4} | {ts[:19]:<20} | {h:<15} | {color}{sev.upper():<8}{C_RESET} | "
              f"{(sha or '-'):<12} | {short}")
    print()

def show_finding(con, finding_id: int):
    row = con.execute(
        "SELECT id, engagement_id, ts, host, phase, title, severity, evidence,"
        "       evidence_path, evidence_sha256, remediation"
        " FROM findings WHERE id = ?", (finding_id,),
    ).fetchone()
    if row is None:
        print(f"{C_RED}[-] no finding with id={finding_id}{C_RESET}")
        return
    (rid, eng, ts, h, phase, title, sev, ev, path, sha, rem) = row
    print(f"{C_CYAN}ID          :{C_RESET} {rid}")
    print(f"{C_CYAN}Engagement  :{C_RESET} {eng if eng is not None else '-'}")
    print(f"{C_CYAN}Timestamp   :{C_RESET} {ts}")
    print(f"{C_CYAN}Host        :{C_RESET} {h}")
    print(f"{C_CYAN}Phase       :{C_RESET} {phase}")
    print(f"{C_CYAN}Severity    :{C_RESET} {sev}")
    print(f"{C_CYAN}Title       :{C_RESET} {title}")
    print(f"{C_CYAN}Evidence    :{C_RESET} {ev or '(none)'}")
    print(f"{C_CYAN}Ev. path    :{C_RESET} {path or '(inline)'}")
    print(f"{C_CYAN}Ev. sha256  :{C_RESET} {sha or '(unhashed)'}")
    print(f"{C_CYAN}Remediation :{C_RESET} {rem or '(none)'}")

# ---------------------------------------------------------------- verify

def verify(con) -> int:
    rows = con.execute(
        "SELECT id, host, title, evidence_path, evidence_sha256"
        " FROM findings WHERE evidence_sha256 IS NOT NULL ORDER BY id"
    ).fetchall()
    if not rows:
        print(f"{C_YELLOW}[*] no hashed evidence to verify{C_RESET}")
        return 0
    problems = 0
    for rid, host, title, path, expected in rows:
        if not path or not os.path.isfile(path):
            print(f"{C_RED}[MISSING ] id={rid:<4} {path or '(no path)'}  <- {title}{C_RESET}")
            problems += 1
            continue
        try:
            actual = sha256_file(path)
        except OSError as exc:
            print(f"{C_RED}[ERROR   ] id={rid:<4} {path}: {exc}{C_RESET}")
            problems += 1
            continue
        if actual == expected:
            print(f"{C_GREEN}[OK      ] id={rid:<4} {path}{C_RESET}")
        else:
            print(f"{C_RED}[TAMPERED] id={rid:<4} {path}{C_RESET}")
            print(f"           expected {expected}")
            print(f"           actual   {actual}")
            problems += 1
    print(f"\n{len(rows)} hashed record(s), {problems} problem(s)")
    return 1 if problems else 0

# ---------------------------------------------------------------- import

def import_headers(con, json_path: str, engagement_id: int, phase: str = "Recon") -> int:
    abs_path = os.path.abspath(json_path)
    if not os.path.isfile(abs_path):
        sys.exit(f"{C_RED}[!] file not found: {abs_path}{C_RESET}")
    try:
        with open(abs_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"{C_RED}[!] cannot parse {abs_path}: {exc}{C_RESET}")

    host = urlparse(data.get("target", "")).hostname
    if not host:
        sys.exit(f"{C_RED}[!] JSON has no parseable 'target' URL{C_RESET}")
    
    host = host.strip().lower()
    enforce_scope(con, engagement_id, host)

    digest = sha256_file(abs_path)
    
    missing = data.get("security_missing") or data.get("missing") or {}
    
    if not missing:
        print(f"{C_YELLOW}[*] report lists no missing security headers -- nothing to import{C_RESET}")
        return 0

    inserted = skipped = 0
    for header, meta in missing.items():
        sev = str((meta or {}).get("severity", "Info")).strip().title()
        if sev not in SEVERITIES:
            sev = "Info"
        title = f"Missing {header}"
        dup = con.execute(
            "SELECT 1 FROM findings WHERE host=? AND title=? AND evidence_sha256=?",
            (host, title, digest),
        ).fetchone()
        if dup:
            skipped += 1
            continue
        con.execute(
            "INSERT INTO findings (engagement_id, ts, host, phase, title, severity,"
            " evidence, evidence_path, evidence_sha256, remediation)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (engagement_id, now_utc(), host, phase, title, sev,
             f"see {abs_path}", abs_path, digest,
             f"Set {header} at the edge/server configuration."),
        )
        inserted += 1
    con.commit()
    print(f"{C_GREEN}[+] imported {inserted} finding(s), skipped {skipped} duplicate(s){C_RESET}")
    return 0

# ---------------------------------------------------------------- report

def to_markdown(con, out_path: str, engagement_id: int = None) -> None:
    q = ("SELECT id, ts, host, phase, title, severity, evidence, evidence_path,"
         "       evidence_sha256, remediation, engagement_id FROM findings")
    params = []
    
    
    if engagement_id:
        q += " WHERE engagement_id = ?"
        params.append(engagement_id)
        
    q += (" ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1"
          "  WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, ts DESC")
          
    rows = con.execute(q, params).fetchall()
    if not rows:
        print(f"{C_YELLOW}[-] nothing to export{C_RESET}")
        return
        
    counts = {s: 0 for s in SEVERITIES}
    for r in rows:
        counts[r[5]] = counts.get(r[5], 0) + 1

    
    if engagement_id:
        eng_row = con.execute("SELECT name FROM engagements WHERE id=?", (engagement_id,)).fetchone()
        eng_name = eng_row[0] if eng_row else f"Engagement_{engagement_id}"
    else:
        eng_name = "Global Findings (All Engagements)"

    out = [f"# Penetration Test Findings: {eng_name}", "", f"_Generated: {now_utc()}_", "",
           "## Executive Summary", "", "| Severity | Count |", "|----------|-------|"]
    for s in SEVERITIES:
        if counts[s]:
            out.append(f"| **{s}** | {counts[s]} |")
    out.append("")

    for rid, ts, h, phase, title, sev, ev, path, sha, rem, eng in rows:
        out += [f"## [{sev}] {title}", "",
                f"- **ID**: {rid}",
                f"- **Host**: `{h}`",
                f"- **Phase**: {phase}",
                f"- **Logged (UTC)**: {ts}",
                f"- **Evidence path**: `{path}`" if path else "- **Evidence path**: (inline)",
                f"- **Evidence SHA-256**: `{sha}`" if sha else "- **Evidence SHA-256**: (unhashed)",
                ""]
        if ev:
          
            out += ["**Evidence**", "", "~~~text", ev, "~~~", ""]
        if rem:
            out += ["**Remediation**", "", rem, ""]

    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out))
    except OSError as exc:
        sys.exit(f"{C_RED}[!] cannot write {out_path}: {exc}{C_RESET}")
    print(f"{C_GREEN}[+] Report written: {out_path} ({len(rows)} findings){C_RESET}")

# ---------------------------------------------------------------- CLI

def build_parser():
    p = argparse.ArgumentParser(description="Pentest finding logger v3.2 (SHADOW EDITION)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="initialize or migrate the database")

    e = sub.add_parser("engagement", help="manage engagements")
    esub = e.add_subparsers(dest="eng_cmd", required=True)
    ea = esub.add_parser("add")
    ea.add_argument("--name", required=True)
    ea.add_argument("--scope", required=True,
                    help='comma-separated globs, e.g. "10.10.10.*,*.acme.lab"')
    esub.add_parser("list")

    a = sub.add_parser("add", help="log one finding")
    a.add_argument("--engagement", type=int)
    a.add_argument("--host", required=True)
    a.add_argument("--phase", required=True)
    a.add_argument("--title", required=True)
    a.add_argument("--severity", required=True, choices=SEVERITIES)
    a.add_argument("--evidence", default="")
    a.add_argument("--evidence-file", default=None)
    a.add_argument("--remediation", default="")

    l = sub.add_parser("list", help="list findings")
    l.add_argument("--host")
    l.add_argument("--severity", choices=SEVERITIES)
    l.add_argument("--json", action="store_true", help="Output in JSON format")

    s = sub.add_parser("show", help="show one finding")
    s.add_argument("--id", type=int, required=True)

    sub.add_parser("verify", help="recompute evidence hashes")

    i = sub.add_parser("import", help="import headers.py --json output")
    i.add_argument("json_path")
    i.add_argument("--engagement", type=int, required=True)
    i.add_argument("--phase", default="Recon")

    r = sub.add_parser("report", help="export Markdown report")
    r.add_argument("-o", "--output", default="report.md")
    r.add_argument("--engagement", type=int, help="Filter report by engagement ID")

    return p

def main() -> int:
    args = build_parser().parse_args()

    if args.command == "init":
        init_db()
        return 0

    con = open_db()
    try:
        if args.command == "engagement":
            if args.eng_cmd == "add":
                add_engagement(con, args.name, args.scope)
            else:
                for rid, name, scope, ts in con.execute(
                        "SELECT id, name, scope, created_ts FROM engagements ORDER BY id"):
                    print(f"  {C_CYAN}{rid:>3}{C_RESET}  {name:<20} {scope}   ({ts})")
        elif args.command == "add":
            add_finding(con, args.host, args.phase, args.title, args.severity,
                        evidence=args.evidence,
                        evidence_file=args.evidence_file,
                        remediation=args.remediation,
                        engagement_id=args.engagement)
        elif args.command == "list":
            list_findings(con, args.host, args.severity, args.json)
        elif args.command == "show":
            show_finding(con, args.id)
        elif args.command == "verify":
            return verify(con)
        elif args.command == "import":
            return import_headers(con, args.json_path, args.engagement, args.phase)
        elif args.command == "report":
            to_markdown(con, args.output, args.engagement)
    except sqlite3.OperationalError as exc:
        print(f"{C_RED}[!] database error: {exc}{C_RESET}", file=sys.stderr)
        return 1
    finally:
        con.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())

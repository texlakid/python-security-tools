#!/usr/bin/env python3
"""
vuln_logger.py v2 -- SQLite findings DB with evidence hashing & scope enforcement.

New in v2:
  * engagements table with scope globs; add/import refuse out-of-scope hosts
  * evidence-as-file: --evidence-file stores absolute path + SHA-256
  * verify: recompute hashes, report OK / TAMPERED / MISSING, exit 1 on drift
  * import: consume headers.py --json output, one finding per missing header,
            deduplicated on (host, title, evidence_sha256)

Usage:
    python3 vuln_logger.py init
    python3 vuln_logger.py engagement add --name thm-acme --scope "10.10.10.*,*.acme.lab"
    python3 vuln_logger.py add --engagement 1 --host 10.10.10.10 --phase Recon \
        --title "Exposed .git" --severity High --evidence-file ./git.txt
    python3 vuln_logger.py import headers.json --engagement 1
    python3 vuln_logger.py verify
    python3 vuln_logger.py report -o report.md
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

DB_FILE = "findings.db"
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


" ---------------------------------------------------------------- utilities

def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def lock_down(path: str) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
     
        pass


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(HASH_CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def open_db() -> sqlite3.Connection:
    if not os.path.exists(DB_FILE):
        sys.exit(f"[!] {DB_FILE} not found. Run: {sys.argv[0]} init")
    try:
        con = sqlite3.connect(DB_FILE)
        row = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='findings'"
        ).fetchone()
    except sqlite3.DatabaseError as exc:
        sys.exit(f"[!] cannot open {DB_FILE}: {exc}")
    if row is None:
        con.close()
        sys.exit(f"[!] {DB_FILE} exists but is not initialized. Run: {sys.argv[0]} init")
    return con


" ---------------------------------------------------------------- schema

def init_db() -> None:
    existed = os.path.exists(DB_FILE)
    con = sqlite3.connect(DB_FILE)
    try:
        con.executescript(SCHEMA)
     
        cols = {r[1] for r in con.execute("PRAGMA table_info(findings)")}
        for col, ddl in (("engagement_id", "INTEGER"),
                         ("evidence_path", "TEXT"),
                         ("evidence_sha256", "TEXT")):
            if col not in cols:
              
                con.execute(f"ALTER TABLE findings ADD COLUMN {col} {ddl}")
                print(f"[*] migrated: added findings.{col}")
        con.commit()
    finally:
        con.close()
    lock_down(DB_FILE)
    print(f"[+] Database {'updated' if existed else 'created'}: {DB_FILE}")


 "---------------------------------------------------------------- scope

def scope_globs(con, engagement_id: int):
    row = con.execute("SELECT scope FROM engagements WHERE id=?",
                      (engagement_id,)).fetchone()
    if row is None:
        sys.exit(f"[!] no engagement with id={engagement_id}")
    return [g.strip() for g in row[0].split(",") if g.strip()]


def enforce_scope(con, engagement_id: int, host: str) -> None:
    globs = scope_globs(con, engagement_id)
    if not any(fnmatch.fnmatch(host, g) for g in globs):
        sys.exit(f"[!] host {host!r} is OUT OF SCOPE for engagement {engagement_id}\n"
                 f"    scope: {globs}\n"
                 f"    refusal is deliberate. Fix scope or fix target.")


def add_engagement(con, name: str, scope: str) -> None:
    try:
        con.execute(
            "INSERT INTO engagements (name, scope, created_ts) VALUES (?,?,?)",
            (name, scope, now_utc()),
        )
        con.commit()
    except sqlite3.IntegrityError:
        sys.exit(f"[!] engagement {name!r} already exists")
    print(f"[+] Engagement created: {name}  scope={scope}")


"---------------------------------------------------------------- findings

def resolve_evidence(inline, path):
    """Return (text, abs_path, sha256). Hash is taken exactly once, here."""
    if path:
        abs_path = os.path.abspath(path)
        if not os.path.isfile(abs_path):
            sys.exit(f"[!] evidence file not found: {abs_path}")
        try:
            digest = sha256_file(abs_path)
        except OSError as exc:
            sys.exit(f"[!] cannot hash {abs_path}: {exc}")
        return (inline or f"see {abs_path}", abs_path, digest)
    return (inline or "", None, None)


def add_finding(con, host, phase, title, severity, evidence="",
                evidence_file=None, remediation="", engagement_id=None):
    sev = severity.strip().title()
    if sev not in SEVERITIES:
        sys.exit(f"[!] severity must be one of {SEVERITIES}")
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
    print(f"[+] Logged: [{sev.upper()}] {title} on {host}{tail}")


def list_findings(con, host=None, severity=None):
    q = ("SELECT id, ts, host, phase, title, severity,"
         " substr(evidence_sha256,1,12) FROM findings WHERE 1=1")
    params = []
    if host:
        q += " AND host = ?"; params.append(host)
    if severity:
        q += " AND severity = ?"; params.append(severity.strip().title())
    q += " ORDER BY ts DESC"
    rows = con.execute(q, params).fetchall()
    if not rows:
        print("[-] No findings match.")
        return
    print()
    print(f"{'ID':>4} | {'TIMESTAMP (UTC)':<20} | {'HOST':<15} | {'SEV':<8} | {'SHA256':<12} | TITLE")
    print("-" * 110)
    for rid, ts, h, phase, title, sev, sha in rows:
        short = title if len(title) <= 36 else title[:33] + "..."
        print(f"{rid:>4} | {ts[:19]:<20} | {h:<15} | {sev.upper():<8} | "
              f"{(sha or '-'):<12} | {short}")
    print()


def show_finding(con, finding_id: int):
    row = con.execute(
        "SELECT id, engagement_id, ts, host, phase, title, severity, evidence,"
        "       evidence_path, evidence_sha256, remediation"
        " FROM findings WHERE id = ?", (finding_id,),
    ).fetchone()
    if row is None:
        print(f"[-] no finding with id={finding_id}")
        return
    (rid, eng, ts, h, phase, title, sev, ev, path, sha, rem) = row
    print(f"ID          : {rid}")
    print(f"Engagement  : {eng if eng is not None else '-'}")
    print(f"Timestamp   : {ts}")
    print(f"Host        : {h}")
    print(f"Phase       : {phase}")
    print(f"Severity    : {sev}")
    print(f"Title       : {title}")
    print(f"Evidence    : {ev or '(none)'}")
    print(f"Ev. path    : {path or '(inline)'}")
    print(f"Ev. sha256  : {sha or '(unhashed)'}")
    print(f"Remediation : {rem or '(none)'}")


 "---------------------------------------------------------------- verify

def verify(con) -> int:
    rows = con.execute(
        "SELECT id, host, title, evidence_path, evidence_sha256"
        " FROM findings WHERE evidence_sha256 IS NOT NULL ORDER BY id"
    ).fetchall()
    if not rows:
        print("[*] no hashed evidence to verify")
        return 0
    problems = 0
    for rid, host, title, path, expected in rows:
        if not path or not os.path.isfile(path):
            print(f"[MISSING ] id={rid:<4} {path or '(no path)'}  <- {title}")
            problems += 1
            continue
        try:
            actual = sha256_file(path)
        except OSError as exc:
            print(f"[ERROR   ] id={rid:<4} {path}: {exc}")
            problems += 1
            continue
        if actual == expected:
            print(f"[OK      ] id={rid:<4} {path}")
        else:
            print(f"[TAMPERED] id={rid:<4} {path}")
            print(f"           expected {expected}")
            print(f"           actual   {actual}")
            problems += 1
    print(f"\n{len(rows)} hashed record(s), {problems} problem(s)")
    return 1 if problems else 0


 "---------------------------------------------------------------- import

def import_headers(con, json_path: str, engagement_id: int,
                   phase: str = "Recon") -> int:
    abs_path = os.path.abspath(json_path)
    if not os.path.isfile(abs_path):
        sys.exit(f"[!] file not found: {abs_path}")
    try:
        with open(abs_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"[!] cannot parse {abs_path}: {exc}")

    host = urlparse(data.get("target", "")).hostname
    if not host:
        sys.exit("[!] JSON has no parseable 'target' URL")
    enforce_scope(con, engagement_id, host)

    digest = sha256_file(abs_path)
    missing = data.get("security_missing") or {}
    if not missing:
        print("[*] report lists no missing security headers -- nothing to import")
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
    print(f"[+] imported {inserted} finding(s), skipped {skipped} duplicate(s)")
    return 0


 "---------------------------------------------------------------- report

def to_markdown(con, out_path: str) -> None:
    rows = con.execute(
        "SELECT id, ts, host, phase, title, severity, evidence, evidence_path,"
        "       evidence_sha256, remediation FROM findings ORDER BY"
        " CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1"
        "  WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, ts DESC"
    ).fetchall()
    if not rows:
        print("[-] nothing to export")
        return
    counts = {s: 0 for s in SEVERITIES}
    for r in rows:
        counts[r[5]] = counts.get(r[5], 0) + 1

    out = ["# Engagement Findings", "", f"_Generated: {now_utc()}_", "",
           "## Summary", "", "| Severity | Count |", "|----------|-------|"]
    for s in SEVERITIES:
        if counts[s]:
            out.append(f"| {s} | {counts[s]} |")
    out.append("")

    for rid, ts, h, phase, title, sev, ev, path, sha, rem in rows:
        out += [f"## [{sev}] {title}", "",
                f"- **ID**: {rid}",
                f"- **Host**: `{h}`",
                f"- **Phase**: {phase}",
                f"- **Logged (UTC)**: {ts}",
                f"- **Evidence path**: `{path}`" if path else "- **Evidence path**: (inline)",
                f"- **Evidence SHA-256**: `{sha}`" if sha else "- **Evidence SHA-256**: (unhashed)",
                ""]
        if ev:
            out += ["**Evidence**", "", "```", ev, "```", ""]
        if rem:
            out += ["**Remediation**", "", rem, ""]

    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out))
    except OSError as exc:
        sys.exit(f"[!] cannot write {out_path}: {exc}")
    print(f"[+] Report written: {out_path} ({len(rows)} findings)")


 "---------------------------------------------------------------- CLI

def build_parser():
    p = argparse.ArgumentParser(description="Pentest finding logger v2")
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

    s = sub.add_parser("show", help="show one finding")
    s.add_argument("--id", type=int, required=True)

    sub.add_parser("verify", help="recompute evidence hashes")

    i = sub.add_parser("import", help="import headers.py --json output")
    i.add_argument("json_path")
    i.add_argument("--engagement", type=int, required=True)
    i.add_argument("--phase", default="Recon")

    r = sub.add_parser("report", help="export Markdown report")
    r.add_argument("-o", "--output", default="report.md")

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
                    print(f"  {rid:>3}  {name:<20} {scope}   ({ts})")
        elif args.command == "add":
            add_finding(con, args.host, args.phase, args.title, args.severity,
                        evidence=args.evidence,
                        evidence_file=args.evidence_file,
                        remediation=args.remediation,
                        engagement_id=args.engagement)
        elif args.command == "list":
            list_findings(con, args.host, args.severity)
        elif args.command == "show":
            show_finding(con, args.id)
        elif args.command == "verify":
            return verify(con)
        elif args.command == "import":
            return import_headers(con, args.json_path, args.engagement, args.phase)
        elif args.command == "report":
            to_markdown(con, args.output)
    except sqlite3.OperationalError as exc:
        print(f"[!] database error: {exc}", file=sys.stderr)
        return 1
    finally:
        con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

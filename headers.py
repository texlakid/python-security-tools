#!/usr/bin/env python3
"""
headers.py -- HTTP response header & TLS fingerprint auditor.
AUTHORIZED LAB USE ONLY.

One GET + capped redirect chain. Reports fingerprint, TLS posture,
security-header coverage, and cookie flag discipline.

Usage:
    python3 headers.py https://LAB_HOST/
    python3 headers.py https://LAB_HOST/ --json
    python3 headers.py http://10.10.10.10/ --insecure --timeout 8
"""
import argparse
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from urllib.parse import urlparse

UA = "headers-audit/1.0 (authorized-lab)"


SECURITY_HEADERS = {
    "Content-Security-Policy":        ("Medium",  "restricts script/style/connect origins; primary XSS mitigation"),
    "Strict-Transport-Security":      ("Medium",  "forces HTTPS for future requests; absent = downgrade risk"),
    "X-Frame-Options":                ("Low",     "clickjacking; superseded by CSP frame-ancestors"),
    "X-Content-Type-Options":         ("Low",     "stops MIME sniffing; should be 'nosniff'"),
    "Referrer-Policy":                ("Low",     "controls referrer leakage to third parties"),
    "Permissions-Policy":             ("Info",    "restricts browser features (camera, geolocation)"),
    "Cross-Origin-Opener-Policy":     ("Info",    "process isolation; mitigates XS-Leaks"),
    "Cross-Origin-Resource-Policy":   ("Info",    "blocks cross-origin resource embedding"),
}


FINGERPRINT_HEADERS = ("Server", "X-Powered-By", "Via", "X-AspNet-Version",
                       "X-Generator", "X-Drupal-Cache", "X-Varnish")

MAX_REDIRECTS = 5


class Recorder(urllib.request.HTTPRedirectHandler):
    """Follow redirects but keep the chain for the report."""
    chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        Recorder.chain.append((code, newurl))
        if len(Recorder.chain) > MAX_REDIRECTS:
            raise urllib.error.HTTPError(
                newurl, code, f"redirect cap {MAX_REDIRECTS} exceeded", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def tls_info(host, port, insecure, timeout):
    """Best-effort TLS handshake. Returns dict; never raises."""
    out = {"enabled": False}
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                out["enabled"] = True
                out["protocol"] = tls.version()
                out["cipher"] = tls.cipher()[0] if tls.cipher() else None
             
                cert = tls.getpeercert() or {}
                if cert:
                    subj = {k: v for tup in cert.get("subject", ()) for k, v in tup}
                    iss = {k: v for tup in cert.get("issuer", ()) for k, v in tup}
                    out["subject"] = subj.get("commonName")
                    out["issuer"] = iss.get("organizationName") or iss.get("commonName")
                    out["not_after"] = cert.get("notAfter")
                else:
                    out["note"] = "cert not verified (insecure mode or invalid chain)"
    except ssl.SSLCertVerificationError as exc:
        out["error"] = f"cert verification failed: {exc.verify_message}"
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        out["error"] = str(exc)
    return out


def audit_cookies(resp):
    """Flag discipline: Secure, HttpOnly, SameSite."""
    cookies = []
    for raw in resp.headers.get_all("Set-Cookie") or []:
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            cookies.append({"raw": raw, "error": "unparseable"})
            continue
        for name, morsel in jar.items():
            cookies.append({
                "name": name,
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": morsel["samesite"] or None,
            })
    return cookies


def run(url, insecure, timeout, follow):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        sys.exit("[!] URL must start with http:// or https://")
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    Recorder.chain = []
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    if follow:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx), Recorder())
    else:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx), NoRedirect())

    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    try:
        resp = opener.open(req, timeout=timeout)
        status, headers, body = resp.status, resp.headers, resp.read(4096)
    except urllib.error.HTTPError as exc:
        status, headers, body = exc.code, exc.headers, b""
    except urllib.error.URLError as exc:
        sys.exit(f"[!] request failed: {exc.reason}")
    except socket.timeout:
        sys.exit(f"[!] timeout after {timeout}s")

    present = {h: headers.get(h) for h in SECURITY_HEADERS if headers.get(h)}
    missing = {h: v for h, v in SECURITY_HEADERS.items() if h not in present}

    report = {
        "target": url,
        "status": status,
        "redirect_chain": [{"code": c, "to": u} for c, u in Recorder.chain],
        "fingerprint": {h: headers.get(h) for h in FINGERPRINT_HEADERS if headers.get(h)},
        "security_present": present,
        "security_missing": {h: {"severity": v[0], "why": v[1]} for h, v in missing.items()},
        "cookies": audit_cookies(resp),
        "tls": tls_info(host, port, insecure, timeout) if parsed.scheme == "https" else {"enabled": False},
    }
    return report


def render(r):
    print(f"\nTARGET   {r['target']}")
    print(f"STATUS   {r['status']}")
    for hop in r["redirect_chain"]:
        print(f"  -> {hop['code']} {hop['to']}")

    if r["fingerprint"]:
        print("\nFINGERPRINT")
        for k, v in r["fingerprint"].items():
            print(f"  {k}: {v}")

    t = r["tls"]
    if t.get("enabled"):
        print("\nTLS")
        print(f"  protocol : {t.get('protocol')}")
        print(f"  cipher   : {t.get('cipher')}")
        if t.get("subject"):
            print(f"  subject  : {t['subject']}")
            print(f"  issuer   : {t.get('issuer')}")
            print(f"  expires  : {t.get('not_after')}")
        if t.get("error"):
            print(f"  error    : {t['error']}")
        if t.get("note"):
            print(f"  note     : {t['note']}")
    elif t.get("error"):
        print(f"\nTLS\n  error: {t['error']}")

    print("\nSECURITY HEADERS — PRESENT")
    if not r["security_present"]:
        print("  (none)")
    for k, v in r["security_present"].items():
        print(f"  [+] {k}: {v[:110]}")

    print("\nSECURITY HEADERS — MISSING")
    if not r["security_missing"]:
        print("  (none)")
    for k, meta in sorted(r["security_missing"].items(), key=lambda x: x[1]["severity"]):
        print(f"  [{meta['severity']:<6}] {k} -- {meta['why']}")

    if r["cookies"]:
        print("\nCOOKIES")
        for c in r["cookies"]:
            if "error" in c:
                print(f"  [!] {c['raw'][:80]}")
                continue
            flags = []
            if not c["secure"]:
                flags.append("no-Secure")
            if not c["httponly"]:
                flags.append("no-HttpOnly")
            if not c["samesite"]:
                flags.append("no-SameSite")
            tag = " ; ".join(flags) if flags else "ok"
            print(f"  {c['name']:<24} {tag}")
    print()


def main():
    ap = argparse.ArgumentParser(description="HTTP header & TLS auditor (lab only)")
    ap.add_argument("url")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (labs)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--no-follow", action="store_true", help="do not follow redirects")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    report = run(args.url, args.insecure, args.timeout, not args.no_follow)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        render(report)


if __name__ == "__main__":
    main()

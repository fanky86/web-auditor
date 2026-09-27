"""Passive / low-impact security checks."""
import re
import logging
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from .utils import safe_request

logger = logging.getLogger(__name__)


SAFE_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/.env.local",
    "/config.json",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/.DS_Store",
    "/phpinfo.php",
    "/debug",
    "/actuator",
    "/actuator/health",
    "/server-status",
    "/.well-known/security.txt",
]


def check_exposed_paths(ctx):
    print("\n[SECURITY] Checking common exposed paths (low-impact, single GET)")
    for p in SAFE_PATHS:
        url = urljoin(ctx.target + "/", p.lstrip("/"))
        r = safe_request(ctx.session, "GET", url, ctx.rl,
                         timeout=ctx.config["timeout"], max_retries=0)
        if r is None:
            continue
        if r.status_code == 200 and len(r.content) > 0 and \
                "html" not in r.headers.get("Content-Type", "").lower() or \
                (r.status_code == 200 and p in ("/.git/HEAD", "/.env")):
            # heuristic: content check for git/env
            body = r.text[:400]
            sig = p in ("/.git/HEAD", "/.env") and (
                "ref:" in body or "=" in body or "[core]" in body.lower())
            if sig or (r.status_code == 200 and p in ("/phpinfo.php", "/server-status")):
                ctx.add_finding(
                    "CRITICAL", f"Exposed sensitive file: {p}",
                    url, f"HTTP 200, first bytes: {body[:120].strip()}",
                    "Publicly accessible sensitive file may leak credentials/config.",
                    f"Block access to {p} at web server / CDN level.")
                print(f"  [!] EXPOSED: {url}")


def check_directory_listing(ctx):
    print("[SECURITY] Checking directory listing")
    for p in ("/", "/uploads/", "/files/", "/static/"):
        url = urljoin(ctx.target + "/", p.lstrip("/"))
        r = safe_request(ctx.session, "GET", url, ctx.rl,
                         timeout=ctx.config["timeout"], max_retries=0)
        if r is None or r.status_code != 200:
            continue
        if re.search(r"<title>\s*Index of /", r.text, re.I):
            ctx.add_finding("MEDIUM", "Directory listing enabled",
                            url, "<title>Index of /</title> found",
                            "Attackers can enumerate files.",
                            "Disable autoindex in web server configuration.")
            print(f"  [!] Listing: {url}")


def check_open_redirect(ctx):
    print("[SECURITY] Checking open redirect indicators")
    parsed = urlparse(ctx.target)
    if not parsed.query:
        return
    qs = parse_qs(parsed.query)
    redirect_keys = [k for k in qs if k.lower() in
                     ("redirect", "next", "url", "return", "continue", "dest")]
    for k in redirect_keys:
        test_qs = dict(qs)
        test_qs[k] = ["https://example.org/"]
        new_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
        r = safe_request(ctx.session, "GET", new_url, ctx.rl,
                         timeout=ctx.config["timeout"], max_retries=0,
                         allow_redirects=False)
        if r is not None and r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if loc.startswith("https://example.org"):
                ctx.add_finding("MEDIUM", "Potential open redirect",
                                new_url, f"Redirected to {loc}",
                                "Open redirect may aid phishing.",
                                "Validate redirect targets against a whitelist.")


def check_http_methods(ctx):
    print("[SECURITY] Checking allowed HTTP methods")
    r = safe_request(ctx.session, "OPTIONS", ctx.target, ctx.rl,
                     timeout=ctx.config["timeout"], max_retries=0)
    if r is None:
        return
    allow = r.headers.get("Allow", "") or r.headers.get("Access-Control-Allow-Methods", "")
    if allow:
        print(f"  Allow: {allow}")
        risky = [m for m in ("PUT", "DELETE", "TRACE") if m in allow.upper()]
        if risky:
            ctx.add_finding("MEDIUM", "Risky HTTP methods advertised",
                            ctx.target, f"Allow: {allow}",
                            "Advertised risky methods may be reachable.",
                            "Restrict methods at the web server / WAF.")


def run_all(ctx):
    check_exposed_paths(ctx)
    check_directory_listing(ctx)
    check_open_redirect(ctx)
    check_http_methods(ctx)

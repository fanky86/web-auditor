#!/usr/bin/env python3
"""
Web Security Auditor — authorized self-audit tool.

Usage:
    python3 auditor.py

Only test domains you own or have explicit written permission to test.
"""
import os
import sys
import time
import json
import logging
import argparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError as e:
    print("[!] Missing dependency:", e)
    print("Install with:  pip install -r requirements.txt")
    sys.exit(1)

from modules.utils import (
    normalize_url, make_session, RateLimiter,
    safe_request, parse_cookie_file, DEFAULT_UA,
)
from modules import recon as recon_mod
from modules import crawler as crawler_mod
from modules import headers as headers_mod
from modules import js_analyzer as js_mod
from modules import api_discovery as api_mod
from modules import exposure as exposure_mod
from modules import security_checks as sec_mod
from modules import reporter as reporter_mod


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------
class AuditContext:
    def __init__(self, target, session, rate_limiter, config):
        self.target = target
        self.session = session
        self.rl = rate_limiter
        self.config = config
        self.start_time = time.time()
        self.findings = []          # list of finding dicts
        self.pages = []
        self.endpoints = set()
        self.api_endpoints = set()
        self.js_files = []
        self.api_results = []
        self.recon_result = None

    def add_finding(self, severity, title, url, evidence, impact, recommendation):
        f = {
            "severity": severity.upper(),
            "title": title,
            "url": url,
            "evidence": evidence,
            "impact": impact,
            "recommendation": recommendation,
            "timestamp": time.time(),
        }
        # De-duplicate by (title, url)
        for existing in self.findings:
            if existing["title"] == title and existing["url"] == url:
                return
        self.findings.append(f)


# ---------------------------------------------------------------------------
# Banner / menu
# ---------------------------------------------------------------------------
def banner():
    print("╔══════════════════════════════════╗")
    print("║      WEB SECURITY AUDITOR        ║")
    print("║    Authorized self-audit only    ║")
    print("╚══════════════════════════════════╝")


def menu():
    print("\n[1] Recon")
    print("[2] Crawl")
    print("[3] API discovery")
    print("[4] Security headers")
    print("[5] Data exposure")
    print("[6] Full audit")
    print("[0] Exit")


# ---------------------------------------------------------------------------
# Individual run modes
# ---------------------------------------------------------------------------
def do_recon(ctx):
    ctx.recon_result = recon_mod.recon(ctx)
    if ctx.recon_result:
        headers_mod.analyze_headers(ctx, ctx.recon_result["headers"],
                                    ctx.recon_result["final_url"])


def do_crawl(ctx):
    crawler_mod.crawl(ctx)
    # collect JS files from pages
    for p in ctx.pages:
        ctx.js_files.extend(p["scripts"])
    # also collect forms endpoints
    for p in ctx.pages:
        for f in p["forms"]:
            ctx.endpoints.add(f["action"])
            ctx.endpoints.add(p["url"])


def do_api(ctx):
    if not ctx.api_endpoints:
        # also seed from JS if pages already crawled
        if ctx.js_files:
            js_mod.analyze(ctx)
    api_mod.inspect_endpoints(ctx)


def do_headers(ctx):
    if not ctx.recon_result:
        ctx.recon_result = recon_mod.recon(ctx)
    if ctx.recon_result:
        headers_mod.analyze_headers(ctx, ctx.recon_result["headers"],
                                    ctx.recon_result["final_url"])


def do_exposure(ctx):
    if not ctx.pages:
        do_crawl(ctx)
    exposure_mod.analyze_pages(ctx)


def do_full(ctx):
    print("\n=== FULL AUDIT ===")
    do_recon(ctx)
    do_crawl(ctx)
    js_mod.analyze(ctx)
    api_mod.inspect_endpoints(ctx)
    do_exposure(ctx)
    sec_mod.run_all(ctx)
    print("\n[FULL] Completed.")


# ---------------------------------------------------------------------------
# CLI args (for advanced use)
# ---------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(description="Web Security Auditor (authorized self-audit)")
    p.add_argument("--target", help="Target URL (skip interactive prompt)")
    p.add_argument("--mode", choices=["recon", "crawl", "api", "headers",
                                      "exposure", "full"],
                   help="Run a specific mode non-interactively")
    p.add_argument("--cookie", help="Raw Cookie header string")
    p.add_argument("--cookie-file", help="Path to Netscape cookie file")
    p.add_argument("--max-pages", type=int, default=100)
    p.add_argument("--max-depth", type=int, default=3)
    p.add_argument("--delay", type=float, default=1.0)
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--max-requests", type=int, default=500)
    p.add_argument("--user-agent", default=DEFAULT_UA)
    p.add_argument("--output", default="reports")
    p.add_argument("--verbose", "-v", action="store_true")
    return p


def setup_logging(verbose):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def build_context(target, args):
    try:
        target = normalize_url(target)
    except ValueError as e:
        print(f"[!] Invalid target: {e}")
        sys.exit(2)

    cookies = {}
    if args.cookie:
        # Parse "k1=v1; k2=v2"
        for part in args.cookie.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
    if args.cookie_file:
        try:
            cookies.update(parse_cookie_file(args.cookie_file))
        except Exception as e:
            print(f"[!] Failed to read cookie file: {e}")

    session = make_session(user_agent=args.user_agent, cookies=cookies)
    rl = RateLimiter(delay=args.delay, max_requests=args.max_requests)
    config = {
        "max_pages": args.max_pages,
        "max_depth": args.max_depth,
        "delay": args.delay,
        "timeout": args.timeout,
        "user_agent": args.user_agent,
        "max_requests": args.max_requests,
    }
    return AuditContext(target, session, rl, config)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose)

    banner()

    # Non-interactive mode
    if args.target and args.mode:
        ctx = build_context(args.target, args)
        print(f"Target URL: {ctx.target}")
        if args.mode == "recon":    do_recon(ctx)
        elif args.mode == "crawl":  do_crawl(ctx)
        elif args.mode == "api":    do_crawl(ctx); do_api(ctx)
        elif args.mode == "headers":do_headers(ctx)
        elif args.mode == "exposure":do_exposure(ctx)
        elif args.mode == "full":   do_full(ctx)
        reporter_mod.write_all(ctx, args.output)
        return

    # Interactive
    try:
        target_in = args.target or input("Target URL: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nBye.")
        return
    if not target_in:
        print("[!] No target provided.")
        return

    ctx = build_context(target_in, args)
    print(f"\n[✓] Target set: {ctx.target}")
    print(f"    Delay {ctx.config['delay']}s | "
          f"Timeout {ctx.config['timeout']}s | "
          f"Max pages {ctx.config['max_pages']} | "
          f"Max depth {ctx.config['max_depth']}")

    while True:
        menu()
        try:
            choice = input("Select: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice == "0":
            break
        elif choice == "1":
            do_recon(ctx)
        elif choice == "2":
            do_crawl(ctx)
        elif choice == "3":
            do_crawl(ctx)
            do_api(ctx)
        elif choice == "4":
            do_headers(ctx)
        elif choice == "5":
            do_exposure(ctx)
        elif choice == "6":
            do_full(ctx)
        else:
            print("[!] Unknown option.")

        # persist report after every run
        try:
            reporter_mod.write_all(ctx, args.output)
        except Exception as e:
            print(f"[!] Report error: {e}")

    print("\nDone.")


if __name__ == "__main__":
    main()

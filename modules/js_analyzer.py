"""Download JS files and extract endpoints/URLs/patterns."""
import re
import logging
from urllib.parse import urljoin, urlparse
from .utils import safe_request

logger = logging.getLogger(__name__)

ENDPOINT_RE = re.compile(
    r"""["'`](?P<url>
        (?:https?://[^\s"'`<>]+)
        |
        (?:/(?:api|rest|graphql|admin|login|auth|user|users|upload|download|v\d+)[^\s"'`<>]*)
    )["'`]""",
    re.VERBOSE | re.IGNORECASE,
)

RELATIVE_PATH_RE = re.compile(r"""["'`](/[a-zA-Z0-9_\-/]{2,80})["'`]""")


def analyze(ctx):
    print(f"\n[JS] Analyzing {len(set(ctx.js_files))} script file(s)")
    endpoints = set()
    api_endpoints = set()

    for js_url in set(ctx.js_files):
        if not js_url.lower().endswith((".js", ".mjs", ".jsx", ".ts")) and "?" not in js_url:
            # still try fetching if script tag pointed here
            pass
        resp = safe_request(ctx.session, "GET", js_url, ctx.rl,
                            timeout=ctx.config["timeout"])
        if resp is None or resp.status_code != 200:
            continue
        text = resp.text
        size = len(text)

        # Source map
        if "sourceMappingURL=" in text:
            m = re.search(r"sourceMappingURL=([^\s*]+)", text)
            if m:
                sm = urljoin(js_url, m.group(1))
                ctx.add_finding("LOW", "Source map reference in JS",
                                js_url, f"sourceMappingURL={m.group(1)}",
                                "Source maps may expose original source code.",
                                "Do not ship source maps to production.")

        found_here = 0
        for m in ENDPOINT_RE.finditer(text):
            u = m.group("url")
            if u.startswith("//"):
                u = "https:" + u
            elif u.startswith("/"):
                u = urljoin(ctx.target, u)
            endpoints.add(u)
            if any(k in u.lower() for k in ("/api/", "/v1/", "/v2/", "/graphql", "/rest/")):
                api_endpoints.add(u)
            found_here += 1

        for m in RELATIVE_PATH_RE.finditer(text):
            p = m.group(1)
            if len(p) < 4 or p.startswith(("//", "/_", "/static", "/assets")):
                continue
            endpoints.add(urljoin(ctx.target, p))
            found_here += 1

        print(f"  {js_url[:80]}...  size={size}  refs={found_here}")

    ctx.endpoints.update(endpoints)
    ctx.api_endpoints.update(api_endpoints)
    print(f"[JS] Total unique endpoints: {len(endpoints)} (API-like: {len(api_endpoints)})")
    return endpoints, api_endpoints

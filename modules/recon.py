"""Initial reconnaissance: status, redirects, headers, cookies, robots, sitemap."""
import logging
from urllib.parse import urljoin
from .utils import safe_request

logger = logging.getLogger(__name__)


def recon(ctx, url=None):
    url = url or ctx.target
    print(f"\n[RECON] Target: {url}")
    result = {"url": url}

    resp = safe_request(ctx.session, "GET", url, ctx.rl,
                        timeout=ctx.config["timeout"])
    if resp is None:
        print("  [!] Request failed")
        return result

    result["status_code"] = resp.status_code
    result["final_url"] = resp.url
    result["redirected"] = resp.url != url
    result["headers"] = dict(resp.headers)
    result["content_type"] = resp.headers.get("Content-Type", "")
    result["content_length"] = len(resp.content)
    result["cookies"] = {c.name: {"domain": c.domain, "secure": c.secure,
                                  "httponly": c.has_nonstandard_attr("HttpOnly")
                                  if hasattr(c, "has_nonstandard_attr") else False,
                                  "samesite": c.get_nonstandard_attr("SameSite")}
                         for c in ctx.session.cookies}

    print(f"  Status         : {result['status_code']}")
    print(f"  Final URL      : {result['final_url']}")
    print(f"  Server         : {resp.headers.get('Server', 'n/a')}")
    print(f"  Content-Type   : {result['content_type']}")
    print(f"  Content-Length : {result['content_length']} bytes")
    print(f"  Cookies        : {len(result['cookies'])}")

    # robots.txt
    robots_url = urljoin(url, "/robots.txt")
    r = safe_request(ctx.session, "GET", robots_url, ctx.rl, timeout=ctx.config["timeout"])
    if r is not None and r.status_code == 200 and "text" in r.headers.get("Content-Type", ""):
        result["robots_txt"] = r.text[:5000]
        disallowed = [l.split(":", 1)[1].strip()
                      for l in r.text.splitlines()
                      if l.lower().startswith("disallow:")]
        result["robots_disallowed"] = [d for d in disallowed if d]
        print(f"  robots.txt     : {len(result['robots_disallowed'])} disallowed path(s)")
    else:
        result["robots_txt"] = None
        print("  robots.txt     : not found")

    # sitemap.xml
    sitemap_url = urljoin(url, "/sitemap.xml")
    s = safe_request(ctx.session, "GET", sitemap_url, ctx.rl, timeout=ctx.config["timeout"])
    if s is not None and s.status_code == 200 and "<urlset" in s.text.lower():
        import re
        locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", s.text)
        result["sitemap_urls"] = locs[:200]
        print(f"  sitemap.xml    : {len(locs)} URL(s)")
    else:
        result["sitemap_urls"] = []
        print("  sitemap.xml    : not found")

    return result

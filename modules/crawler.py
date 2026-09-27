"""Conservative internal crawler."""
import logging
from collections import deque
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from .utils import safe_request, same_domain

logger = logging.getLogger(__name__)


def crawl(ctx, start_url=None, max_pages=None, max_depth=None):
    start_url = start_url or ctx.target
    max_pages = max_pages or ctx.config["max_pages"]
    max_depth = max_depth or ctx.config["max_depth"]

    print(f"\n[CRAWL] start={start_url} max_pages={max_pages} max_depth={max_depth}")
    queue = deque([(start_url, 0)])
    seen = set()
    pages = []

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        if url in seen or depth > max_depth:
            continue
        seen.add(url)

        resp = safe_request(ctx.session, "GET", url, ctx.rl,
                            timeout=ctx.config["timeout"])
        if resp is None or resp.status_code >= 400:
            continue
        ctype = resp.headers.get("Content-Type", "")
        if "html" not in ctype.lower():
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        page = {
            "url": resp.url,
            "status": resp.status_code,
            "title": (soup.title.string.strip() if soup.title and soup.title.string else ""),
            "links": [], "forms": [], "scripts": [], "iframes": [], "images": [],
        }

        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            full = urljoin(resp.url, href)
            if same_domain(ctx.target, full):
                page["links"].append(full)
                if full not in seen:
                    queue.append((full, depth + 1))

        for f in soup.find_all("form"):
            page["forms"].append({
                "action": urljoin(resp.url, f.get("action", "")),
                "method": (f.get("method") or "GET").upper(),
                "inputs": [{"name": i.get("name"), "type": i.get("type", "text")}
                           for i in f.find_all(["input", "textarea", "select"])],
            })

        for s in soup.find_all("script", src=True):
            page["scripts"].append(urljoin(resp.url, s["src"]))
        for i in soup.find_all("iframe", src=True):
            page["iframes"].append(urljoin(resp.url, i["src"]))
        for img in soup.find_all("img", src=True):
            page["images"].append(urljoin(resp.url, img["src"]))

        # HTML comments
        comments = [c.strip() for c in soup.find_all(string=lambda t: isinstance(t, type(soup)) and "<!--" in str(t))]
        # BeautifulSoup strips comments; use Comment class
        from bs4 import Comment
        comments = [str(c).strip() for c in soup.find_all(string=lambda t: isinstance(t, Comment))]
        suspicious = [c for c in comments
                      if any(k in c.lower() for k in
                             ("todo", "fixme", "password", "secret", "api", "key", "debug"))]
        if suspicious:
            ctx.add_finding("LOW", "Suspicious HTML comment",
                            resp.url, "; ".join(suspicious)[:200],
                            "Comments may leak internal info.",
                            "Remove debug/TODO comments from production HTML.")

        pages.append(page)
        print(f"  [{len(pages):>3}] {resp.status_code} {resp.url} "
              f"(links={len(page['links'])}, forms={len(page['forms'])})")

    ctx.pages = pages
    print(f"[CRAWL] Done. {len(pages)} page(s) visited.")
    return pages

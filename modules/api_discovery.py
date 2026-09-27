"""Safe, low-impact API endpoint inspection."""
import logging
from .utils import safe_request
from .exposure import scan_text_for_sensitive

logger = logging.getLogger(__name__)


def _looks_like_api(url: str) -> bool:
    return any(k in url.lower() for k in (
        "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/json",
    ))


def inspect_endpoints(ctx):
    print(f"\n[API] Inspecting {len(ctx.api_endpoints)} candidate endpoint(s)")
    inspected = []

    for url in sorted(ctx.api_endpoints):
        if not _looks_like_api(url):
            continue
        # HEAD first (cheap)
        head = safe_request(ctx.session, "HEAD", url, ctx.rl,
                            timeout=ctx.config["timeout"], max_retries=1)
        status = head.status_code if head else None
        ctype = head.headers.get("Content-Type", "") if head else ""
        size = head.headers.get("Content-Length", "") if head else ""

        info = {"url": url, "method": "HEAD", "status": status,
                "content_type": ctype, "size": size, "auth_required": None,
                "json_available": False}

        # GET only if HEAD suggests OK and content is not huge
        if status and status < 400 and "html" not in ctype.lower():
            r = safe_request(ctx.session, "GET", url, ctx.rl,
                             timeout=ctx.config["timeout"], max_retries=1)
            if r is not None:
                info["method"] = "GET"
                info["status"] = r.status_code
                info["content_type"] = r.headers.get("Content-Type", "")
                info["size"] = len(r.content)
                info["auth_required"] = r.status_code in (401, 403)
                if "json" in info["content_type"].lower():
                    info["json_available"] = True
                    try:
                        data = r.json()
                        if isinstance(data, (list, dict)) and data:
                            ctx.add_finding(
                                "HIGH", "Potential public data exposure (unauthenticated JSON)",
                                url,
                                f"GET returns JSON ({info['size']} bytes) without auth",
                                "API returns data without authentication.",
                                "Require authentication and enforce authorization checks."
                            )
                    except Exception:
                        pass
                # sensitive scan
                scan_text_for_sensitive(ctx, url, r.text)

        inspected.append(info)
        print(f"  {info['status']}  {info['method']:>4}  {url[:90]}  "
              f"auth={'Y' if info['auth_required'] else 'N' if info['auth_required'] is False else '?'}")

    ctx.api_results = inspected
    return inspected

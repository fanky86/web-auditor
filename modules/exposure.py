"""Sensitive data detection & masking."""
import re
import logging
from .utils import SENSITIVE_PATTERNS, mask

logger = logging.getLogger(__name__)

# Non-secret noise filters
EMAIL_ALLOW = re.compile(r"@(example\.(com|org)|test\.(com|org)|localhost)$", re.I)


def _filter_hit(key, value):
    if key == "email":
        if EMAIL_ALLOW.search(value):
            return False
        if value.endswith((".png", ".jpg", ".gif", ".css", ".js")):
            return False
    return True


def scan_text_for_sensitive(ctx, url, text, max_hits_per_kind=3):
    """Scan text and add findings; mask values."""
    if not text:
        return []
    hits = []
    for kind, pattern in SENSITIVE_PATTERNS.items():
        count = 0
        for m in re.finditer(pattern, text):
            raw = m.group(0)
            if not _filter_hit(kind, raw):
                continue
            masked = mask(raw, keep_start=6, keep_end=4)
            # snippet around match
            start = max(0, m.start() - 30)
            end = min(len(text), m.end() + 30)
            snippet = text[start:end].replace("\n", " ")
            snippet = re.sub(re.escape(raw), masked, snippet)
            hits.append({"kind": kind, "masked": masked, "snippet": snippet})
            ctx.add_finding(
                severity="HIGH" if kind in ("jwt", "aws_access_key", "private_key",
                                            "github_token", "stripe_live", "db_uri",
                                            "api_key_kv", "password_kv") else "MEDIUM",
                title=f"Sensitive data pattern detected: {kind}",
                url=url,
                evidence=f"{masked}  …ctx: {snippet[:140]}",
                impact="Leaked secrets/credentials/PII may enable lateral attacks.",
                recommendation="Remove secrets from client-side/public responses and rotate credentials."
            )
            count += 1
            if count >= max_hits_per_kind:
                break
    return hits


def analyze_pages(ctx):
    print("\n[EXPOSURE] Scanning page bodies for sensitive patterns")
    from .utils import safe_request
    total = 0
    for page in ctx.pages:
        r = safe_request(ctx.session, "GET", page["url"], ctx.rl,
                         timeout=ctx.config["timeout"], max_retries=1)
        if r is None:
            continue
        hits = scan_text_for_sensitive(ctx, page["url"], r.text)
        if hits:
            total += len(hits)
            print(f"  {page['url'][:80]}  hits={len(hits)}")
    print(f"[EXPOSURE] Total pattern hits: {total}")
    return total

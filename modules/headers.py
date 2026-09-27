"""Security header analysis."""
import logging

logger = logging.getLogger(__name__)

REQUIRED_HEADERS = {
    "Content-Security-Policy":   "Mitigates XSS and content injection.",
    "Strict-Transport-Security": "Forces HTTPS (HSTS).",
    "X-Content-Type-Options":    "Prevents MIME sniffing (should be 'nosniff').",
    "X-Frame-Options":           "Clickjacking protection (DENY/SAMEORIGIN).",
    "Referrer-Policy":           "Controls Referer leakage.",
    "Permissions-Policy":        "Restricts browser features.",
}


def analyze_headers(ctx, headers: dict, url: str):
    print("\n[HEADERS] Security header analysis")
    present, missing = {}, []

    for h, desc in REQUIRED_HEADERS.items():
        v = headers.get(h) or headers.get(h.title())
        if v:
            present[h] = v
            print(f"  [OK]   {h}: {v[:80]}")
        else:
            missing.append(h)
            print(f"  [MISS] {h}")

    for h in missing:
        ctx.add_finding(
            severity="MEDIUM" if h in ("Content-Security-Policy",
                                        "Strict-Transport-Security") else "LOW",
            title=f"Missing security header: {h}",
            url=url,
            evidence=f"Response does not include '{h}'",
            impact=REQUIRED_HEADERS[h],
            recommendation=f"Add the '{h}' header to all responses."
        )

    # CORS
    acao = headers.get("Access-Control-Allow-Origin", "")
    accc = headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*" and accc.lower() == "true":
        ctx.add_finding("HIGH", "Insecure CORS: wildcard origin with credentials",
                        url, f"Access-Control-Allow-Origin: {acao}; Allow-Credentials: {accc}",
                        "Any origin can read authenticated responses.",
                        "Restrict ACAO to a whitelist and never combine '*' with credentials.")
    elif acao == "*":
        ctx.add_finding("LOW", "Permissive CORS (wildcard origin)",
                        url, "Access-Control-Allow-Origin: *",
                        "Public data is exposed cross-origin.",
                        "Restrict origins if the API returns user-specific data.")

    # Cache headers on responses that look dynamic
    cache = headers.get("Cache-Control", "")
    if not cache and url.startswith("https"):
        ctx.add_finding("INFO", "No Cache-Control header",
                        url, "Cache-Control missing",
                        "Sensitive responses may be cached by intermediaries.",
                        "Set Cache-Control: no-store for authenticated endpoints.")

    return {"present": present, "missing": missing}

# Web Security Auditor

A **read-only, low-impact** web security auditor for auditing **websites you own**
or that you have explicit written permission to test.

It performs reconnaissance, crawling, security-header analysis, JS endpoint
discovery, safe API inspection, and data-exposure pattern detection, then
produces JSON / HTML / TXT reports.

> ⚠️ **Authorization required.** Use only against domains you own or are
> authorized to test. Do not point this tool at third-party systems.

---

## Features

1. **Target validation** — URL normalization, HTTP/HTTPS only.
2. **HTTP reconnaissance** — status, redirects, headers, cookies, robots.txt, sitemap.xml.
3. **Security headers** — CSP, HSTS, X-CTO, X-Frame, Referrer, Permissions, CORS, cache.
4. **Frontend analysis** — links, forms, scripts, iframes, images, comments.
5. **JS endpoint discovery** — `/api/`, `/graphql`, `/v1/`, relative & absolute URLs, source maps.
6. **API inspection** — HEAD/GET, auth check, JSON detection, public-data-exposure flag.
7. **Data exposure scan** — JWT, AWS/GitHub/Google tokens, private keys, stack traces,
   internal IPs, DB URIs, credential-looking key/values — **masked output**.
8. **Passive security checks** — exposed `.git`, `.env`, backups, directory listing,
   open-redirect indicators, risky HTTP methods.
9. **Crawler** — internal-domain only, `max_pages`, `max_depth`, `delay`, `timeout`, custom UA.
10. **Rate limiting** — delay, timeout, max requests, retry limit, exponential backoff on `429`.
11. **Auth via cookies** — `--cookie` / `--cookie-file` (never prompts for password).
12. **Reports** — `reports/report.json`, `report.html`, `endpoints.txt`, `urls.txt`, `findings.txt`.
13. **Masked evidence** — secrets are never printed in full.

---

## Installation

```bash
python3 -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Dependencies: `requests`, `beautifulsoup4`, `urllib3`, `dnspython`.

---

## Usage

### Interactive

```bash
python3 auditor.py
```

```
╔══════════════════════════════════╗
║      WEB SECURITY AUDITOR        ║
║    Authorized self-audit only    ║
╚══════════════════════════════════╝
Target URL: https://example.com

[1] Recon
[2] Crawl
[3] API discovery
[4] Security headers
[5] Data exposure
[6] Full audit
[0] Exit
Select:
```

### Non-interactive

```bash
# Full audit
python3 auditor.py --target https://example.com --mode full

# Recon only, with cookies for authenticated area
python3 auditor.py --target https://example.com --mode recon \
    --cookie "session=abc123; csrf=xyz"

# With cookie file (Netscape format exported from browser)
python3 auditor.py --target https://example.com --mode full \
    --cookie-file cookies.txt

# Tuning
python3 auditor.py --target https://example.com --mode full \
    --max-pages 50 --max-depth 2 --delay 1.5 --timeout 15
```

---

## Command-line options

| Option            | Default              | Description                                   |
|-------------------|----------------------|-----------------------------------------------|
| `--target`        | prompt               | Target URL                                    |
| `--mode`          | interactive          | `recon` \| `crawl` \| `api` \| `headers` \| `exposure` \| `full` |
| `--cookie`        | –                    | Raw cookie string `k=v; k2=v2`                |
| `--cookie-file`   | –                    | Netscape-format cookie file                   |
| `--max-pages`     | 100                  | Crawl page limit                              |
| `--max-depth`     | 3                    | Crawl depth limit                             |
| `--delay`         | 1.0                  | Delay between requests (seconds)              |
| `--timeout`       | 10                   | Per-request timeout (seconds)                 |
| `--max-requests`  | 500                  | Global request budget                         |
| `--user-agent`    | WebSecurityAuditor…  | Custom User-Agent                             |
| `--output`        | `reports`            | Report output directory                       |
| `-v, --verbose`   | off                  | Debug logging                                 |

---

## Module overview

| Module                  | Responsibility                                                              |
|-------------------------|-----------------------------------------------------------------------------|
| `modules/utils.py`      | Session, rate-limiter, safe-request, masking, sensitive-data patterns, cookie parsing. |
| `modules/recon.py`      | Initial GET, headers snapshot, cookies, `robots.txt`, `sitemap.xml`.        |
| `modules/headers.py`    | Security-header presence, CORS, cache-control analysis → findings.         |
| `modules/crawler.py`    | Internal-only BFS crawler, respects depth/page limits, extracts links, forms, scripts, iframes, comments. |
| `modules/js_analyzer.py`| Downloads referenced JS, extracts endpoint/URL patterns, flags source maps. |
| `modules/api_discovery.py`| HEAD/GET API candidates, detects 401/403 vs open JSON, forwards to exposure scan. |
| `modules/exposure.py`   | Regex scan for secrets/PII/stack traces/internal hosts/DB URIs; masked evidence. |
| `modules/security_checks.py`| `.git`, `.env`, backups, directory listing, open redirect, risky methods. |
| `modules/reporter.py`   | Writes JSON, HTML, endpoints.txt, urls.txt, findings.txt.                   |

---

## Example report (JSON, abridged)

```json
{
  "summary": {
    "target": "https://example.com",
    "date": "2024-05-12T10:22:31Z",
    "duration_seconds": 42.7,
    "pages_discovered": 17,
    "endpoints_discovered": 143,
    "api_endpoints_discovered": 12,
    "findings_total": 9,
    "requests_made": 92
  },
  "findings": [
    {
      "severity": "HIGH",
      "title": "Potential public data exposure (unauthenticated JSON)",
      "url": "https://example.com/api/v1/users",
      "evidence": "GET returns JSON (24531 bytes) without auth",
      "impact": "API returns data without authentication.",
      "recommendation": "Require authentication and enforce authorization checks."
    },
    {
      "severity": "MEDIUM",
      "title": "Missing security header: Content-Security-Policy",
      "url": "https://example.com/",
      "evidence": "Response does not include 'Content-Security-Policy'",
      "impact": "Mitigates XSS and content injection.",
      "recommendation": "Add the 'Content-Security-Policy' header to all responses."
    },
    {
      "severity": "HIGH",
      "title": "Sensitive data pattern detected: stripe_live",
      "url": "https://example.com/static/app.js",
      "evidence": "sk_live_************abcd  …ctx: const KEY='sk_live_************abcd'",
      "impact": "Leaked secrets/credentials/PII may enable lateral attacks.",
      "recommendation": "Remove secrets from client-side/public responses and rotate credentials."
    }
  ]
}
```

---

## Example report (HTML)

The HTML report (`reports/report.html`) contains:

* Header card with target, date, duration, request count.
* Summary list (pages / endpoints / findings).
* Findings list, each with left-border colour-coded by severity.
* Two tables: discovered pages, inspected API endpoints.

Open it in any browser.

---

## Safety & rate-limiting

* All requests are **read-only** (`GET`, `HEAD`, `OPTIONS`).
* No brute-force, no payload injection, no data mutation, no uploads, no account creation.
* One request at a time (sequential), configurable delay, retry with exponential backoff on `429`.
* Global `--max-requests` cap stops the run when the budget is exhausted.
* Findings are heuristic; severity is based on **observed evidence**, not assumption.
* Secrets are always **masked** before being written to the console or reports.

---

## Legal

This tool is intended for owners auditing their own properties. Running it against
systems you do not own or have not been authorized to test may violate laws in your
jurisdiction. You are solely responsible for how you use it.

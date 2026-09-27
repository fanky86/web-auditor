"""Shared utilities: rate limiting, session, masking, request helpers."""
import re
import time
import logging
import requests
from urllib.parse import urlparse, urljoin
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)

DEFAULT_UA = "WebSecurityAuditor/1.0 (+authorized-self-audit)"

# Patterns for sensitive data detection (used by exposure + reporter)
SENSITIVE_PATTERNS = {
    "email":         r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "jwt":           r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
    "aws_access_key":r"AKIA[0-9A-Z]{16}",
    "google_api":    r"AIza[0-9A-Za-z_\-]{35}",
    "github_token":  r"ghp_[A-Za-z0-9]{36}",
    "stripe_live":   r"sk_live_[0-9a-zA-Z]{16,}",
    "private_key":   r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "password_kv":   r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"']([^\"']{3,})[\"']",
    "api_key_kv":    r"(?i)(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{12,})[\"']",
    "stack_trace":   r"(?:Traceback \(most recent call last\)|at [\w.$]+\([\w.$]+\.java:\d+\)|File \"[^\"]+\", line \d+)",
    "internal_host": r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b",
    "db_uri":        r"(?i)(?:mongodb|mysql|postgres|postgresql|redis)://[^\s\"'<>]+",
    "user_id_field": r"(?i)\"(?:user_?id|uid|internal_?id|account_?id)\"\s*:\s*\d+",
}


def mask(value: str, keep_start: int = 6, keep_end: int = 4) -> str:
    """Mask sensitive string, e.g. sk_live_************abcd."""
    if not value:
        return value
    if len(value) <= keep_start + keep_end:
        return "*" * len(value)
    return value[:keep_start] + "*" * (len(value) - keep_start - keep_end) + value[-keep_end:]


def normalize_url(url: str) -> str:
    """Normalize user input into a valid http(s) URL."""
    url = (url or "").strip()
    if not url:
        raise ValueError("Empty URL")
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    p = urlparse(url)
    if not p.netloc:
        raise ValueError("Invalid URL")
    path = p.path.rstrip("/")
    return f"{p.scheme}://{p.netloc}{path}"


def same_domain(base: str, candidate: str) -> bool:
    try:
        return urlparse(base).netloc.lower() == urlparse(candidate).netloc.lower()
    except Exception:
        return False


def join_url(base: str, link: str) -> str:
    return urljoin(base, link)


class RateLimiter:
    """Simple token-ish rate limiter with adaptive slowdown on 429."""

    def __init__(self, delay: float = 1.0, max_requests: int = 500):
        self.base_delay = delay
        self.delay = delay
        self.max_requests = max_requests
        self._count = 0
        self._last = 0.0

    def wait(self):
        if self._count >= self.max_requests:
            raise RuntimeError(f"Max requests reached ({self.max_requests})")
        elapsed = time.time() - self._last
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last = time.time()
        self._count += 1

    def slow_down(self, extra: float = 1.0):
        self.delay = min(self.delay + extra, 30.0)

    @property
    def count(self):
        return self._count


def make_session(user_agent: str = DEFAULT_UA, cookies: dict | None = None) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    if cookies:
        s.cookies.update(cookies)
    return s


def safe_request(session: requests.Session, method: str, url: str,
                 rate_limiter: RateLimiter, timeout: int = 10,
                 max_retries: int = 2, **kwargs):
    """Rate-limited request with retry + exponential backoff on 429/errors."""
    backoff = 1.0
    for attempt in range(max_retries + 1):
        try:
            rate_limiter.wait()
        except RuntimeError as e:
            logger.warning(str(e))
            return None
        try:
            resp = session.request(method, url, timeout=timeout,
                                   allow_redirects=True, **kwargs)
            if resp.status_code == 429:
                ra = resp.headers.get("Retry-After", "")
                wait = float(ra) if ra.replace(".", "", 1).isdigit() else backoff * 2
                wait = min(wait, 30.0)
                logger.warning(f"429 received, sleeping {wait:.1f}s")
                rate_limiter.slow_down(1.0)
                time.sleep(wait)
                backoff *= 2
                continue
            return resp
        except requests.RequestException as e:
            logger.debug(f"Request error {method} {url}: {e}")
            time.sleep(backoff)
            backoff *= 2
    return None


def parse_cookie_file(path: str) -> dict:
    """Parse a Netscape-style cookie file (also accepts simple key=value lines)."""
    cookies = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 7:
                cookies[parts[5]] = parts[6]
            elif "=" in line:
                k, v = line.split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies

"""
heuristics.py - URL Heuristic Analysis for Phishing Detection
Analyzes URLs using pattern matching, entropy, and structural anomalies.
"""

import re
import math
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Tuple


# ─── Known brand names commonly abused in phishing ──────────────────────────
BRAND_KEYWORDS = [
    "paypal", "amazon", "google", "facebook", "microsoft", "apple",
    "netflix", "instagram", "linkedin", "twitter", "dropbox", "chase",
    "wellsfargo", "bankofamerica", "citibank", "ebay", "steam", "discord",
]

# ─── Suspicious TLDs often used in phishing campaigns ───────────────────────
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Free Freenom TLDs
    ".xyz", ".top", ".work", ".click",
    ".loan", ".win", ".racing", ".stream",
    ".party", ".gdn", ".men",
}

# ─── URL shorteners ──────────────────────────────────────────────────────────
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bit.do", "shorte.st",
    "cutt.ly", "rb.gy",
}


@dataclass
class HeuristicResult:
    score: int = 0                          # Risk score 0–100
    flags: List[Tuple[str, int]] = field(default_factory=list)  # (reason, points)

    def add(self, reason: str, points: int) -> None:
        self.flags.append((reason, points))
        self.score = min(self.score + points, 100)

    @property
    def risk_level(self) -> str:
        if self.score >= 70:
            return "HIGH"
        elif self.score >= 40:
            return "MEDIUM"
        return "LOW"


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string (higher = more random)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def analyze_url(url: str) -> HeuristicResult:
    """
    Run all heuristic checks on a URL and return a HeuristicResult.
    """
    result = HeuristicResult()

    # Ensure scheme is present for parsing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        result.add("Could not parse URL", 30)
        return result

    hostname = parsed.hostname or ""
    path     = parsed.path or ""
    query    = parsed.query or ""
    full_url = url.lower()

    # ── 1. IP address instead of domain ─────────────────────────────────────
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    if ip_pattern.match(hostname):
        result.add("IP address used instead of domain", 25)

    # ── 2. Suspicious TLD ───────────────────────────────────────────────────
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            result.add(f"Suspicious TLD: {tld}", 15)
            break

    # ── 3. Brand keyword in subdomain / path (not in registered domain) ─────
    parts = hostname.split(".")
    # registered domain = last two parts (e.g. "evil.com")
    registered = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    subdomains_and_path = ".".join(parts[:-2]) + path

    for brand in BRAND_KEYWORDS:
        if brand in subdomains_and_path.lower() and brand not in registered.lower():
            result.add(f"Brand '{brand}' impersonated in subdomain/path", 20)
            break

    # ── 4. Excessive subdomains (≥ 4 levels) ────────────────────────────────
    if len(parts) >= 4:
        result.add(f"Excessive subdomain depth ({len(parts)} levels)", 15)

    # ── 5. Long hostname (> 30 chars) ───────────────────────────────────────
    if len(hostname) > 30:
        result.add(f"Long hostname ({len(hostname)} chars)", 10)

    # ── 6. Hyphen abuse (≥ 3 hyphens in hostname) ───────────────────────────
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        result.add(f"Excessive hyphens in hostname ({hyphen_count})", 10)

    # ── 7. @ symbol in URL (used to obfuscate real host) ────────────────────
    if "@" in full_url:
        result.add("@ symbol in URL (host obfuscation)", 25)

    # ── 8. Double slash redirect trick (//evil.com) ─────────────────────────
    if re.search(r"https?://[^/]+//", url):
        result.add("Double-slash redirect pattern", 20)

    # ── 9. HTTP (not HTTPS) ─────────────────────────────────────────────────
    if parsed.scheme == "http":
        result.add("Non-HTTPS connection (plain HTTP)", 10)

    # ── 10. URL shortener ───────────────────────────────────────────────────
    if hostname in SHORTENERS:
        result.add(f"URL shortener detected ({hostname})", 20)

    # ── 11. High entropy hostname (random-looking domain) ───────────────────
    domain_label = parts[-2] if len(parts) >= 2 else hostname
    entropy = shannon_entropy(domain_label)
    if entropy > 3.8:
        result.add(f"High entropy domain label (entropy={entropy:.2f})", 15)

    # ── 12. Suspicious keywords in path/query ───────────────────────────────
    suspicious_words = [
        "login", "signin", "verify", "account", "secure", "update",
        "confirm", "banking", "password", "credential", "wallet",
    ]
    combined = (path + query).lower()
    hits = [w for w in suspicious_words if w in combined]
    if hits:
        result.add(f"Suspicious keywords in path/query: {', '.join(hits)}", 10)

    # ── 13. Numeric obfuscation in hostname ─────────────────────────────────
    if re.search(r"\d{4,}", hostname):
        result.add("Long numeric sequence in hostname", 10)

    # ── 14. Punycode / IDN homograph attack ─────────────────────────────────
    if "xn--" in hostname:
        result.add("Punycode/IDN hostname (possible homograph attack)", 30)

    return result

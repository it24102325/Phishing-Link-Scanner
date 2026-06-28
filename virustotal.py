"""
virustotal.py - VirusTotal API v3 Integration
Submits URLs to VirusTotal and parses multi-engine scan results.
"""

import hashlib
import time
import requests
from typing import Optional


VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalScanner:
    """
    Wraps the VirusTotal v3 API for URL scanning.

    Usage:
        scanner = VirusTotalScanner(api_key="YOUR_KEY")
        result  = scanner.scan("https://suspicious-site.tk/login")
    """

    def __init__(self, api_key: str, timeout: int = 20) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
        }

    # ── Public interface ─────────────────────────────────────────────────────

    def scan(self, url: str) -> dict:
        """
        Submit *url* for scanning, poll for results, and return a parsed dict.

        Returns:
            {
                "available": bool,
                "malicious": int,
                "suspicious": int,
                "undetected": int,
                "total_engines": int,
                "permalink": str,
                "engines": {engine_name: {"category": ..., "result": ...}, ...}
            }
        """
        if not self.api_key:
            return self._unavailable("No API key provided")

        # Step 1 – check cache by URL ID first (avoids quota burns)
        url_id = self._url_id(url)
        cached = self._fetch_report(url_id)
        if cached:
            return self._parse(cached, url)

        # Step 2 – submit URL for fresh scan
        analysis_id = self._submit(url)
        if not analysis_id:
            return self._unavailable("Failed to submit URL to VirusTotal")

        # Step 3 – poll analysis endpoint (max 30 s)
        report = self._poll(analysis_id)
        if not report:
            return self._unavailable("Analysis did not complete in time")

        return self._parse(report, url)

    # ── Private helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _url_id(url: str) -> str:
        """VirusTotal URL ID = base64url(sha256(url)) without padding."""
        import base64
        digest = hashlib.sha256(url.encode()).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    def _fetch_report(self, url_id: str) -> Optional[dict]:
        """Try to get an existing cached report."""
        try:
            resp = requests.get(
                f"{VT_BASE}/urls/{url_id}",
                headers=self.headers,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                return resp.json()
        except requests.RequestException:
            pass
        return None

    def _submit(self, url: str) -> Optional[str]:
        """Submit a URL scan and return the analysis ID."""
        try:
            resp = requests.post(
                f"{VT_BASE}/urls",
                headers={**self.headers, "Content-Type": "application/x-www-form-urlencoded"},
                data=f"url={requests.utils.quote(url, safe='')}",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                return resp.json()["data"]["id"]
        except (requests.RequestException, KeyError):
            pass
        return None

    def _poll(self, analysis_id: str, wait: int = 30, interval: int = 5) -> Optional[dict]:
        """Poll the analyses endpoint until status is 'completed'."""
        deadline = time.time() + wait
        while time.time() < deadline:
            try:
                resp = requests.get(
                    f"{VT_BASE}/analyses/{analysis_id}",
                    headers=self.headers,
                    timeout=self.timeout,
                )
                data = resp.json()
                if data.get("data", {}).get("attributes", {}).get("status") == "completed":
                    return data
            except (requests.RequestException, KeyError):
                pass
            time.sleep(interval)
        return None

    @staticmethod
    def _parse(data: dict, url: str) -> dict:
        """Normalise raw VT JSON into a clean result dict."""
        try:
            # Cached URL report vs fresh analysis have slightly different shapes
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            engines_raw = attrs.get("last_analysis_results", {})

            engines = {
                name: {
                    "category": v.get("category", ""),
                    "result":   v.get("result", ""),
                }
                for name, v in engines_raw.items()
            }

            total = sum(stats.values())
            permalink = f"https://www.virustotal.com/gui/url/{VirusTotalScanner._url_id(url)}"

            return {
                "available":     True,
                "malicious":     stats.get("malicious", 0),
                "suspicious":    stats.get("suspicious", 0),
                "undetected":    stats.get("undetected", 0),
                "harmless":      stats.get("harmless", 0),
                "total_engines": total,
                "permalink":     permalink,
                "engines":       engines,
            }
        except Exception:
            return VirusTotalScanner._unavailable("Failed to parse VirusTotal response")

    @staticmethod
    def _unavailable(reason: str) -> dict:
        return {
            "available":     False,
            "reason":        reason,
            "malicious":     0,
            "suspicious":    0,
            "undetected":    0,
            "harmless":      0,
            "total_engines": 0,
            "permalink":     "",
            "engines":       {},
        }

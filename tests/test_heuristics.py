"""
tests/test_heuristics.py - Unit tests for the heuristic analysis engine
Run with:  python3 -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from heuristics import analyze_url, shannon_entropy


# ── Shannon entropy ──────────────────────────────────────────────────────────

class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_random_looking_string(self):
        # High-entropy string
        assert shannon_entropy("aB3#mZ9xQwRt") > 3.0

    def test_uniform_distribution(self):
        # "abcd" has 4 unique chars → max entropy for length 4
        e = shannon_entropy("abcd")
        assert e == pytest.approx(2.0, abs=0.01)


# ── IP address detection ─────────────────────────────────────────────────────

class TestIPAddress:
    def test_ipv4_url_flagged(self):
        r = analyze_url("http://192.168.1.1/login")
        reasons = [f for f, _ in r.flags]
        assert any("IP address" in reason for reason in reasons)

    def test_normal_domain_not_flagged_as_ip(self):
        r = analyze_url("https://google.com")
        reasons = [f for f, _ in r.flags]
        assert not any("IP address" in reason for reason in reasons)


# ── Brand impersonation ──────────────────────────────────────────────────────

class TestBrandImpersonation:
    def test_paypal_in_subdomain(self):
        r = analyze_url("http://paypal.verify-account.evil.tk/signin")
        reasons = [f for f, _ in r.flags]
        assert any("paypal" in reason.lower() for reason in reasons)

    def test_real_paypal_not_flagged(self):
        r = analyze_url("https://www.paypal.com/signin")
        reasons = [f for f, _ in r.flags]
        assert not any("impersonated" in reason for reason in reasons)


# ── Suspicious TLD ───────────────────────────────────────────────────────────

class TestSuspiciousTLD:
    @pytest.mark.parametrize("tld", [".tk", ".ml", ".xyz", ".top"])
    def test_suspicious_tld_flagged(self, tld):
        r = analyze_url(f"http://secure-login{tld}/account")
        assert any(tld in f for f, _ in r.flags)

    def test_com_not_flagged(self):
        r = analyze_url("https://example.com/path")
        assert not any("TLD" in f for f, _ in r.flags)


# ── Punycode ─────────────────────────────────────────────────────────────────

class TestPunycode:
    def test_punycode_hostname_flagged(self):
        r = analyze_url("https://xn--pypal-4ve.com/")
        reasons = [f for f, _ in r.flags]
        assert any("Punycode" in reason or "IDN" in reason for reason in reasons)


# ── URL shortener ────────────────────────────────────────────────────────────

class TestURLShortener:
    def test_bitly_flagged(self):
        r = analyze_url("https://bit.ly/abc123")
        assert any("shortener" in f.lower() for f, _ in r.flags)

    def test_tinyurl_flagged(self):
        r = analyze_url("http://tinyurl.com/xyz999")
        assert any("shortener" in f.lower() for f, _ in r.flags)


# ── @ symbol obfuscation ─────────────────────────────────────────────────────

class TestAtSymbol:
    def test_at_symbol_flagged(self):
        r = analyze_url("http://user@evil.com/login")
        assert any("@" in f for f, _ in r.flags)


# ── HTTP (not HTTPS) ─────────────────────────────────────────────────────────

class TestHTTP:
    def test_http_flagged(self):
        r = analyze_url("http://normalsite.com/page")
        assert any("HTTP" in f or "http" in f.lower() for f, _ in r.flags)

    def test_https_not_flagged_for_scheme(self):
        r = analyze_url("https://normalsite.com/page")
        assert not any("Non-HTTPS" in f for f, _ in r.flags)


# ── Score bounds ─────────────────────────────────────────────────────────────

class TestScoreBounds:
    def test_score_never_exceeds_100(self):
        # Pile on every bad signal
        r = analyze_url("http://192.168.1.1@paypal.verify.xn--login.tk/signin?password=x")
        assert r.score <= 100

    def test_score_is_non_negative(self):
        r = analyze_url("https://google.com")
        assert r.score >= 0


# ── Risk level labels ────────────────────────────────────────────────────────

class TestRiskLevels:
    def test_clearly_phishing_is_high(self):
        r = analyze_url("http://192.168.0.1/paypal-login-verify.tk")
        assert r.risk_level == "HIGH"

    def test_clean_url_is_low(self):
        r = analyze_url("https://github.com/user/repo")
        assert r.risk_level == "LOW"

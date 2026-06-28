#!/usr/bin/env python3
"""
scanner.py - Phishing Link Scanner (Main Entry Point)
=====================================================
Cybersecurity portfolio project for Kali Linux.

Usage:
    python3 scanner.py -u https://suspicious-site.tk/login
    python3 scanner.py -f urls.txt --vt-key YOUR_KEY --save
    python3 scanner.py -u http://paypal-secure.verify.ml --engines

Author : Muditha
Project: Phishing Link Scanner
"""

import argparse
import sys
import os
from typing import Optional

from heuristics import analyze_url
from virustotal import VirusTotalScanner
from report import print_banner, print_result, save_report


# ── Argument parser ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scanner",
        description="Phishing Link Scanner — heuristic + VirusTotal analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single URL (offline heuristics only):
    python3 scanner.py -u https://paypal-login.verify.ml

  Single URL with VirusTotal:
    python3 scanner.py -u https://bit.ly/abc123 --vt-key YOUR_API_KEY

  Batch scan from file + save JSON reports:
    python3 scanner.py -f urls.txt --vt-key YOUR_API_KEY --save

  Show flagging AV engines:
    python3 scanner.py -u https://evil-login.tk --vt-key KEY --engines
        """,
    )

    # Target
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url",  metavar="URL",  help="Single URL to scan")
    group.add_argument("-f", "--file", metavar="FILE", help="File with one URL per line")

    # VirusTotal
    p.add_argument(
        "--vt-key",
        metavar="API_KEY",
        default=os.getenv("VT_API_KEY", ""),
        help="VirusTotal API key (or set VT_API_KEY env var)",
    )

    # Output
    p.add_argument("--save",    action="store_true", help="Save JSON report to reports/")
    p.add_argument("--engines", action="store_true", help="Show flagging AV engines")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colours")

    return p


# ── Core scan logic ──────────────────────────────────────────────────────────

def scan_one(
    url: str,
    vt: Optional[VirusTotalScanner],
    args: argparse.Namespace,
) -> dict:
    """Run heuristics (+ optionally VT) on a single URL."""

    url = url.strip()
    if not url:
        return {}

    # 1. Heuristic analysis (always runs, no network needed)
    heuristic_result = analyze_url(url)

    # 2. VirusTotal (only if API key supplied)
    vt_result = None
    if vt:
        print(f"  Querying VirusTotal for: {url[:70]}…")
        vt_result = vt.scan(url)

    # 3. Print to terminal
    print_result(url, heuristic_result, vt_result, show_engines=args.engines)

    # 4. Optionally save JSON report
    saved_path = None
    if args.save:
        saved_path = save_report(url, heuristic_result, vt_result)
        print(f"  ✔  Report saved → {saved_path}\n")

    return {
        "url":       url,
        "score":     heuristic_result.score,
        "risk":      heuristic_result.risk_level,
        "flags":     len(heuristic_result.flags),
        "vt_hits":   (vt_result or {}).get("malicious", 0),
        "saved":     saved_path,
    }


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    # Disable colour if requested
    if args.no_color:
        import report as _r
        for attr in ("RED", "YELLOW", "GREEN", "CYAN", "BOLD", "DIM", "RESET"):
            setattr(_r.C, attr, "")

    print_banner()

    # Build VT scanner (None if no key)
    vt_scanner = VirusTotalScanner(args.vt_key) if args.vt_key else None
    if not vt_scanner:
        print("  ℹ  No VirusTotal API key — running heuristics only.\n"
              "     Add --vt-key YOUR_KEY or set VT_API_KEY env var.\n")

    # Collect URLs
    if args.url:
        urls = [args.url]
    else:
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                urls = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except FileNotFoundError:
            print(f"[ERROR] File not found: {args.file}")
            sys.exit(1)

    if not urls:
        print("[ERROR] No URLs to scan.")
        sys.exit(1)

    # Run scans
    results = []
    for url in urls:
        r = scan_one(url, vt_scanner, args)
        if r:
            results.append(r)

    # ── Summary table (batch mode) ───────────────────────────────────────────
    if len(results) > 1:
        print("\n" + "═" * 52)
        print(f"  SUMMARY  ({len(results)} URLs scanned)")
        print("═" * 52)
        for r in results:
            risk_icons = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
            icon = risk_icons.get(r["risk"], "⚪")
            print(
                f"  {icon} [{r['risk']:<6}] score={r['score']:>3}  "
                f"flags={r['flags']}  vt={r['vt_hits']}  "
                f"{r['url'][:45]}"
            )
        high   = sum(1 for r in results if r["risk"] == "HIGH")
        medium = sum(1 for r in results if r["risk"] == "MEDIUM")
        print(f"\n  Total HIGH: {high}  MEDIUM: {medium}  LOW: {len(results)-high-medium}")
        print("═" * 52 + "\n")


if __name__ == "__main__":
    main()

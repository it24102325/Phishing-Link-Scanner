#!/usr/bin/env python3
"""
app.py - Interactive Terminal UI for Phishing Link Scanner
==========================================================
A numbered-menu terminal interface that wraps scanner.py,
heuristics.py, virustotal.py, and report.py in one place.

Usage:
    python3 app.py
"""

import os
import sys
import json
import time
import math
import re
import urllib.parse
from datetime import datetime

# ── Try importing project modules ────────────────────────────────────────────
try:
    from heuristics import analyze_url, HeuristicResult
    from virustotal import VirusTotalScanner
    from report import save_report
except ImportError as e:
    print(f"[ERROR] Missing module: {e}")
    print("Make sure heuristics.py, virustotal.py, report.py are in the same folder.")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
#  ANSI colour / style helpers
# ─────────────────────────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"
    BG_RED = "\033[41m"

def clr(text, *codes):
    return "".join(codes) + str(text) + C.RESET

def risk_colour(level):
    return {
        "HIGH":   C.RED,
        "MEDIUM": C.YELLOW,
        "LOW":    C.GREEN,
    }.get(level, C.RESET)

def score_bar(score, width=20):
    filled = int(score / 100 * width)
    col = C.RED if score >= 70 else (C.YELLOW if score >= 40 else C.GREEN)
    bar = clr("█" * filled, col) + clr("░" * (width - filled), C.DIM)
    return f"[{bar}]"

def clear():
    os.system("clear" if os.name != "nt" else "cls")

def sep(char="─", width=56):
    return clr(char * width, C.DIM)

def header(title):
    print(sep())
    print(clr(f"  {title}", C.CYAN, C.BOLD))
    print(sep())

def pause():
    input(clr("\n  Press Enter to continue...", C.DIM))


# ─────────────────────────────────────────────────────────────────────────────
#  Scan history (in-memory for this session)
# ─────────────────────────────────────────────────────────────────────────────

scan_history = []   # list of dicts


# ─────────────────────────────────────────────────────────────────────────────
#  Banner
# ─────────────────────────────────────────────────────────────────────────────

def print_banner():
    clear()
    print()
    print(clr("╔══════════════════════════════════════════════════════╗", C.CYAN))
    print(clr("║", C.CYAN) + clr("       PHISHING LINK SCANNER  v1.0                  ", C.WHITE, C.BOLD) + clr("║", C.CYAN))
    print(clr("║", C.CYAN) + clr("       Cybersecurity Portfolio Project               ", C.DIM) + clr("║", C.CYAN))
    print(clr("╚══════════════════════════════════════════════════════╝", C.CYAN))
    print()


# ─────────────────────────────────────────────────────────────────────────────
#  Main menu
# ─────────────────────────────────────────────────────────────────────────────

def main_menu(vt_key):
    vt_status = clr("● connected", C.GREEN) if vt_key else clr("○ not set", C.DIM)
    print(clr("  VirusTotal API", C.DIM) + f"  {vt_status}")
    print()
    print(clr("  ┌─ MENU ──────────────────────────────────┐", C.DIM))
    print(clr("  │", C.DIM) + f"  {clr('1', C.YELLOW, C.BOLD)}  Scan a single URL                       " + clr("│", C.DIM))
    print(clr("  │", C.DIM) + f"  {clr('2', C.YELLOW, C.BOLD)}  Heuristic deep-inspect (14 checks)      " + clr("│", C.DIM))
    print(clr("  │", C.DIM) + f"  {clr('3', C.YELLOW, C.BOLD)}  Batch scan from file / paste            " + clr("│", C.DIM))
    print(clr("  │", C.DIM) + f"  {clr('4', C.YELLOW, C.BOLD)}  View scan history                       " + clr("│", C.DIM))
    print(clr("  │", C.DIM) + f"  {clr('5', C.YELLOW, C.BOLD)}  Set VirusTotal API key                  " + clr("│", C.DIM))
    print(clr("  │", C.DIM) + f"  {clr('6', C.YELLOW, C.BOLD)}  Help & usage guide                      " + clr("│", C.DIM))
    print(clr("  │", C.DIM) + f"  {clr('0', C.RED,    C.BOLD)}  Exit                                    " + clr("│", C.DIM))
    print(clr("  └─────────────────────────────────────────┘", C.DIM))
    print()
    choice = input(clr("  scanner", C.CYAN) + clr(" $ ", C.DIM)).strip()
    return choice


# ─────────────────────────────────────────────────────────────────────────────
#  View 1 — Single URL scan
# ─────────────────────────────────────────────────────────────────────────────

def view_scan_url(vt_scanner):
    clear()
    print_banner()
    header("1  ·  Scan a Single URL")
    print()
    url = input(clr("  Enter URL: ", C.WHITE)).strip()
    if not url:
        print(clr("  No URL entered.", C.DIM))
        pause()
        return

    print()
    print(clr("  Running heuristic analysis...", C.DIM))
    hresult = analyze_url(url)

    vt_result = None
    if vt_scanner:
        print(clr("  Querying VirusTotal (may take ~10s)...", C.DIM))
        vt_result = vt_scanner.scan(url)

    _print_full_result(url, hresult, vt_result)

    # Add to history
    scan_history.append({
        "ts":       datetime.now().strftime("%H:%M:%S"),
        "url":      url,
        "score":    hresult.score,
        "risk":     hresult.risk_level,
        "flags":    len(hresult.flags),
        "vt_hits":  (vt_result or {}).get("malicious", 0),
    })

    # Offer to save
    print()
    save = input(clr("  Save JSON report? [y/N]: ", C.DIM)).strip().lower()
    if save == "y":
        path = save_report(url, hresult, vt_result)
        print(clr(f"  ✔  Saved → {path}", C.GREEN))
    pause()


def _print_full_result(url, hresult, vt_result=None, show_engines=False):
    rc = risk_colour(hresult.risk_level)
    print()
    print(sep())
    print(clr("  URL ", C.DIM) + clr(url, C.WHITE))
    print(sep())
    print()
    # Heuristic block
    print(clr("  ■ HEURISTIC ANALYSIS", C.CYAN, C.BOLD))
    print(f"    Risk Level  {clr(hresult.risk_level, rc, C.BOLD)}")
    print(f"    Score       {clr(hresult.score, rc, C.BOLD)}/100  {score_bar(hresult.score)}")
    print()
    if hresult.flags:
        print(clr("    Flags detected:", C.DIM))
        for reason, pts in hresult.flags:
            print(f"      {clr('▸', C.YELLOW)} {reason}  {clr(f'+{pts}', C.DIM)}")
    else:
        print(clr("    ✓ No suspicious patterns found", C.GREEN))

    print()
    # VT block
    print(clr("  ■ VIRUSTOTAL", C.CYAN, C.BOLD))
    if not vt_result or not vt_result.get("available"):
        reason = (vt_result or {}).get("reason", "Not requested — use option 5 to set API key")
        print(clr(f"    Unavailable — {reason}", C.DIM))
    else:
        mal = vt_result["malicious"]
        sus = vt_result["suspicious"]
        tot = vt_result["total_engines"]
        mc  = C.RED if mal > 0 else (C.YELLOW if sus > 0 else C.GREEN)
        print(f"    Malicious   {clr(mal, mc, C.BOLD)} / {tot} engines")
        print(f"    Suspicious  {clr(sus, C.YELLOW)} / {tot}")
        print(f"    Harmless    {clr(vt_result['harmless'], C.GREEN)}")
        print(f"    Report      {clr(vt_result['permalink'], C.BLUE)}")
        if show_engines:
            flagged = {n: v for n, v in vt_result.get("engines", {}).items()
                       if v["category"] in ("malicious", "suspicious")}
            if flagged:
                print()
                print(clr("    Flagging engines:", C.DIM))
                for name, info in list(flagged.items())[:10]:
                    ec = C.RED if info["category"] == "malicious" else C.YELLOW
                    print(f"      {clr('▸', ec)} {name}: {info['result'] or info['category']}")

    # Verdict
    verdict, vc = _overall_verdict(hresult, vt_result)
    print()
    print(f"  {clr('Verdict', C.DIM)}  {clr(verdict, vc, C.BOLD)}")
    print()
    print(sep())


def _overall_verdict(h, vt):
    vt_mal = (vt or {}).get("malicious", 0) if (vt or {}).get("available") else 0
    vt_sus = (vt or {}).get("suspicious", 0) if (vt or {}).get("available") else 0
    if vt_mal > 2 or h.risk_level == "HIGH":
        return "⚠  LIKELY PHISHING — DO NOT VISIT", C.RED
    elif vt_mal > 0 or vt_sus > 0 or h.risk_level == "MEDIUM":
        return "⚡  SUSPICIOUS — Proceed with caution", C.YELLOW
    return "✔  Appears Clean", C.GREEN


# ─────────────────────────────────────────────────────────────────────────────
#  View 2 — Heuristic deep-inspect
# ─────────────────────────────────────────────────────────────────────────────

ALL_CHECKS = [
    ("IP address used instead of domain",          25),
    ("Punycode/IDN hostname",                      30),
    ("Brand impersonated in subdomain/path",        20),
    ("@ symbol (host obfuscation)",                25),
    ("URL shortener detected",                     20),
    ("Double-slash redirect pattern",              20),
    ("Suspicious TLD",                             15),
    ("High entropy domain label",                  15),
    ("Excessive subdomain depth",                  15),
    ("Long hostname",                              10),
    ("Excessive hyphens in hostname",              10),
    ("Non-HTTPS connection",                       10),
    ("Suspicious keywords in path/query",          10),
    ("Long numeric sequence in hostname",          10),
]

def view_heuristics(_vt):
    clear()
    print_banner()
    header("2  ·  Heuristic Deep-Inspect  (14 checks)")
    print()
    url = input(clr("  Enter URL to inspect: ", C.WHITE)).strip()
    if not url:
        print(clr("  No URL entered.", C.DIM))
        pause()
        return

    result = analyze_url(url)
    flag_reasons = [r.lower() for r, _ in result.flags]

    print()
    print(sep())
    print(clr("  14-point heuristic inspection", C.CYAN, C.BOLD))
    print(sep())
    print()

    for i, (check_name, max_pts) in enumerate(ALL_CHECKS, 1):
        # Find if this check fired by matching key words
        key = check_name.lower().split("(")[0].strip().split()[:4]
        hit = next((f for f, _ in result.flags
                    if all(k in f.lower() for k in key[:2])), None)
        num  = clr(f"  {i:02d}", C.DIM)
        if hit:
            icon  = clr("✗", C.RED)
            name  = clr(check_name, C.RED)
            pts   = clr(f"+{max_pts}", C.RED)
            extra = f"\n       {clr('↳ ' + hit, C.DIM)}" if hit != check_name else ""
        else:
            icon  = clr("✓", C.GREEN)
            name  = clr(check_name, C.DIM)
            pts   = clr(f"+{max_pts}", C.DIM)
            extra = ""
        print(f"{num}  {icon}  {name}  {pts}{extra}")

    print()
    print(sep())
    rc = risk_colour(result.risk_level)
    print(f"  Score   {clr(result.score, rc, C.BOLD)}/100  {score_bar(result.score)}  "
          f"{clr(result.risk_level, rc, C.BOLD)}")
    print(sep())
    pause()


# ─────────────────────────────────────────────────────────────────────────────
#  View 3 — Batch scan
# ─────────────────────────────────────────────────────────────────────────────

def view_batch(vt_scanner):
    clear()
    print_banner()
    header("3  ·  Batch Scan")
    print()
    print(f"  {clr('a', C.YELLOW)}  Load from file")
    print(f"  {clr('b', C.YELLOW)}  Paste URLs manually")
    print()
    choice = input(clr("  Choose [a/b]: ", C.DIM)).strip().lower()

    urls = []
    if choice == "a":
        path = input(clr("  File path: ", C.WHITE)).strip()
        try:
            with open(path, encoding="utf-8") as fh:
                urls = [ln.strip() for ln in fh
                        if ln.strip() and not ln.startswith("#")]
        except FileNotFoundError:
            print(clr(f"  [ERROR] File not found: {path}", C.RED))
            pause()
            return
    else:
        print(clr("  Paste URLs (one per line). Type 'done' on a new line when finished:", C.DIM))
        while True:
            line = input("  ").strip()
            if line.lower() == "done":
                break
            if line:
                urls.append(line)

    if not urls:
        print(clr("  No URLs to scan.", C.DIM))
        pause()
        return

    print()
    print(clr(f"  Scanning {len(urls)} URLs...", C.DIM))
    print(sep())

    results = []
    for i, url in enumerate(urls, 1):
        print(clr(f"  [{i}/{len(urls)}] ", C.DIM) + url[:55])
        hres = analyze_url(url)
        vt   = vt_scanner.scan(url) if vt_scanner else None
        results.append({"url": url, "h": hres, "vt": vt})
        scan_history.append({
            "ts":      datetime.now().strftime("%H:%M:%S"),
            "url":     url,
            "score":   hres.score,
            "risk":    hres.risk_level,
            "flags":   len(hres.flags),
            "vt_hits": (vt or {}).get("malicious", 0),
        })

    # Summary table
    print()
    print(sep("═"))
    print(clr("  BATCH SUMMARY", C.CYAN, C.BOLD))
    print(sep("═"))
    icons = {"HIGH": clr("●", C.RED), "MEDIUM": clr("●", C.YELLOW), "LOW": clr("●", C.GREEN)}
    for r in results:
        ic   = icons[r["h"].risk_level]
        scr  = str(r["h"].score).rjust(3)
        vhit = r["vt"].get("malicious", 0) if (r["vt"] or {}).get("available") else "-"
        url_t = r["url"][:44]
        print(f"  {ic}  score={clr(scr, C.WHITE)}  vt={vhit}  {clr(url_t, C.DIM)}")

    high   = sum(1 for r in results if r["h"].risk_level == "HIGH")
    medium = sum(1 for r in results if r["h"].risk_level == "MEDIUM")
    low    = len(results) - high - medium
    print()
    print(f"  {clr('HIGH:', C.RED)} {high}   {clr('MEDIUM:', C.YELLOW)} {medium}   {clr('LOW:', C.GREEN)} {low}")
    print(sep("═"))

    save = input(clr("\n  Save JSON reports for all? [y/N]: ", C.DIM)).strip().lower()
    if save == "y":
        for r in results:
            p = save_report(r["url"], r["h"], r["vt"])
            print(clr(f"  ✔ {p}", C.GREEN))
    pause()


# ─────────────────────────────────────────────────────────────────────────────
#  View 4 — Scan history
# ─────────────────────────────────────────────────────────────────────────────

def view_history(_vt):
    clear()
    print_banner()
    header("4  ·  Scan History  (this session)")
    print()
    if not scan_history:
        print(clr("  No scans yet in this session.", C.DIM))
        pause()
        return

    icons = {"HIGH": clr("[HIGH  ]", C.RED), "MEDIUM": clr("[MEDIUM]", C.YELLOW), "LOW": clr("[LOW   ]", C.GREEN)}
    for i, r in enumerate(reversed(scan_history), 1):
        ic  = icons[r["risk"]]
        url = r["url"][:42]
        print(f"  {clr(str(i).rjust(3), C.DIM)}  {r['ts']}  {ic}  score={str(r['score']).rjust(3)}  "
              f"flags={r['flags']}  vt={r['vt_hits']}  {clr(url, C.DIM)}")
    print()
    print(clr(f"  Total: {len(scan_history)} scan(s)", C.DIM))
    pause()


# ─────────────────────────────────────────────────────────────────────────────
#  View 5 — Set VT key
# ─────────────────────────────────────────────────────────────────────────────

def view_set_vt_key(current_key):
    clear()
    print_banner()
    header("5  ·  VirusTotal API Key")
    print()
    print(clr("  Get a free key at: https://virustotal.com (Profile → API Key)", C.DIM))
    print(clr("  Free tier: 4 requests/min, 500/day", C.DIM))
    print()
    if current_key:
        masked = current_key[:6] + "..." + current_key[-4:]
        print(f"  Current key: {clr(masked, C.GREEN)}")
    else:
        print(clr("  No key set.", C.DIM))
    print()
    new_key = input(clr("  Paste new API key (Enter to keep current): ", C.WHITE)).strip()
    return new_key if new_key else current_key


# ─────────────────────────────────────────────────────────────────────────────
#  View 6 — Help
# ─────────────────────────────────────────────────────────────────────────────

def view_help(_vt):
    clear()
    print_banner()
    header("6  ·  Help & Usage Guide")
    print()
    sections = [
        ("MENU OVERVIEW", [
            "1  Scan URL     — single URL, heuristics + optional VT scan",
            "2  Deep-inspect — all 14 checks shown pass/fail individually",
            "3  Batch scan   — scan a file or pasted list of URLs",
            "4  History      — view all scans in this session",
            "5  VT API key   — set your VirusTotal key for AV engine results",
            "6  Help         — this screen",
        ]),
        ("HEURISTIC CHECKS (14)", [
            "+25  IP address used instead of domain",
            "+30  Punycode/IDN hostname (homograph attack)",
            "+25  @ symbol for host obfuscation",
            "+20  Brand keyword in subdomain/path (paypal, amazon…)",
            "+20  URL shortener (bit.ly, tinyurl…)",
            "+20  Double-slash redirect pattern",
            "+15  Suspicious TLD (.tk .ml .xyz .top…)",
            "+15  High Shannon entropy domain label",
            "+15  Excessive subdomain depth (4+ levels)",
            "+10  Long hostname (>30 chars)",
            "+10  Excessive hyphens (≥3)",
            "+10  Non-HTTPS (plain HTTP)",
            "+10  Suspicious path keywords (login, verify, password…)",
            "+10  Numeric obfuscation in hostname",
        ]),
        ("RISK LEVELS", [
            "LOW     (0–39)   Likely clean",
            "MEDIUM  (40–69)  Suspicious — investigate further",
            "HIGH    (70–100) Likely phishing — do not visit",
        ]),
        ("CLI EQUIVALENT", [
            "python3 scanner.py -u <url>",
            "python3 scanner.py -u <url> --vt-key YOUR_KEY",
            "python3 scanner.py -f urls.txt --save",
            "python3 scanner.py -f urls.txt --vt-key KEY --engines",
            "python3 -m pytest tests/ -v",
        ]),
        ("REPORTS", [
            "Reports are saved as JSON to the reports/ folder.",
            "Each file contains: URL, verdict, score, flags, VT results.",
        ]),
    ]
    for title, lines in sections:
        print(f"  {clr(title, C.CYAN, C.BOLD)}")
        for line in lines:
            print(f"    {clr(line, C.DIM)}")
        print()
    pause()


# ─────────────────────────────────────────────────────────────────────────────
#  Main loop
# ─────────────────────────────────────────────────────────────────────────────

VIEWS = {
    "1": view_scan_url,
    "2": view_heuristics,
    "3": view_batch,
    "4": view_history,
    "6": view_help,
}

def main():
    vt_key = os.getenv("VT_API_KEY", "")
    vt_scanner = VirusTotalScanner(vt_key) if vt_key else None

    while True:
        clear()
        print_banner()
        choice = main_menu(vt_key)

        if choice == "0":
            clear()
            print(clr("\n  Goodbye.\n", C.DIM))
            break
        elif choice in VIEWS:
            VIEWS[choice](vt_scanner)
        elif choice == "5":
            vt_key = view_set_vt_key(vt_key)
            vt_scanner = VirusTotalScanner(vt_key) if vt_key else None
            status = clr("API key saved ✔", C.GREEN) if vt_key else clr("Key cleared.", C.DIM)
            print(f"\n  {status}")
            time.sleep(1)
        else:
            print(clr("\n  Invalid choice. Enter 0–6.", C.RED))
            time.sleep(0.8)


if __name__ == "__main__":
    main()

"""
report.py - Report Generation for Phishing Link Scanner
Outputs scan results as formatted terminal output and JSON files.
"""

import json
import os
from datetime import datetime
from typing import Optional

from heuristics import HeuristicResult


# ── ANSI colour helpers ──────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def _risk_colour(level: str) -> str:
    return {
        "HIGH":   C.RED,
        "MEDIUM": C.YELLOW,
        "LOW":    C.GREEN,
    }.get(level, C.RESET)


# ── Terminal output ──────────────────────────────────────────────────────────

def print_banner() -> None:
    banner = f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════╗
║          PHISHING LINK SCANNER v1.0              ║
║       Cybersecurity Portfolio Project            ║
╚══════════════════════════════════════════════════╝{C.RESET}
"""
    print(banner)


def print_result(
    url: str,
    heuristic: HeuristicResult,
    vt: Optional[dict] = None,
    show_engines: bool = False,
) -> None:
    """Pretty-print a full scan result to the terminal."""

    rc = _risk_colour(heuristic.risk_level)
    sep = f"{C.DIM}{'─' * 52}{C.RESET}"

    print(f"\n{sep}")
    print(f"{C.BOLD}URL:{C.RESET} {url}")
    print(sep)

    # ── Heuristic block ──────────────────────────────────────────────────────
    print(f"\n{C.BOLD}[HEURISTIC ANALYSIS]{C.RESET}")
    print(f"  Risk Level : {rc}{C.BOLD}{heuristic.risk_level}{C.RESET}")
    print(f"  Score      : {rc}{heuristic.score}/100{C.RESET}")

    if heuristic.flags:
        print(f"\n  {C.BOLD}Flags detected:{C.RESET}")
        for reason, pts in heuristic.flags:
            print(f"    {C.YELLOW}▸{C.RESET} {reason}  {C.DIM}(+{pts}){C.RESET}")
    else:
        print(f"  {C.GREEN}No suspicious patterns found.{C.RESET}")

    # ── VirusTotal block ─────────────────────────────────────────────────────
    print(f"\n{C.BOLD}[VIRUSTOTAL SCAN]{C.RESET}")
    if not vt or not vt.get("available"):
        reason = (vt or {}).get("reason", "Not requested")
        print(f"  {C.DIM}Unavailable — {reason}{C.RESET}")
    else:
        mal  = vt["malicious"]
        sus  = vt["suspicious"]
        tot  = vt["total_engines"]
        link = vt["permalink"]

        mal_colour = C.RED if mal > 0 else (C.YELLOW if sus > 0 else C.GREEN)
        print(f"  Malicious  : {mal_colour}{C.BOLD}{mal}{C.RESET} / {tot} engines")
        print(f"  Suspicious : {C.YELLOW}{sus}{C.RESET} / {tot} engines")
        print(f"  Harmless   : {C.GREEN}{vt['harmless']}{C.RESET}")
        print(f"  Report     : {C.CYAN}{link}{C.RESET}")

        if show_engines and vt.get("engines"):
            flagged = {
                name: info for name, info in vt["engines"].items()
                if info["category"] in ("malicious", "suspicious")
            }
            if flagged:
                print(f"\n  {C.BOLD}Flagging engines:{C.RESET}")
                for name, info in list(flagged.items())[:10]:
                    cat_c = C.RED if info["category"] == "malicious" else C.YELLOW
                    print(f"    {cat_c}▸{C.RESET} {name}: {info['result'] or info['category']}")

    # ── Overall verdict ──────────────────────────────────────────────────────
    verdict, vc = _overall_verdict(heuristic, vt)
    print(f"\n  {C.BOLD}Overall Verdict:{C.RESET} {vc}{C.BOLD}{verdict}{C.RESET}")
    print(f"\n{sep}\n")


def _overall_verdict(h: HeuristicResult, vt: Optional[dict]) -> tuple[str, str]:
    vt_mal = (vt or {}).get("malicious", 0) if (vt or {}).get("available") else 0
    vt_sus = (vt or {}).get("suspicious", 0) if (vt or {}).get("available") else 0

    if vt_mal > 2 or h.risk_level == "HIGH":
        return "⚠  LIKELY PHISHING — DO NOT VISIT", C.RED
    elif vt_mal > 0 or vt_sus > 0 or h.risk_level == "MEDIUM":
        return "⚡  SUSPICIOUS — Proceed with caution", C.YELLOW
    else:
        return "✔  Appears Clean", C.GREEN


# ── JSON report export ───────────────────────────────────────────────────────

def save_report(
    url: str,
    heuristic: HeuristicResult,
    vt: Optional[dict],
    output_dir: str = "reports",
) -> str:
    """Serialise results to a JSON file and return the file path."""
    os.makedirs(output_dir, exist_ok=True)

    safe_name = "".join(c if c.isalnum() else "_" for c in url)[:60]
    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename   = f"{output_dir}/{timestamp}_{safe_name}.json"

    verdict, _ = _overall_verdict(heuristic, vt)

    report = {
        "timestamp": datetime.now().isoformat(),
        "url": url,
        "verdict": verdict.strip(),
        "heuristic": {
            "score":      heuristic.score,
            "risk_level": heuristic.risk_level,
            "flags": [
                {"reason": r, "points": p} for r, p in heuristic.flags
            ],
        },
        "virustotal": vt if vt else {"available": False},
    }

    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    return filename

# 🔍 Phishing Link Scanner

A command-line phishing URL detection tool built for **Kali Linux**, combining multi-factor heuristic analysis with optional **VirusTotal API** integration.

Built as a cybersecurity portfolio project — demonstrates URL threat analysis, API integration, and Python security tooling.

---

## Features

| Feature | Description |
|---|---|
| 🧠 Heuristic Engine | 14 pattern checks — IP abuse, brand spoofing, entropy, punycode, TLD abuse |
| 🦠 VirusTotal Integration | Multi-engine AV scan via VT API v3 |
| 📦 Batch Scanning | Scan a file of URLs in one command |
| 📄 JSON Reports | Auto-save structured reports to `reports/` |
| 🎨 Colour Terminal UI | Risk-level colour output (RED/YELLOW/GREEN) |
| ✅ Unit Tests | 20+ pytest tests covering all heuristic checks |

---

## Project Structure

```
phishing-link-scanner/
├── scanner.py          # Main CLI entry point
├── heuristics.py       # URL heuristic analysis engine
├── virustotal.py       # VirusTotal API v3 integration
├── report.py           # Terminal output + JSON report generator
├── requirements.txt    # Dependencies
├── urls.txt            # Sample URLs for batch testing
├── tests/
│   └── test_heuristics.py   # Unit tests (pytest)
├── reports/            # JSON scan reports (auto-created)
└── logs/               # Reserved for future logging
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/phishing-link-scanner.git
cd phishing-link-scanner

# Install dependencies
pip3 install -r requirements.txt
```

---

## Usage

### Single URL scan (heuristics only — no API key needed)
```bash
python3 scanner.py -u https://paypal-secure.verify.ml/login
```

### Single URL with VirusTotal
```bash
python3 scanner.py -u https://bit.ly/abc123 --vt-key YOUR_VT_API_KEY
```

### Batch scan from file
```bash
python3 scanner.py -f urls.txt --vt-key YOUR_VT_API_KEY --save
```

### Show which AV engines flagged the URL
```bash
python3 scanner.py -u http://evil-login.tk --vt-key YOUR_KEY --engines
```

### Use environment variable for API key
```bash
export VT_API_KEY="your_key_here"
python3 scanner.py -u https://suspicious-site.xyz
```

---

## Getting a VirusTotal API Key (Free)

1. Go to [virustotal.com](https://www.virustotal.com) and create a free account
2. Navigate to your profile → **API Key**
3. Copy the key and pass it with `--vt-key` or set `VT_API_KEY`

> Free tier allows 4 lookups/minute and 500/day — sufficient for learning/portfolio use.

---

## Heuristic Checks

The scanner runs 14 independent checks, each adding points to a 0–100 risk score:

| Check | Points |
|---|---|
| IP address used instead of domain | +25 |
| Punycode / IDN homograph hostname | +30 |
| Brand keyword in subdomain/path | +20 |
| URL shortener detected | +20 |
| @ symbol for host obfuscation | +25 |
| Suspicious TLD (.tk, .ml, .xyz …) | +15 |
| High Shannon entropy domain | +15 |
| Excessive subdomain depth | +15 |
| Long hostname (>30 chars) | +10 |
| Excessive hyphens (≥3) | +10 |
| HTTP not HTTPS | +10 |
| Suspicious keywords in path/query | +10 |
| Numeric obfuscation in hostname | +10 |
| Double-slash redirect pattern | +20 |

**Risk Levels:**
- 🟢 `LOW` — score 0–39
- 🟡 `MEDIUM` — score 40–69
- 🔴 `HIGH` — score 70–100

---

## Running Tests

```bash
python3 -m pytest tests/ -v
```

Expected output: 20+ tests, all passing.

---

## Sample Output

```
╔══════════════════════════════════════════════════╗
║          PHISHING LINK SCANNER v1.0              ║
║       Cybersecurity Portfolio Project            ║
╚══════════════════════════════════════════════════╝

────────────────────────────────────────────────────
URL: http://paypal-secure.verify-account.ml/signin
────────────────────────────────────────────────────

[HEURISTIC ANALYSIS]
  Risk Level : HIGH
  Score      : 75/100

  Flags detected:
    ▸ Brand 'paypal' impersonated in subdomain/path  (+20)
    ▸ Suspicious TLD: .ml                            (+15)
    ▸ Excessive hyphens in hostname (3)              (+10)
    ▸ Non-HTTPS connection (plain HTTP)              (+10)
    ▸ Suspicious keywords in path/query: signin      (+10)
    ▸ High entropy domain label (entropy=3.91)       (+15)

[VIRUSTOTAL SCAN]
  Malicious  : 12 / 89 engines
  Report     : https://virustotal.com/gui/url/...

  Overall Verdict: ⚠  LIKELY PHISHING — DO NOT VISIT
```

---

## Skills Demonstrated

- Python3 — argparse, urllib, dataclasses, re, math
- Security concepts — phishing heuristics, Shannon entropy, IDN attacks
- API integration — VirusTotal v3 REST API
- Software engineering — modular design, unit testing with pytest
- CLI tooling — colour output, batch processing, JSON export

---

## Legal & Ethical Notice

This tool is for **educational and defensive security purposes only**.  
Only scan URLs you have permission to analyse. Do not use this tool to facilitate attacks.

---

## License

MIT — free to use and modify for personal and educational projects.

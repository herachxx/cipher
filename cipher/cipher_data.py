#!/usr/bin/env python3
"""
responsibilities:
    - generate or refresh mock threat-feed data (ticker, articles, CVE summaries)
    - export data as data.js for the front-end
    - (optionally) serve the site locally with live-reload
usage:
    python cipher_data.py generate          # write js/data.js from templates
    python cipher_data.py serve [--port N]  # local dev server (default 8080)
    python cipher_data.py validate          # check data.js structure

(!) no third-party packages needed.
"""

from __future__ import annotations
import argparse
import http.server
import json
import os
import random
import re
import string
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Literal

# project root (one level up from this script if placed in /py)
ROOT = Path(__file__).resolve().parent
JS_DATA_PATH = ROOT / "js" / "data.js"

# seed data pools
TICKER_POOL: list[dict] = [
    {"tag": "[ALERT]",      "tagClass": "tag-alert",  "text": "Critical zero-day in OpenSSH - patch immediately"},
    {"tag": "[CVE]",        "tagClass": "tag-cve",    "text": "CVE-2024-11881 - CVSS 9.8 - Remote Code Execution"},
    {"tag": "[BREACH]",     "tagClass": "tag-breach", "text": "Cloud provider reports unauthorized access to 1.2M records"},
    {"tag": "[TIP]",        "tagClass": "tag-tip",    "text": "Enable MFA on all privileged accounts immediately"},
    {"tag": "[RESEARCH]",   "tagClass": "tag-cve",    "text": "New side-channel attack bypasses hardware encryption"},
    {"tag": "[RANSOMWARE]", "tagClass": "tag-breach", "text": "LockBit variant targeting healthcare sector detected"},
    {"tag": "[TOOL]",       "tagClass": "tag-tool",   "text": "Wireshark 4.2 released with improved protocol dissectors"},
    {"tag": "[ADVISORY]",   "tagClass": "tag-alert",  "text": "CISA adds 3 new vulnerabilities to known exploited list"},
    {"tag": "[PATCH]",      "tagClass": "tag-tip",    "text": "Microsoft Patch Tuesday: 67 fixes, 6 critical RCE"},
]

TOPIC_DATA: list[dict] = [
    {"num": "01", "icon": "🛡️", "title": "Network Defense",
     "desc": "Firewalls, IDS/IPS, segmentation strategies, traffic analysis, and resilient network architectures.",
     "tag": "Defensive"},
    {"num": "02", "icon": "🔴", "title": "Red Team Ops",
     "desc": "Penetration testing, lateral movement, privilege escalation, C2 frameworks, adversary simulation.",
     "tag": "Offensive"},
    {"num": "03", "icon": "🔐", "title": "Cryptography",
     "desc": "Symmetric/asymmetric encryption, PKI, TLS internals, hash functions, weak implementation hunting.",
     "tag": "Foundations"},
    {"num": "04", "icon": "🕵️", "title": "Threat Intelligence",
     "desc": "OSINT, threat actor profiling, IOC analysis, MITRE ATT&CK mapping, structured threat hunting.",
     "tag": "Intelligence"},
    {"num": "05", "icon": "🧩", "title": "Malware Analysis",
     "desc": "Static/dynamic analysis, reverse engineering (Ghidra/IDA), sandboxing, deobfuscation, YARA rules.",
     "tag": "Forensics"},
    {"num": "06", "icon": "☁️", "title": "Cloud Security",
     "desc": "AWS/Azure/GCP misconfigs, IAM privilege escalation, container escape, serverless attack surfaces.",
     "tag": "Cloud"},
]

ARTICLE_DATA: list[dict] = [
    {"id": 1, "featured": True, "category": "critical", "badge": "Critical", "badgeClass": "badge-red",
     "title": "Anatomy of a Supply Chain Attack: How SolarWinds Changed Everything",
     "excerpt": "A deep technical analysis of how nation-state actors compromised a build pipeline and silently infected 18,000 organisations.",
     "body": "Understanding the SUNBURST implant, its C2 communication patterns, and detection gaps that allowed it to operate undetected for nine months.",
     "date": "2024-12-01", "readTime": "18 MIN", "tag": "SUPPLY CHAIN"},
    {"id": 2, "featured": False, "category": "research", "badge": "Research", "badgeClass": "badge-cyan",
     "title": "Bypassing EDR With Direct Syscalls",
     "excerpt": "How attackers evade endpoint detection by calling Windows kernel functions directly, skipping userland hooks.",
     "date": "2024-11-20", "readTime": "9 MIN", "tag": "EVASION"},
    {"id": 3, "featured": False, "category": "tutorial", "badge": "Tutorial", "badgeClass": "badge-green",
     "title": "Building a Home SOC for Under $200",
     "excerpt": "Set up a fully functional security operations centre with open-source tools on commodity hardware.",
     "date": "2024-11-14", "readTime": "12 MIN", "tag": "BLUE TEAM"},
    {"id": 4, "featured": False, "category": "malware", "badge": "Malware", "badgeClass": "badge-red",
     "title": "Dissecting a New Infostealer Targeting Crypto Wallets",
     "excerpt": "Static and dynamic analysis of a novel Python-based stealer with browser injection capabilities.",
     "date": "2024-11-08", "readTime": "14 MIN", "tag": "REVERSE ENG"},
    {"id": 5, "featured": False, "category": "research", "badge": "Guide", "badgeClass": "badge-cyan",
     "title": "OSINT Tradecraft: Tracking Infrastructure Without Getting Burned",
     "excerpt": "Operational security for threat researchers - how to investigate without leaving fingerprints.",
     "date": "2024-11-01", "readTime": "10 MIN", "tag": "OSINT"},
]

# dataclass wrappers
@dataclass
class TickerItem:
    tag: str
    tagClass: str
    text: str

@dataclass
class Article:
    id: int
    featured: bool
    category: str
    badge: str
    badgeClass: str
    title: str
    excerpt: str
    date: str
    readTime: str
    tag: str
    body: str = ""

def generate_data_js(output_path: Path = JS_DATA_PATH) -> None:
    """Serialise content data to window.CIPHER_DATA and write data.js."""
    payload = {
        "ticker":  TICKER_POOL,
        "topics":  TOPIC_DATA,
        "articles": ARTICLE_DATA,
        "meta": {
            "generated": date.today().isoformat(),
            "version": "1.0.0",
        },
    }
    js = (
        "/**\n"
        " * data.js - AUTO-GENERATED by cipher_data.py\n"
        f" * Generated: {date.today().isoformat()}\n"
        " * Do not edit manually - run: python cipher_data.py generate\n"
        " */\n\n"
        "window.CIPHER_DATA = "
        + json.dumps(payload, indent=2, ensure_ascii=False)
        + ";\n"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(js, encoding="utf-8")
    print(f"[cipher_data] ✓  Written {output_path.relative_to(ROOT)}")

def validate_data_js(path: Path = JS_DATA_PATH) -> bool:
    """Basic structural validation of data.js."""
    if not path.exists():
        print(f"[cipher_data] ✗  {path} not found - run: python cipher_data.py generate")
        return False
    src = path.read_text(encoding="utf-8")
    match = re.search(r"window\.CIPHER_DATA\s*=\s*(\{.*\});", src, re.DOTALL)
    if not match:
        print("[cipher_data] ✗  Could not parse window.CIPHER_DATA")
        return False
    try:
        data = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        print(f"[cipher_data] ✗  JSON parse error: {exc}")
        return False
    required_keys = {"ticker", "topics", "articles"}
    missing = required_keys - data.keys()
    if missing:
        print(f"[cipher_data] ✗  Missing keys: {missing}")
        return False
    print(f"[cipher_data] ✓  data.js is valid")
    print(f"               ticker:   {len(data['ticker'])} items")
    print(f"               topics:   {len(data['topics'])} items")
    print(f"               articles: {len(data['articles'])} items")
    return True

# dev server
def serve(port: int = 8080) -> None:
    """Simple HTTP dev server rooted at the project directory."""
    os.chdir(ROOT)
    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            print(f"  {self.address_string()} → {fmt % args}")
        def end_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-cache")
            super().end_headers()
    with http.server.HTTPServer(("", port), Handler) as httpd:
        print(f"[cipher_data] Serving at  http://localhost:{port}")
        print(f"               Root:        {ROOT}")
        print(f"               Press Ctrl+C to stop.\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[cipher_data] Server stopped.")

# cli
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cipher_data.py",
        description="CIPHER website data utility",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate", help="Write js/data.js from Python data")
    sub.add_parser("validate", help="Validate existing js/data.js")
    serve_p = sub.add_parser("serve", help="Run local dev server")
    serve_p.add_argument("--port", "-p", type=int, default=8080, help="Port (default 8080)")
    args = parser.parse_args()
    if args.cmd == "generate":
        generate_data_js()
    elif args.cmd == "validate":
        ok = validate_data_js()
        sys.exit(0 if ok else 1)
    elif args.cmd == "serve":
        serve(args.port)
if __name__ == "__main__":
    main()

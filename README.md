# CIPH3R - Cybersecurity Intelligence Platform

> A fully client-side cybersecurity education & IP intelligence platform.  
> No backend. No install. Open `index.html` and go.

---

## What is CIPHER?

CIPHER is an open educational cybersecurity website that combines a curated learning resource with a live, browser-based **IP Toolkit** - a direct port of [`ip_toolkit.py`](ip_toolkit.py) to vanilla JavaScript. Every tool runs inside the browser tab. No servers, no data collection, no setup.

---

## Live Tools - IP Toolkit

The toolkit replicates all five modules from `ip_toolkit.py`:

| Tool | Description | Data Source |
|---|---|---|
| **IP Info** | Geolocation, ISP, ASN, org, coordinates, timezone, proxy/VPN/hosting/mobile flags | [ip-api.com](https://ip-api.com) |
| **WHOIS** | Domain registrar, creation/expiry dates, nameservers, DNSSEC status; IP range & org for IPs | [rdap.org](https://rdap.org) / [rdap.arin.net](https://rdap.arin.net) |
| **Port Scan** | 16 common ports with service name and risk rating (HIGH/MEDIUM/LOW) | [portscan.io](https://portscan.io) API |
| **Reputation** | DNSBL blocklist check across 5 major lists via DNS-over-HTTPS | [dns.google](https://dns.google) DoH |
| **IP Analysis** | Local IPv4 classification, binary/hex/decimal, RFC class, type flags. Also does CIDR subnet calculation | Runs 100% locally - no requests |
| **Run All** | Executes all five tools in sequence against a single target | - |

### Scanned ports & risk levels

| Port | Service | Risk |
|---|---|---|
| 23 | Telnet | 🔴 HIGH |
| 445 | SMB | 🔴 HIGH |
| 3389 | RDP | 🔴 HIGH |
| 6379 | Redis | 🔴 HIGH |
| 27017 | MongoDB | 🔴 HIGH |
| 21 | FTP | 🟡 MEDIUM |
| 25 | SMTP | 🟡 MEDIUM |
| 5900 | VNC | 🟡 MEDIUM |
| 22 | SSH | 🟢 LOW |
| 53 | DNS | 🟢 LOW |
| 80 | HTTP | 🟢 LOW |
| 110 | POP3 | 🟢 LOW |
| 143 | IMAP | 🟢 LOW |
| 443 | HTTPS | 🟢 LOW |
| 3306 | MySQL | 🟢 LOW |
| 8080 | HTTP-Alt | 🟢 LOW |

### DNSBL blocklists checked

- Spamhaus ZEN (`zen.spamhaus.org`)
- SpamCop (`bl.spamcop.net`)
- SORBS (`dnsbl.sorbs.net`)
- Spamhaus XBL (`xbl.spamhaus.org`)
- Barracuda (`b.barracudacentral.org`)

### Browser vs Python differences

| Feature | `ip_toolkit.py` | Browser (CIPHER) |
|---|---|---|
| IP Info | ip-api.com via raw HTTP | ip-api.com via `fetch` |
| WHOIS | Raw socket on port 43 | RDAP REST API (CORS-safe) |
| Port Scan | Raw TCP connect, threaded | portscan.io API + WS fallback |
| Reputation | Raw DNS via `socket.getaddrinfo` | dns.google DNS-over-HTTPS |
| IP Analysis | Own IPv4 logic | Same logic, rewritten in JS |
| Traceroute | `tracert`/`traceroute` subprocess | ❌ Not possible in browsers (requires raw ICMP) |
| Log file | Saves to `ip_log.txt` | Output displayed in terminal pane |

---

## Project Structure

```
cipher/
│
├── index.html                  ← single entry point - open this in any browser
│
├── css/
│   ├── reset.css               ← box-model normalisation, reduced-motion support
│   ├── variables.css           ← all design tokens (colours, spacing, fonts, shadows)
│   ├── layout.css              ← nav, hero, sections, footer, search overlay
│   ├── components.css          ← cards, buttons, terminal, scanner/toolkit UI
│   ├── animations.css          ← all @keyframes in one place
│   └── responsive.css          ← tablet (≤1024px) and mobile (≤768px) breakpoints
│
├── js/
│   ├── data.js                 ← central content store - edit here to update all text/data
│   ├── cursor.js               ← custom cursor with lag-follow ring (desktop only)
│   ├── background.js           ← animated particle field canvas (respects prefers-reduced-motion)
│   ├── ticker.js               ← threat ticker tape (auto-duplicates for seamless loop)
│   ├── terminal.js             ← typewriter terminal animation (triggers on scroll into view)
│   ├── topics.js               ← renders topic cards from data.js
│   ├── articles.js             ← renders article grid + filter tab logic
│   ├── threatmap.js            ← animated threat map canvas with attack beam particles
│   ├── ui.js                   ← search overlay (⌘K), toast notifications, nav scroll, back-to-top
│   ├── scanner.js              ← full IP Toolkit - all 5 tools ported from ip_toolkit.py
│   └── main.js                 ← app entry point, build hash, console branding
│
├── ip_toolkit.py               ← original Python CLI toolkit (see below)
├── cipher_net.cpp              ← c++ companion CLI: IPv4 analysis, CIDR calc, TCP scan
└── README.md                   ← this file
```

---

## Quick Start

### Open in browser - zero setup
```
Double-click index.html
```
That's it. Works in Chrome, Firefox, Edge, Safari - any modern browser.

### Optional: local dev server (avoids CORS on some APIs)
```bash
# Python 3 (built-in, no install needed)
python -m http.server 8080

# Then open:
http://localhost:8080
```

---

## Content - How to Edit

All page content lives in **`js/data.js`** as a single `window.CIPHER_DATA` object. You never need to touch HTML to update content.

### Add a ticker alert
```js
// js/data.js → ticker array
{ tag: '[ALERT]', tagClass: 'tag-alert', text: 'Your message here' },
```
Tag classes: `tag-alert` (amber) · `tag-cve` (cyan) · `tag-breach` (red) · `tag-tip` (green) · `tag-tool` (grey)

### Add a topic card
```js
// js/data.js → topics array
{
  num: '07', icon: '🦠',
  title: 'Incident Response',
  desc: 'Detection, containment, eradication, and recovery playbooks for modern incidents.',
  tag: 'Blue Team',
},
```

### Add an article
```js
// js/data.js → articles array
{
  id: 6,
  featured: false,
  category: 'tutorial',       // 'critical' | 'research' | 'tutorial' | 'malware'
  badge: 'Tutorial',
  badgeClass: 'badge-green',  // 'badge-red' | 'badge-cyan' | 'badge-green' | 'badge-amber'
  title: 'Your Article Title',
  excerpt: 'Short summary shown in the grid.',
  date: '2025-01-15',
  readTime: '8 MIN',
  tag: 'FORENSICS',
},
```

### Add a search result
```js
// js/data.js → searchIndex array
{ title: 'Incident Response', tag: 'TOPIC', href: '#topics' },
```

---

## Features

### Website
- **Custom cursor** - dot + lag-follow ring, colour-shifts on hover
- **Particle background** - animated node/edge canvas, auto-disabled with `prefers-reduced-motion`
- **Threat ticker** - scrolling live-feed bar, pauses on hover
- **Hero section** - staggered entry animations, large typographic layout
- **Typewriter terminal** - nmap-style demo, types itself when scrolled into view, copy button
- **Topic cards** - 6 learning paths, hover reveals left border + tag colour
- **Article grid** - featured + regular layout, filter tabs (All / Critical / Research / Tutorial / Malware)
- **Threat map** - canvas animation with attack beam particles + animated stat counters
- **Newsletter form** - email validation, success/error states, toast feedback
- **Search overlay** - `⌘K` / `Ctrl+K`, keyboard navigation (`↑↓` + `Enter`), live results
- **Scroll reveal** - IntersectionObserver-based, staggered per section
- **Active nav links** - highlights current section as you scroll
- **Back to top** - appears after 600px scroll, smooth scroll
- **Mobile nav** - hamburger menu with animated open/close
- **Toast notifications** - non-blocking feedback for all actions
- **Fully accessible** - ARIA roles, `aria-live`, keyboard nav, `focus-visible`

### IP Toolkit
- Single target input - accepts both IPs and domain names
- **Detect My IP** - one click, fetches public IP and pre-fills the input
- Real-time terminal output - results stream into the terminal pane as they arrive
- All tools share one output pane - scroll back to compare results
- **Run All** - chains all 5 tools in sequence

---

## Original Python Toolkit (`ip_toolkit.py`)

The Python version is fully functional and independent. It requires no external packages - only Python's standard library + `socket`.

### Run
```bash
python ip_toolkit.py                        # Interactive menu
python ip_toolkit.py info       8.8.8.8
python ip_toolkit.py whois      google.com
python ip_toolkit.py scan       192.168.1.1
python ip_toolkit.py reputation 185.220.101.1
python ip_toolkit.py traceroute google.com
python ip_toolkit.py all        google.com  # runs all + saves ip_log.txt
```

### Saved logs
When using `all`, results are appended to `ip_log.txt` in the current directory:
```
=======================================================
  [2024-12-01 14:32]  TARGET: google.com
=======================================================
  >> IP INFO
  ────────────────────────────────────────
     IP Address     : 142.250.185.46
     Country        : United States
     ...
```

---

## C++ Companion CLI (`cipher_net.cpp`)

A standalone command-line network analyser. Cross-platform (Windows + Linux/macOS).

### Build
```bash
# Windows (MinGW / g++)
g++ -std=c++17 -O2 -Wall -o cipher_net cipher_net.cpp -lws2_32

# Linux / macOS
g++ -std=c++17 -O2 -Wall -o cipher_net cipher_net.cpp
```

### Usage
```bash
./cipher_net ip   8.8.8.8             # IPv4 analysis
./cipher_net ip   192.168.1.1         # Private IP flags
./cipher_net cidr 10.0.0.0/8          # Subnet calculator
./cipher_net cidr 192.168.1.0/24
./cipher_net scan localhost 1 1024    # TCP port scan (max 1024 ports/run)
./cipher_net scan 192.168.1.1 20 443
```

> ⚠ Only use the port scanner on hosts you own or have explicit written permission to test.

---

## APIs Used

| API | Purpose | Free? | Rate limit |
|---|---|---|---|
| [ip-api.com](https://ip-api.com) | IP geolocation & flags | ✅ Free | 45 req/min |
| [rdap.org](https://rdap.org) | Domain WHOIS (RDAP) | ✅ Free | Reasonable use |
| [rdap.arin.net](https://rdap.arin.net) | IP WHOIS (ARIN RDAP) | ✅ Free | Reasonable use |
| [portscan.io](https://portscan.io) | TCP port scanning | ✅ Free | Reasonable use |
| [dns.google](https://dns.google) | DNS-over-HTTPS for DNSBL | ✅ Free | Very generous |
| [api.ipify.org](https://api.ipify.org) | Public IP detection | ✅ Free | Unlimited |

All APIs are public, CORS-enabled, and privacy-respecting. No API keys required.

---

## Browser Support

| Browser | Version | Status |
|---|---|---|
| Chrome / Chromium | 90+ | ✅ Full support |
| Firefox | 88+ | ✅ Full support |
| Edge | 90+ | ✅ Full support |
| Safari | 14+ | ✅ Full support |
| Mobile Chrome | Any modern | ✅ Responsive |
| Mobile Safari | Any modern | ✅ Responsive |

No build tools. No npm. No bundler. No framework. Pure HTML + CSS + JS.

---

## Design System

| Token | Value |
|---|---|
| Background | `#030508` |
| Surface | `#080d14` |
| Accent (Cyan) | `#00e5ff` |
| Accent (Red) | `#ff2d55` |
| Accent (Green) | `#39ff14` |
| Accent (Amber) | `#ffbe00` |
| Display font | Bebas Neue |
| Mono font | Share Tech Mono |
| Body font | DM Sans |

All tokens live in `css/variables.css` - change one line to retheme the whole site.

---

## Disclaimer

This project is for **educational purposes only**.

- The IP Toolkit is designed to help learners understand how network analysis tools work
- Only use the port scanner and network tools on systems you own or have explicit permission to test
- All threat data shown on the website is simulated
- The authors are not responsible for any misuse of these tools

---

## License

See `LICENSE` in the original `ip_toolkit` repository.

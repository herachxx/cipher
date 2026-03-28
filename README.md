<div align="center">

**Cybersecurity Intelligence Platform**  
*Open the browser. Start hacking - legally.*  

</div>

```
     ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗
    ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗
    ██║     ██║██████╔╝███████║█████╗  ██████╔╝
    ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗
    ╚██████╗██║██║     ██║  ██║███████╗██║  ██║
     ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
```

---

<div align="center">
 
![HTML](https://img.shields.io/badge/HTML5-pure-00e5ff?style=flat-square&logo=html5&logoColor=00e5ff&labelColor=030508)
![CSS](https://img.shields.io/badge/CSS3-modular-00e5ff?style=flat-square&logo=css3&logoColor=00e5ff&labelColor=030508)
![JavaScript](https://img.shields.io/badge/JavaScript-vanilla-00e5ff?style=flat-square&logo=javascript&logoColor=00e5ff&labelColor=030508)
![Python](https://img.shields.io/badge/Python-3.9+-00e5ff?style=flat-square&logo=python&logoColor=00e5ff&labelColor=030508)
![C++](https://img.shields.io/badge/C++-17-00e5ff?style=flat-square&logo=cplusplus&logoColor=00e5ff&labelColor=030508)
![License](https://img.shields.io/badge/License-MIT-39ff14?style=flat-square&labelColor=030508)
![No Backend](https://img.shields.io/badge/Backend-none-ff2d55?style=flat-square&labelColor=030508)
![No npm](https://img.shields.io/badge/npm-never-ff2d55?style=flat-square&labelColor=030508)

</div>

---

## What is CIPHER?

CIPHER is a **client-side cybersecurity education platform** - part learning hub, part live intelligence toolkit. It runs entirely in your browser tab. There's no server, no database, no install, no `npm install`. Just open `index.html`.  

At its core is the **IP Toolkit** - a full port of [`ip_toolkit.py`](ip_toolkit.py) in JavaScript. Every tool that ran in your terminal now runs in a slick terminal-style UI inside the browser, hitting real APIs in real time.  

```
┌─────────────────────────────────────────────────────┐
│  cipher3r@toolkit:~$ ip info 8.8.8.8                │
│                                                     │
│  ┌─ IP INFO ───────────────────────────────────┐    │
│  │  IP Address    8.8.8.8                      │    │
│  │  Country       United States                │    │
│  │  ISP           Google LLC                   │    │
│  │  ASN           AS15169 Google LLC           │    │
│  │  Proxy/VPN     NO                           │    │
│  │  Hosting       YES                          │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
# Option 1 - just open the file
open index.html

# Option 2 - local server (recommended, fixes CORS on some APIs)
python -m http.server 8080
# → http://localhost:8080
```

That's the entire setup. No package managers. No compilers. No configuration files.

---

## IP Toolkit - 8 Live Tools

> All tools accept an IP address **or** a domain name as input.
> Results stream into the terminal pane in real time.

```
┌──────────────────┬──────────────────────────────────────────────┬──────────────────────────────┐
│ Tool             │ What it does                                 │ Data source                  │
├──────────────────┼──────────────────────────────────────────────┼──────────────────────────────┤
│ IP Info          │ Geolocation · ISP · ASN · org · timezone     │ ip-api.com                   │
│                  │ proxy/VPN · hosting · mobile flags           │                              │
├──────────────────┼──────────────────────────────────────────────┼──────────────────────────────┤
│ WHOIS            │ Registrar · created/expiry dates             │ rdap.org / rdap.arin.net     │
│                  │ nameservers · DNSSEC · IP range & org        │                              │
├──────────────────┼──────────────────────────────────────────────┼──────────────────────────────┤
│ Port Scan        │ 16 common ports · service names              │ portscan.io API              │
│                  │ risk rating (HIGH / MEDIUM / LOW)            │                              │
├──────────────────┼──────────────────────────────────────────────┼──────────────────────────────┤
│ Reputation       │ DNSBL check across 5 major blocklists        │ dns.google (DoH)             │
├──────────────────┼──────────────────────────────────────────────┼──────────────────────────────┤
│ DNS Lookup       │ A · AAAA · MX · NS · TXT · CNAME records     │ dns.google (DoH)             │
├──────────────────┼──────────────────────────────────────────────┼──────────────────────────────┤
│ SSL Check        │ Issuer · expiry · days remaining · SANs      │ crt.sh (CT logs)             │
├──────────────────┼──────────────────────────────────────────────┼──────────────────────────────┤
│ Ping             │ HTTP round-trip latency · 5 probes           │ Direct (no-cors fetch)       │
│                  │ live bar chart · min/avg/max RTT             │                              │
├──────────────────┼──────────────────────────────────────────────┼──────────────────────────────┤
│ IP Analysis      │ Binary · hex · decimal · RFC class           │ 100% local, zero requests    │
│                  │ type flags · CIDR subnet calculator          │                              │
├──────────────────┼──────────────────────────────────────────────┼──────────────────────────────┤
│ Run All          │ Chains all 8 tools in sequence               │ —                            │
└──────────────────┴──────────────────────────────────────────────┴──────────────────────────────┘
```

### Port risk classification

| Risk | Ports |
|---|---|
| `HIGH` | 23 Telnet · 445 SMB · 3389 RDP · 6379 Redis · 27017 MongoDB |
| `MEDIUM` | 21 FTP · 25 SMTP · 5900 VNC |
| `LOW` | 22 SSH · 53 DNS · 80 HTTP · 110 POP3 · 143 IMAP · 443 HTTPS · 3306 MySQL · 8080 HTTP-Alt |

### DNSBL blocklists checked

```
zen.spamhaus.org  ·  bl.spamcop.net  ·  dnsbl.sorbs.net  ·  xbl.spamhaus.org  ·  b.barracudacentral.org
```

---

## Browser vs Python — What Changed

The original `ip_toolkit.py` used raw sockets and OS subprocesses. Browsers don't allow those. Here's how each tool was adapted:

| Tool | Python original | Browser adaptation |
|---|---|---|
| IP Info | Raw HTTP to ip-api.com | `fetch()` to ip-api.com |
| WHOIS | Raw socket on port 43 | RDAP REST API (CORS-safe) |
| Port Scan | Raw TCP connect, threaded | portscan.io API + WebSocket fallback |
| Reputation | `socket.getaddrinfo()` DNS | dns.google DNS-over-HTTPS |
| IP Analysis | Custom IPv4 logic | Same logic, rewritten in JS |
| DNS Lookup | - | dns.google DoH (new tool) |
| SSL Check | - | crt.sh CT log API (new tool) |
| Ping | - | HTTP RTT measurement (new tool) |
| Traceroute | `tracert` / `traceroute` subprocess | **Not possible** - requires raw ICMP |
| Log file | Saves to `ip_log.txt` | Displayed in terminal pane |

---

## Project Structure

```
cipher/
│
├── index.html                   ← the whole site. open this.
│
├── css/
│   ├── reset.css                ← box-model normalisation + reduced-motion
│   ├── variables.css            ← design tokens: colours, spacing, fonts
│   │                              light/dark theme via [data-theme] attribute
│   ├── layout.css               ← nav · hero · sections · footer · search overlay
│   ├── components.css           ← cards · buttons · terminal · scanner UI · icons
│   ├── animations.css           ← all @keyframes in one place
│   └── responsive.css           ← tablet (≤1024px) · mobile (≤768px)
│
├── js/
│   ├── icons.js                 ← SVG icon library - CIPHER_ICONS.get('shield', 20)
│   ├── data.js                  ← central content store - edit here, never touch HTML
│   ├── cursor.js                ← custom dot cursor + lag-follow ring (desktop)
│   ├── background.js            ← particle field canvas (respects prefers-reduced-motion)
│   ├── ticker.js                ← live threat ticker tape - pauses on hover
│   ├── terminal.js              ← typewriter terminal - triggers on scroll into view
│   ├── topics.js                ← renders topic cards from data.js
│   ├── articles.js              ← article grid + filter tabs
│   ├── threatmap.js             ← canvas threat map with animated attack beams
│   ├── ui.js                    ← search (⌘K) · toasts · nav scroll · theme toggle
│   ├── email.js                 ← newsletter via EmailJS — configure 4 constants
│   ├── scanner.js               ← IP toolkit: all 8 tools, terminal output engine
│   └── main.js                  ← entry point · icon hydration · build hash
│
├── ip_toolkit.py                ← original python CLI (zero dependencies)
├── cipher_net.cpp               ← C++ CLI: IPv4 analysis · CIDR · TCP scan
└── README.md
```

**Total:** ~3,800 lines across 25 files with no dependencies.

---

## Website Features

### Visual & UX
- **Custom cursor** - dual-layer dot + lag-follow ring, morphs on hover
- **Particle field** - animated node/edge canvas, auto-disables with `prefers-reduced-motion`
- **Dark / light theme** - toggle in nav bar, remembers preference, respects OS default
- **Scroll reveal** - intersectionObserver with per-section stagger
- **Animated hero** - staggered typeface entry, large typographic layout
- **Live threat ticker** - scrolling feed, pauses on hover

### Content
- **6 topic cards** - learning paths with real external links (TryHackMe, CryptoHack, MITRE ATT&CK...)
- **9 curated articles** - filter by Critical / Research / Tutorial / Malware
- **Typewriter terminal** - nmap-style scan demo, copy-to-clipboard
- **Threat map** - canvas animation with attack beam particles, animated counters

### Navigation & Interaction
- **Search overlay** - `⌘K` / `Ctrl+K`, keyboard navigation `↑↓ Enter`, live results
- **Active nav links** - highlights current section while scrolling
- **Mobile hamburger nav** - animated open/close
- **Back to top** - appears after 600px, smooth scroll
- **Toast notifications** - non-blocking, typed (success / error / info)

### Accessibility
- Semantic HTML5 with ARIA roles throughout
- `aria-live` regions for dynamic content
- Full keyboard navigation - `focus-visible` outlines
- Reduced-motion: disables particle canvas and heavy animations

---

## Editing Content

Everything the visitor sees lives in **`js/data.js`**. Edit that file - the site updates automatically.

### Add a threat ticker item
```js
// js/data.js → ticker array
{ tag: '[CVE]', tagClass: 'tag-cve', text: 'CVE-2025-XXXX - CVSS 9.1 - critical patch available' },
// tagClass options: tag-alert · tag-cve · tag-breach · tag-tip · tag-tool
```

### Add a topic card
```js
// js/data.js → topics array
{
  num:  '07',
  icon: 'server',             // any key from js/icons.js
  title: 'Incident Response',
  desc:  'Detection, containment, eradication, and recovery playbooks for modern incidents.',
  tag:   'Blue Team',
  href:  'https://www.sans.org/white-papers/incident-handlers-handbook/',
},
```

### Add an article
```js
// js/data.js → articles array
{
  id:        10,
  featured:  false,
  category:  'tutorial',        // critical · research · tutorial · malware
  badge:     'Tutorial',
  badgeClass:'badge-green',     // badge-red · badge-cyan · badge-green · badge-amber
  title:     'Your Article Title',
  excerpt:   'One-sentence hook shown in the grid.',
  date:      '2025-03-01',
  readTime:  '8 MIN',
  tag:       'FORENSICS',
  href:      'https://real-article-url.com',
},
```

---

## Newsletter (EmailJS)

The subscription form sends **real emails** via [EmailJS](https://emailjs.com) - no server needed, free up to 200 emails/month.

Open `js/email.js` and fill in four constants:

```js
const EMAILJS_PUBLIC_KEY       = 'your_public_key';
const EMAILJS_SERVICE_ID       = 'service_xxxxxxx';
const EMAILJS_NOTIFY_TEMPLATE  = 'template_xxxxxxx';  // notifies you of new sub
const EMAILJS_WELCOME_TEMPLATE = 'template_xxxxxxx';  // welcome email to subscriber
```

Full setup walkthrough is in the comment block at the top of `js/email.js`.

---

## Original Python Toolkit

`ip_toolkit.py` is a fully self-contained CLI tool. No pip installs - standard library only.

```bash
python ip_toolkit.py                         # interactive menu

python ip_toolkit.py info       8.8.8.8
python ip_toolkit.py whois      github.com
python ip_toolkit.py scan       192.168.1.1
python ip_toolkit.py reputation 185.220.101.1
python ip_toolkit.py traceroute google.com
python ip_toolkit.py all        google.com   # run everything + save ip_log.txt
```

Running `all` appends a structured report to `ip_log.txt`:

```
=======================================================
  [2025-03-01 14:32]  TARGET: google.com
=======================================================
  >> IP INFO
  ────────────────────────────────────────
     IP Address     : 142.250.185.46
     Country        : United States
     ISP            : Google LLC
     Proxy/VPN      : NO
     ...
```

---

## C++ CLI - `cipher_net.cpp`

A standalone cross-platform network analyser. No external libraries.

### Build

```bash
# Windows  (MinGW / g++)
g++ -std=c++17 -O2 -Wall -o cipher_net cipher_net.cpp -lws2_32

# Linux / macOS
g++ -std=c++17 -O2 -Wall -o cipher_net cipher_net.cpp
```

### Usage

```bash
./cipher_net ip   8.8.8.8                 # classify address, show binary/hex/flags
./cipher_net ip   192.168.1.1             # detect RFC 1918 private range
./cipher_net cidr 10.0.0.0/8             # full subnet breakdown
./cipher_net cidr 192.168.1.0/24         # network · broadcast · first/last host
./cipher_net scan localhost 1 1024        # TCP connect scan - max 1024 ports/run
./cipher_net scan 192.168.1.1 20 443
```

> **Only scan hosts you own or have explicit written permission to test.**

---

## APIs

All free. All public. No API keys required.

| API | Used for | Limit |
|---|---|---|
| [ip-api.com](https://ip-api.com) | IP geolocation + flags | 45 req/min |
| [rdap.org](https://rdap.org) | Domain WHOIS | Fair use |
| [rdap.arin.net](https://rdap.arin.net) | IP WHOIS (ARIN) | Fair use |
| [portscan.io](https://portscan.io) | TCP port scanning | Fair use |
| [dns.google](https://dns.google) | DNS-over-HTTPS · DNSBL | Very generous |
| [crt.sh](https://crt.sh) | SSL certificate transparency | Fair use |
| [api.ipify.org](https://api.ipify.org) | Public IP detection | Unlimited |

---

## Design Tokens

All design decisions live in `css/variables.css`. Change one token - retheme the whole site.

```css
/* Dark theme (default) */
--bg:      #030508;   /* page background      */
--surface: #080d14;   /* card / panel surface  */
--accent:  #00e5ff;   /* primary cyan          */
--accent2: #ff2d55;   /* danger red            */
--accent3: #39ff14;   /* success green         */
--accent4: #ffbe00;   /* warning amber         */

/* Fonts */
--font-display: 'Bebas Neue';       /* headings    */
--font-mono:    'Share Tech Mono';  /* code / UI   */
--font-body:    'DM Sans';          /* body text   */
```

Light theme tokens are declared under `[data-theme="light"]` in the same file.

---

## Browser Support

| Browser | Min version | Notes |
|---|---|---|
| Chrome / Chromium | 90 | Full support |
| Firefox | 88 | Full support |
| Edge | 90 | Full support |
| Safari | 14 | Full support |
| Mobile Chrome | Modern | Responsive, cursor disabled |
| Mobile Safari | Modern | Responsive, cursor disabled |

---

## Disclaimer

This project is for **educational purposes only**.

- Threat feed data is simulated - not a live intelligence source
- The port scanner must only be used on systems you own or have explicit permission to test
- The authors accept no responsibility for misuse of any tool in this repository

---

## License

MIT © 2026 [Aruzhan Maratova (@herachxx)](https://github.com/herachxx)

---

<div align="center">

```
// built for defenders. by someone learning to be one.
```

</div>

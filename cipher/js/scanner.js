/**
 * scanner.js - CIPHER IP Toolkit (browser edition)
 * All 5 tools from ip_toolkit.py, reimplemented in JS.
 * Tools:
 *   1. IP Info - geolocation, ISP, ASN, proxy/VPN/hosting flags (ip-api.com)
 *   2. WHOIS - domain registrar, dates, nameservers (whois.freeaiapi.workers.dev)
 *   3. Port Scan - TCP connect scan on 16 common ports via portscan.io API
 *   4. Reputation - DNSBL blocklist check (5 lists via dns.google DoH)
 *   5. IP Analysis - local IPv4 classify + CIDR calc (no external requests)
 * Notes on browser limitations vs Python original:
 *   - Raw TCP sockets: not available in browsers → port scan uses portscan.io public API
 *   - Raw WHOIS (port 43): blocked by browsers → uses public WHOIS REST API
 *   - DNSBL: raw DNS not available → uses dns.google DNS-over-HTTPS
 *   - Traceroute: requires OS-level ICMP → not possible in browsers, omitted
 */
(function () {
  'use strict';
  const RISK = {
    23:    { level: 'HIGH',   cls: 't-err'  },
    445:   { level: 'HIGH',   cls: 't-err'  },
    3389:  { level: 'HIGH',   cls: 't-err'  },
    6379:  { level: 'HIGH',   cls: 't-err'  },
    27017: { level: 'HIGH',   cls: 't-err'  },
    21:    { level: 'MEDIUM', cls: 't-warn' },
    5900:  { level: 'MEDIUM', cls: 't-warn' },
    25:    { level: 'MEDIUM', cls: 't-warn' },
  };
  const PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
    443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
    5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 27017: 'MongoDB',
  };
  const BLOCKLISTS = [
    { host: 'zen.spamhaus.org',       name: 'Spamhaus ZEN'  },
    { host: 'bl.spamcop.net',         name: 'SpamCop'       },
    { host: 'dnsbl.sorbs.net',        name: 'SORBS'         },
    { host: 'xbl.spamhaus.org',       name: 'Spamhaus XBL'  },
    { host: 'b.barracudacentral.org', name: 'Barracuda'     },
  ];

  // IPv4 local analysis (no network)
  function parseIPv4(str) {
    str = (str || '').trim();
    const parts = str.split('.');
    if (parts.length !== 4) return null;
    const nums = parts.map(Number);
    if (nums.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    return (nums[0] * 16777216 + nums[1] * 65536 + nums[2] * 256 + nums[3]) >>> 0;
  }
  function uint32ToIP(n) {
    n = n >>> 0;
    return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  }
  function toBinaryStr(n) {
    n = n >>> 0;
    let s = '';
    for (let i = 31; i >= 0; i--) {
      s += (n >>> i) & 1;
      if (i > 0 && i % 8 === 0) s += '.';
    }
    return s;
  }
  function classifyIP(n) {
    n = n >>> 0;
    if (n === 0xFFFFFFFF)                             return { label: 'Broadcast',               cls: 't-warn' };
    if ((n >>> 24) === 127)                           return { label: 'Loopback',                cls: 't-ok'   };
    if ((n & 0xFFFF0000) >>> 0 === 0xA9FE0000)       return { label: 'Link-Local (APIPA)',       cls: 't-warn' };
    if ((n & 0xF0000000) >>> 0 === 0xE0000000)       return { label: 'Multicast',               cls: 't-warn' };
    if ((n & 0xFF000000) >>> 0 === 0x0A000000)       return { label: 'Private - 10.x.x.x',      cls: 't-ok'   };
    if ((n & 0xFFF00000) >>> 0 === 0xAC100000)       return { label: 'Private - 172.16-31.x.x', cls: 't-ok'   };
    if ((n & 0xFFFF0000) >>> 0 === 0xC0A80000)       return { label: 'Private - 192.168.x.x',   cls: 't-ok'   };
    if ((n & 0xFFFFFF00) >>> 0 === 0xC0000200 ||
        (n & 0xFFFFFF00) >>> 0 === 0xC6336400 ||
        (n & 0xFFFFFF00) >>> 0 === 0xCB007100)       return { label: 'Documentation/TEST-NET',  cls: 't-comment'};
    return { label: 'Public / Routable', cls: '' };
  }
  function rfcClass(n) {
    const b = (n >>> 24) & 0xFF;
    if (b < 128) return 'A'; if (b < 192) return 'B';
    if (b < 224) return 'C'; if (b < 240) return 'D (Multicast)';
    return 'E (Reserved)';
  }
  function isPrivateIP(n) {
    n = n >>> 0;
    return (n >>> 24) === 127
      || (n & 0xFF000000) >>> 0 === 0x0A000000
      || (n & 0xFFF00000) >>> 0 === 0xAC100000
      || (n & 0xFFFF0000) >>> 0 === 0xC0A80000;
  }
  function parseCIDR(str) {
    str = (str || '').trim();
    const slash = str.indexOf('/');
    if (slash === -1) return null;
    const prefix = parseInt(str.slice(slash + 1), 10);
    if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;
    const base = parseIPv4(str.slice(0, slash));
    if (base === null) return null;
    const mask      = prefix === 0 ? 0 : ((~0 << (32 - prefix)) >>> 0);
    const network   = (base & mask) >>> 0;
    const wildcard  = (~mask) >>> 0;
    const broadcast = (network | wildcard) >>> 0;
    const first     = prefix === 32 ? network : (network + 1) >>> 0;
    const last      = prefix >= 31  ? broadcast : (broadcast - 1) >>> 0;
    const total     = prefix === 32 ? 1 : prefix === 31 ? 2 : Math.pow(2, 32 - prefix) - 2;
    return {
      cidr: uint32ToIP(network) + '/' + prefix,
      network: uint32ToIP(network),
      mask: uint32ToIP(mask),
      wildcard: uint32ToIP(wildcard),
      broadcast: uint32ToIP(broadcast),
      first: uint32ToIP(first),
      last: uint32ToIP(last),
      total: total.toLocaleString(),
      prefix,
      class: rfcClass(network),
      type: classifyIP(network).label,
    };
  }
  // output helpers
  function ln(cls, html) {
    return `<span class="t-line ${cls || ''}">${html}</span>`;
  }
  function kv(key, val, valCls) {
    const pad = '&nbsp;'.repeat(Math.max(1, 20 - key.length));
    return ln('t-out', `<span class="t-comment">${escHtml(key)}</span>${pad}<span class="${valCls || 't-ok'}">${escHtml(String(val))}</span>`);
  }
  function hdr(title) {
    return [
      ln('', ''),
      ln('t-comment', `┌─ ${title} ${'─'.repeat(Math.max(2, 40 - title.length))}┐`),
    ].join('');
  }
  function ftr() {
    return ln('t-comment', `└${'─'.repeat(44)}┘`);
  }
  function promptLine(cmd) {
    return ln('', `<span class="t-prompt">cipher3r</span><span class="t-at">@toolkit</span><span style="color:var(--accent)">:~$</span> <span class="t-cmd">${escHtml(cmd)}</span>`);
  }
  function errLine(msg) {
    return ln('t-err', `[!] ${escHtml(msg)}`);
  }
  function warnLine(msg) {
    return ln('t-warn', `[~] ${escHtml(msg)}`);
  }
  function infoLine(msg) {
    return ln('t-out', escHtml(msg));
  }
  function escHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  // output pane
  const output = document.getElementById('scannerOutput');
  function append(html) {
    if (!output) return;
    output.innerHTML += html;
    output.scrollTop = output.scrollHeight;
  }
  function appendLine(html) { append(html + ln('', '')); }
  function setStatus(msg, cls) {
    const el = document.getElementById('scannerStatus');
    if (!el) return;
    el.textContent = msg;
    el.className = 'scanner-status ' + (cls || '');
  }

  // tool: ip info (ip-api.com)
  async function toolIPInfo(target) {
    append(promptLine(`ip info ${target}`));
    append(hdr('IP INFO'));
    append(warnLine(`Fetching info for ${target}...`));
    setStatus('Fetching IP info...', 'loading');
    try {
      const url = `https://ip-api.com/json/${encodeURIComponent(target)}?fields=status,message,query,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting`;
      const res  = await fetch(url);
      const data = await res.json();
      if (data.status !== 'success') {
        append(errLine(data.message || 'ip-api.com returned an error'));
        append(ftr()); appendLine(''); return;
      }
      append(kv('IP Address',   data.query));
      append(kv('Country',      `${data.country} (${data.countryCode})`));
      append(kv('Region',       data.regionName));
      append(kv('City',         data.city));
      append(kv('ZIP',          data.zip || 'N/A'));
      append(kv('Coordinates',  `${data.lat}, ${data.lon}`));
      append(kv('Timezone',     data.timezone));
      append(kv('ISP',          data.isp));
      append(kv('Organisation', data.org));
      append(kv('ASN',          data.as));
      append(kv('Proxy / VPN',  data.proxy   ? 'YES (!)' : 'NO',  data.proxy   ? 't-err'  : 't-ok'));
      append(kv('Hosting',      data.hosting ? 'YES'     : 'NO',  data.hosting ? 't-warn' : 't-ok'));
      append(kv('Mobile',       data.mobile  ? 'YES'     : 'NO',  data.mobile  ? 't-warn' : 't-ok'));
      append(ftr());
      appendLine('');
      setStatus('Done.', 'ok');
    } catch (e) {
      append(errLine('Request failed: ' + e.message));
      append(ftr()); appendLine('');
      setStatus('Error.', 'err');
    }
  }
  // tool: WHOIS (whois.freeaiapi.workers.dev)
  // falls back to rdap.org for IPs
  async function toolWhois(target) {
    append(promptLine(`whois ${target}`));
    append(hdr('WHOIS'));
    setStatus('Querying WHOIS...', 'loading');
    const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(target.trim());
    try {
      let data;
      if (isIP) {
        const res = await fetch(`https://rdap.arin.net/registry/ip/${encodeURIComponent(target)}`);
        if (!res.ok) throw new Error(`RDAP returned ${res.status}`);
        data = await res.json();
        append(kv('IP',           target));
        append(kv('Name',         data.name        || 'N/A'));
        append(kv('Handle',       data.handle      || 'N/A'));
        append(kv('Country',      data.country     || 'N/A'));
        const start = data.startAddress || 'N/A';
        const end   = data.endAddress   || 'N/A';
        append(kv('Range',        `${start} – ${end}`));
        if (data.entities && data.entities.length) {
          const org = data.entities.find(e => e.roles?.includes('registrant') || e.roles?.includes('administrative'));
          if (org) append(kv('Organisation', org.handle || org.fn || 'N/A'));
        }
        if (data.remarks && data.remarks.length) {
          const desc = data.remarks[0]?.description?.[0];
          if (desc) append(kv('Description', desc));
        }
      } else {
        // RDAP for domains
        const domain = target.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').trim();
        const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
        if (!res.ok) throw new Error(`RDAP returned ${res.status}`);
        data = await res.json();
        const getDate = key => {
          const e = (data.events || []).find(x => x.eventAction === key);
          return e ? e.eventDate.split('T')[0] : 'N/A';
        };
        append(kv('Domain',      data.ldhName                         || domain));
        append(kv('Status',      (data.status || []).join(', ')       || 'N/A'));
        append(kv('Registered',  getDate('registration')));
        append(kv('Updated',     getDate('last changed')));
        append(kv('Expiry',      getDate('expiration')));
        const registrar = (data.entities || []).find(e => e.roles?.includes('registrar'));
        if (registrar) {
          const vcards = registrar.vcardArray?.[1] || [];
          const fn = vcards.find(v => v[0] === 'fn');
          append(kv('Registrar', fn ? fn[3] : registrar.handle || 'N/A'));
        }
        const ns = (data.nameservers || []).map(n => n.ldhName).filter(Boolean);
        if (ns.length) append(kv('Nameservers', ns.slice(0, 4).join(', ')));
        const dnssec = data.secureDNS?.delegationSigned;
        append(kv('DNSSEC', dnssec === true ? 'Signed' : dnssec === false ? 'Unsigned' : 'N/A',
          dnssec ? 't-ok' : 't-warn'));
      }
      append(ftr()); appendLine('');
      setStatus('Done.', 'ok');
    } catch (e) {
      append(errLine('WHOIS failed: ' + e.message));
      append(warnLine('Try a different target or check your connection.'));
      append(ftr()); appendLine('');
      setStatus('Error.', 'err');
    }
  }

  // tool: port scan (portscan.io)
  async function toolPortScan(target) {
    append(promptLine(`port scan ${target}`));
    append(hdr('PORT SCAN'));
    const portList = Object.keys(PORTS).join(',');
    append(warnLine(`Scanning ${target} - ${Object.keys(PORTS).length} common ports...`));
    setStatus('Scanning ports...', 'loading');
    try {
      const res  = await fetch(`https://portscan.io/api/?host=${encodeURIComponent(target)}&ports=${portList}`);
      const data = await res.json();
      if (!data || data.error) {
        throw new Error(data?.error || 'portscan.io returned an error');
      }
      const open = (data.open_ports || []).map(Number).sort((a, b) => a - b);
      if (open.length === 0) {
        append(warnLine('No open ports found in the scanned set.'));
      } else {
        append(ln('t-out', `<span class="t-comment">${'PORT'.padEnd(10)}${'SERVICE'.padEnd(14)}RISK</span>`));
        append(ln('t-out', '-'.repeat(36)));
        open.forEach(port => {
          const service = PORTS[port] || 'unknown';
          const risk    = RISK[port] || { level: 'LOW', cls: 't-ok' };
          append(ln(risk.cls, `${String(port).padEnd(10)}${service.padEnd(14)}${risk.level}`));
        });
      }
      append(ftr()); appendLine('');
      setStatus('Done.', 'ok');
    } catch (e) {
      append(warnLine('portscan.io unreachable - trying fallback method...'));
      await portScanFallback(target);
    }
  }
  async function portScanFallback(target) {
    // WebSocket probing (connects succeed on open HTTP/WS ports, fail fast on closed)
    const probePorts = [80, 443, 8080, 8443];
    const results = [];
    const checks = probePorts.map(port => new Promise(resolve => {
      const ws = new WebSocket(`wss://${target}:${port}`);
      const timer = setTimeout(() => { ws.close(); resolve({ port, open: false }); }, 1200);
      ws.onopen  = () => { clearTimeout(timer); ws.close(); resolve({ port, open: true  }); };
      ws.onerror = () => { clearTimeout(timer);             resolve({ port, open: false }); };
    }));
    const found = await Promise.all(checks);
    const open  = found.filter(r => r.open);
    if (open.length) {
      open.forEach(r => {
        const service = PORTS[r.port] || 'unknown';
        append(ln('t-ok', `${String(r.port).padEnd(10)}${service.padEnd(14)}LOW`));
      });
    } else {
      append(warnLine('Could not determine port status from browser context.'));
      append(ln('t-comment', '# Browsers restrict raw TCP - use the python ip_toolkit.py for full scans.'));
    }
    append(ftr()); appendLine('');
    setStatus('Done (fallback).', 'warn');
  }

  // tool: reputation / DNSBL (dns.google DoH)
  async function toolReputation(target) {
    append(promptLine(`reputation ${target}`));
    append(hdr('REPUTATION CHECK'));

    // resolve target to IP first if it's a domain
    let ip = target.trim();
    const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
    if (!isIP) {
      append(warnLine(`Resolving ${target}...`));
      try {
        const res  = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(target)}&type=A`);
        const data = await res.json();
        const ans  = (data.Answer || []).find(a => a.type === 1);
        if (!ans) throw new Error('No A record found');
        ip = ans.data;
        append(warnLine(`${target} → ${ip}`));
      } catch (e) {
        append(errLine('Could not resolve domain: ' + e.message));
        append(ftr()); appendLine(''); return;
      }
    }
    append(warnLine(`Checking ${ip} against ${BLOCKLISTS.length} blocklists...`));
    append(ln('', ''));
    setStatus('Checking blocklists...', 'loading');

    // reverse the IP octets for DNSBL lookup
    const reversed = ip.split('.').reverse().join('.');
    let listedCount = 0;
    const checks = BLOCKLISTS.map(async bl => {
      const query = `${reversed}.${bl.host}`;
      try {
        const res  = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(query)}&type=A`);
        const data = await res.json();
        const listed = data.Status === 0 && (data.Answer || []).length > 0;
        return { name: bl.name, listed };
      } catch {
        return { name: bl.name, listed: false, err: true };
      }
    });
    const results = await Promise.all(checks);
    results.forEach(r => {
      if (r.err) {
        append(ln('t-comment', `  [ERROR]   ${r.name}`));
      } else if (r.listed) {
        listedCount++;
        append(ln('t-err',  `  [LISTED]  ${r.name}`));
      } else {
        append(ln('t-ok',   `  [CLEAN]   ${r.name}`));
      }
    });
    append(ln('', ''));
    if (listedCount === 0) {
      append(ln('t-ok',  `  Result: IP appears CLEAN across all ${BLOCKLISTS.length} blocklists.`));
    } else {
      append(ln('t-err', `  Result: IP is LISTED on ${listedCount} blocklist(s)!`));
    }
    append(ftr()); appendLine('');
    setStatus('Done.', 'ok');
  }

  // tool: ip analysis (local, no network)
  function toolIPAnalysis(target) {
    append(promptLine(`analyse ip ${target}`));
    const isCIDR = target.includes('/');
    if (isCIDR) {
      append(hdr('CIDR CALCULATOR'));
      const r = parseCIDR(target);
      if (!r) { append(errLine('Invalid CIDR. Example: 192.168.1.0/24')); appendLine(''); return; }
      append(kv('Network',       r.cidr));
      append(kv('Subnet Mask',   r.mask));
      append(kv('Wildcard',      r.wildcard,   't-comment'));
      append(kv('Broadcast',     r.broadcast,  't-warn'));
      append(kv('First Host',    r.first,      't-ok'));
      append(kv('Last Host',     r.last,       't-ok'));
      append(kv('Total Hosts',   r.total));
      append(kv('Class',         r.class));
      append(kv('Type',          r.type));
      append(ftr()); appendLine('');
    } else {
      append(hdr('IPv4 ANALYSIS'));
      const n = parseIPv4(target);
      if (n === null) { append(errLine('Invalid IPv4 address.')); appendLine(''); return; }
      const type = classifyIP(n);
      append(kv('Address',     uint32ToIP(n)));
      append(kv('Binary',      toBinaryStr(n),   't-comment'));
      append(kv('Hex',         '0x' + (n >>> 0).toString(16).toUpperCase().padStart(8, '0'), 't-warn'));
      append(kv('Decimal',     String(n >>> 0)));
      append(kv('Class',       rfcClass(n)));
      append(kv('Type',        type.label,        type.cls || 't-ok'));
      append(kv('Loopback',    (n >>> 24) === 127         ? 'Yes' : 'No', (n >>> 24) === 127 ? 't-warn' : 't-ok'));
      append(kv('Private',     isPrivateIP(n)             ? 'Yes' : 'No', isPrivateIP(n) ? 't-ok' : 't-warn'));
      append(kv('Multicast',   ((n & 0xF0000000) >>> 0 === 0xE0000000) ? 'Yes' : 'No', 't-ok'));
      append(ftr()); appendLine('');
    }
  }

  // my public ip
  async function detectMyIP() {
    try {
      const res  = await fetch('https://api.ipify.org?format=json');
      const data = await res.json();
      return data.ip || null;
    } catch { return null; }
  }
  // DOM wiring
  const scannerSection = document.getElementById('scanner');
  if (!scannerSection) return;
  const targetInput  = document.getElementById('scannerTarget');
  const myIpDisplay  = document.getElementById('myIpDisplay');
  const clearBtn     = document.getElementById('scannerClearBtn');
  const myIpBtn      = document.getElementById('scannerMyIpBtn');
  const toolBtns = {
    info:       document.getElementById('btnIPInfo'),
    whois:      document.getElementById('btnWhois'),
    scan:       document.getElementById('btnPortScan'),
    reputation: document.getElementById('btnReputation'),
    analyse:    document.getElementById('btnAnalyse'),
    all:        document.getElementById('btnAll'),
  };
  function getTarget() {
    return (targetInput?.value || '').trim();
  }
  function setAllBtnsLoading(loading) {
    Object.values(toolBtns).forEach(btn => {
      if (!btn) return;
      btn.disabled = loading;
    });
  }
  async function run(fn, label) {
    const target = getTarget();
    if (!target) { window.CIPHER_UI?.toast('Enter a target IP or domain first', 'error'); return; }
    setAllBtnsLoading(true);
    setStatus(`Running ${label}...`, 'loading');
    try {
      await fn(target);
    } finally {
      setAllBtnsLoading(false);
    }
  }
  toolBtns.info?.addEventListener('click', () => run(toolIPInfo, 'IP Info'));
  toolBtns.whois?.addEventListener('click', () => run(toolWhois, 'WHOIS'));
  toolBtns.scan?.addEventListener('click', () => run(toolPortScan, 'Port Scan'));
  toolBtns.reputation?.addEventListener('click', () => run(toolReputation, 'Reputation'));
  toolBtns.analyse?.addEventListener('click', () => {
    const target = getTarget();
    if (!target) { window.CIPHER_UI?.toast('Enter an IP or CIDR block', 'error'); return; }
    toolIPAnalysis(target);
  });
  toolBtns.all?.addEventListener('click', async () => {
    const target = getTarget();
    if (!target) { window.CIPHER_UI?.toast('Enter a target IP or domain first', 'error'); return; }
    setAllBtnsLoading(true);
    await toolIPInfo(target);
    await toolWhois(target);
    await toolPortScan(target);
    await toolReputation(target);
    toolIPAnalysis(target);
    setAllBtnsLoading(false);
    setStatus('All tools complete.', 'ok');
  });
  myIpBtn?.addEventListener('click', async () => {
    myIpBtn.disabled = true;
    myIpBtn.textContent = 'Detecting...';
    const ip = await detectMyIP();
    if (ip) {
      if (myIpDisplay) myIpDisplay.textContent = ip;
      if (targetInput) targetInput.value = ip;
      window.CIPHER_UI?.toast('Your IP detected: ' + ip, 'success');
    } else {
      window.CIPHER_UI?.toast('Could not detect public IP', 'error');
    }
    myIpBtn.disabled = false;
    myIpBtn.textContent = '🦕 My IP';
  });
  clearBtn?.addEventListener('click', () => {
    if (!output) return;
    output.innerHTML = [
      ln('t-comment', '# CIPHER IP Toolkit - output cleared.'),
      ln('t-comment', '# Enter a target above and pick a tool.'),
      ln('', ''),
    ].join('');
    setStatus('Ready.', '');
  });
  // enter key
  targetInput?.addEventListener('keydown', e => {
    if (e.key === 'Enter') toolBtns.info?.click();
  });
  
  // init message
  if (output) {
    output.innerHTML = [
      ln('t-comment', '# ╔══════════════════════════════════════════╗'),
      ln('t-comment', '# ║   CIPHER IP Toolkit — browser edition     ║'),
      ln('t-comment', '# ╚══════════════════════════════════════════╝'),
      ln('', ''),
      ln('t-out',     'Tools: IP Info · WHOIS · Port Scan · Reputation · IP Analysis'),
      ln('t-out',     'Enter a target IP or domain, then pick a tool below.'),
      ln('', ''),
      ln('t-comment', '# All results appear here in real time.'),
      ln('', ''),
    ].join('');
  }

})();

// main.js - app entry point, initialisation & build info
(function () {
  'use strict';
  // build hash for footer
  const hashEl = document.getElementById('buildHash');
  if (hashEl) {
    const hash = Math.random().toString(36).slice(2, 10).toUpperCase();
    hashEl.textContent = `BUILD: ${hash}`;
  }
  // keyboard shortcut hint in nav
  const searchBtn = document.getElementById('searchBtn');
  if (searchBtn && !('ontouchstart' in window)) {
    const hint = document.createElement('span');
    hint.style.cssText = 'font-family:var(--font-mono);font-size:9px;color:var(--muted);letter-spacing:1px;margin-left:4px;';
    hint.textContent = '⌘K';
    searchBtn.appendChild(hint);
  }
  console.log(
    '%cCIPH3R',
    'font-size:32px;font-weight:bold;color:#00e5ff;text-shadow:0 0 20px rgba(0,229,255,0.5);',
  );
  console.log(
    '%cCybersecurity Intelligence Platform — For educational use only.',
    'color:#3a5a6e;font-size:13px;',
  );
})();

/**
 * ui.js - UI helpers: toast, search overlay, nav scroll, back-to-top
 * exposes window.CIPHER_UI for cross-module use
 */
(function () {
  'use strict';
  const toastContainer = document.getElementById('toastContainer');
  function toast(message, type = 'info') {
    if (!toastContainer) return;
    const el = document.createElement('div');
    el.className = `toast${type !== 'info' ? ' ' + type : ''}`;
    el.textContent = '// ' + message;
    toastContainer.appendChild(el);
    setTimeout(() => {
      el.classList.add('out');
      el.addEventListener('animationend', () => el.remove(), { once: true });
    }, 3000);
  }
  const searchBtn     = document.getElementById('searchBtn');
  const searchOverlay = document.getElementById('searchOverlay');
  const searchInput   = document.getElementById('searchInput');
  const searchResults = document.getElementById('searchResults');
  const index         = window.CIPHER_DATA?.searchIndex || [];
  let focusedIndex = -1;
  function openSearch() {
    searchOverlay.classList.add('open');
    searchOverlay.setAttribute('aria-hidden', 'false');
    searchBtn?.setAttribute('aria-expanded', 'true');
    setTimeout(() => searchInput?.focus(), 50);
  }
  function closeSearch() {
    searchOverlay.classList.remove('open');
    searchOverlay.setAttribute('aria-hidden', 'true');
    searchBtn?.setAttribute('aria-expanded', 'false');
    if (searchInput) searchInput.value = '';
    if (searchResults) searchResults.innerHTML = '';
    focusedIndex = -1;
  }
  function doSearch(q) {
    if (!searchResults) return;
    const query = q.toLowerCase().trim();
    if (!query) { searchResults.innerHTML = ''; return; }
    const hits = index.filter(item =>
      item.title.toLowerCase().includes(query) ||
      item.tag.toLowerCase().includes(query)
    ).slice(0, 8);
    if (!hits.length) {
      searchResults.innerHTML = `<div class="search-result-item"><span style="color:var(--muted);">No results for "${q}"</span></div>`;
      return;
    }
    searchResults.innerHTML = hits.map((item, i) =>
      `<a href="${item.href}" class="search-result-item" data-idx="${i}" role="option">
        <span class="result-tag">${item.tag}</span>
        ${item.title}
      </a>`
    ).join('');
    searchResults.querySelectorAll('.search-result-item').forEach(el => {
      el.addEventListener('click', closeSearch);
    });
  }
  function moveFocus(dir) {
    const items = searchResults?.querySelectorAll('.search-result-item') || [];
    if (!items.length) return;
    items.forEach(el => el.classList.remove('focused'));
    focusedIndex = Math.max(0, Math.min(items.length - 1, focusedIndex + dir));
    items[focusedIndex]?.classList.add('focused');
    items[focusedIndex]?.scrollIntoView({ block: 'nearest' });
  }
  if (searchBtn) searchBtn.addEventListener('click', openSearch);
  searchOverlay?.addEventListener('click', (e) => { if (e.target === searchOverlay) closeSearch(); });
  searchInput?.addEventListener('input', (e) => { focusedIndex = -1; doSearch(e.target.value); });
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); openSearch(); }
    if (e.key === 'Escape' && searchOverlay?.classList.contains('open')) closeSearch();
    if (searchOverlay?.classList.contains('open')) {
      if (e.key === 'ArrowDown') { e.preventDefault(); moveFocus(1); }
      if (e.key === 'ArrowUp')   { e.preventDefault(); moveFocus(-1); }
      if (e.key === 'Enter') {
        const focused = searchResults?.querySelector('.search-result-item.focused');
        if (focused) { focused.click(); }
      }
    }
  });
  const header    = document.getElementById('siteHeader');
  const navLinks  = document.querySelectorAll('.nav-link');
  const sections  = document.querySelectorAll('section[id]');
  const backToTop = document.getElementById('backToTop');
  let ticking = false;
  function onScroll() {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      const scrollY = window.scrollY;
      header?.classList.toggle('scrolled', scrollY > 40);
      if (backToTop) {
        if (scrollY > 600) {
          backToTop.hidden = false;
        } else {
          backToTop.hidden = true;
        }
      }
      let current = '';
      sections.forEach(sec => {
        if (scrollY >= sec.offsetTop - 100) current = sec.id;
      });
      navLinks.forEach(link => {
        link.classList.toggle('active', link.getAttribute('href') === '#' + current);
      });
      ticking = false;
    });
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll(); // initial call
  backToTop?.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
  /* hamburger mobile nav */
  const hamburger = document.getElementById('hamburger');
  const mobileNav = document.getElementById('navLinks');
  hamburger?.addEventListener('click', () => {
    const open = hamburger.classList.toggle('open');
    hamburger.setAttribute('aria-expanded', open);
    mobileNav?.classList.toggle('mobile-open', open);
  });
  mobileNav?.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', () => {
      hamburger?.classList.remove('open');
      hamburger?.setAttribute('aria-expanded', 'false');
      mobileNav.classList.remove('mobile-open');
    });
  });
  const reveals = document.querySelectorAll('.reveal');
  const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        e.target.classList.add('visible');
        revealObserver.unobserve(e.target);
      }
    });
  }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });
  reveals.forEach(el => revealObserver.observe(el));
  const themeToggle = document.getElementById('themeToggle');
  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('cipher-theme', theme);
    if (themeToggle) {
      const isLight = theme === 'light';
      themeToggle.setAttribute('aria-checked', isLight);
      themeToggle.setAttribute('aria-label', isLight ? 'Switch to dark theme' : 'Switch to light theme');
    }
  }
  const savedTheme = localStorage.getItem('cipher-theme');
  if (savedTheme) {
    applyTheme(savedTheme);
  } else if (window.matchMedia('(prefers-color-scheme: light)').matches) {
    applyTheme('light');
  }
  themeToggle?.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    applyTheme(current === 'light' ? 'dark' : 'light');
  });
  window.CIPHER_UI = { toast, openSearch, closeSearch };
})();

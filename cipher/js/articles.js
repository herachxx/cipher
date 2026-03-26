/* articles.js - render articles grid + filter tabs */
(function () {
  'use strict';
  const grid = document.getElementById('articlesGrid');
  const tabs = document.querySelectorAll('.tab[data-filter]');
  if (!grid) return;
  const articles = window.CIPHER_DATA.articles;
  let activeFilter = 'all';
  function buildCard(article) {
    const card = document.createElement('article');
    card.className = 'article-card' + (article.featured ? ' featured' : '');
    card.setAttribute('role', 'listitem');
    card.setAttribute('data-category', article.category);
    card.setAttribute('tabindex', '0');
    const bodyHtml = article.body
      ? `<p>${article.body}</p>`
      : '';
    card.innerHTML = `
      <span class="article-badge ${article.badgeClass}">${article.badge}</span>
      <h3>${article.title}</h3>
      <p>${article.excerpt}</p>
      ${bodyHtml}
      <div class="article-meta">
        <span>${article.date} &nbsp;·&nbsp; ${article.readTime} READ &nbsp;·&nbsp; ${article.tag}</span>
        <span class="article-read-more">READ →</span>
      </div>
    `;
    return card;
  }
  function renderAll() {
    grid.innerHTML = '';
    const filtered = activeFilter === 'all'
      ? articles
      : articles.filter(a => a.category === activeFilter);
    if (filtered.length === 0) {
      grid.innerHTML = `<p style="color:var(--muted); font-family:var(--font-mono); font-size:13px; padding:40px;">No articles in this category yet.</p>`;
      return;
    }
    filtered.forEach(article => grid.appendChild(buildCard(article)));
    // re-trigger layout for featured card
    const featured = grid.querySelector('.article-card.featured');
    if (featured && activeFilter === 'all') {
      grid.style.gridTemplateColumns = '2fr 1fr 1fr';
    } else {
      grid.style.gridTemplateColumns = '';
    }
  }
  // tab switching
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
      tab.classList.add('active');
      tab.setAttribute('aria-selected', 'true');
      activeFilter = tab.dataset.filter;
      renderAll();
    });
  });
  renderAll();
})();

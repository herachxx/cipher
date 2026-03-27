/* articles.js - render articles grid + filter tabs, each card linking externally */
(function () {
  'use strict';
  const grid = document.getElementById('articlesGrid');
  const tabs = document.querySelectorAll('.tab[data-filter]');
  if (!grid) return;
  const articles = window.CIPHER_DATA.articles;
  let activeFilter = 'all';
  function buildCard(article) {
    const card = document.createElement('a');
    card.className = 'article-card' + (article.featured ? ' featured' : '');
    card.setAttribute('role', 'listitem');
    card.setAttribute('data-category', article.category);
    card.href   = article.href || '#intel';
    card.target = article.href ? '_blank' : '_self';
    card.rel    = 'noopener noreferrer';
    const bodyHtml = article.body ? `<p>${article.body}</p>` : '';
    card.innerHTML = `
      <span class="article-badge ${article.badgeClass}">${article.badge}</span>
      <h3>${article.title}</h3>
      <p>${article.excerpt}</p>
      ${bodyHtml}
      <div class="article-meta">
        <span>${article.date} &nbsp;·&nbsp; ${article.readTime} READ &nbsp;·&nbsp; ${article.tag}</span>
        <span class="article-read-more" data-icon="arrowUpRight" data-icon-size="11" aria-hidden="true"></span>
      </div>
    `;
    return card;
  }
  function renderAll() {
    grid.innerHTML = '';
    const filtered = activeFilter === 'all'
      ? articles
      : articles.filter(a => a.category === activeFilter);
    if (!filtered.length) {
      grid.innerHTML = `<p style="color:var(--muted);font-family:var(--font-mono);font-size:13px;padding:40px;">No articles in this category yet.</p>`;
      return;
    }
    filtered.forEach(a => grid.appendChild(buildCard(a)));
    window.CIPHER_ICONS?.hydrate(grid);
    grid.style.gridTemplateColumns =
      (activeFilter === 'all' && filtered.find(a => a.featured))
        ? '2fr 1fr 1fr'
        : '';
  }
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

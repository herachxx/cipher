/* topics.js - render topic cards from data, each linking to a real resource */
(function () {
  'use strict';
  const grid = document.getElementById('topicsGrid');
  if (!grid) return;
  window.CIPHER_DATA.topics.forEach((topic) => {
    const card = document.createElement('a');
    card.className = 'topic-card';
    card.setAttribute('role', 'listitem');
    card.href   = topic.href || '#topics';
    card.target = '_blank';
    card.rel    = 'noopener noreferrer';
    card.setAttribute('aria-label', `${topic.title} - opens external resource`);
    card.innerHTML = `
      <div class="topic-card-header">
        <span class="topic-icon" aria-hidden="true">${window.CIPHER_ICONS.get(topic.icon, 22)}</span>
        <span class="topic-num"  aria-hidden="true">${topic.num}</span>
      </div>
      <h3>${topic.title}</h3>
      <p>${topic.desc}</p>
      <span class="topic-tag">${topic.tag}</span>
      <span class="topic-ext-icon" data-icon="arrowUpRight" data-icon-size="13" aria-hidden="true"></span>
    `;
    grid.appendChild(card);
  });
  window.CIPHER_ICONS?.hydrate(grid);
})();

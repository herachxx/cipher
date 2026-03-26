// topics.js - render topic cards from data
(function () {
  'use strict';
  const grid = document.getElementById('topicsGrid');
  if (!grid) return;
  const topics = window.CIPHER_DATA.topics;
  topics.forEach((topic) => {
    const card = document.createElement('div');
    card.className = 'topic-card';
    card.setAttribute('role', 'listitem');
    card.setAttribute('tabindex', '0');
    card.innerHTML = `
      <div class="topic-card-header">
        <span class="topic-icon" aria-hidden="true">${topic.icon}</span>
        <span class="topic-num" aria-hidden="true">${topic.num}</span>
      </div>
      <h3>${topic.title}</h3>
      <p>${topic.desc}</p>
      <span class="topic-tag">${topic.tag}</span>
    `;
    // keyboard accessibility
    card.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        card.click();
      }
    });
    grid.appendChild(card);
  });
})();

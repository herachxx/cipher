// ticker.js - live threat ticker tape
(function () {
  'use strict';
  const track = document.getElementById('tickerTrack');
  if (!track) return;
  const items = window.CIPHER_DATA.ticker;
  function buildItem(item) {
    const span = document.createElement('span');
    span.className = 'ticker-item';
    span.innerHTML = `<span class="ticker-tag ${item.tagClass}">${item.tag}</span> ${item.text}`;
    return span;
  }
  // double the items for seamless infinite scroll
  [...items, ...items].forEach(item => track.appendChild(buildItem(item)));
})();

// terminal.js - typewriter terminal animation
(function () {
  'use strict';
  const body = document.getElementById('terminalBody');
  const copyBtn = document.getElementById('copyTerminal');
  if (!body) return;
  const lines = window.CIPHER_DATA.terminal;
  const CHAR_DELAY  = 28;   // ms per character (typing speed)
  const LINE_DELAY  = 180;  // ms between lines
  const CMD_PAUSE   = 320;  // extra pause after commands
  let currentLineEl = null;
  let plainText = '';       // accumulate for clipboard
  function createLine(className) {
    const el = document.createElement('span');
    el.className = 't-line';
    if (className) el.classList.add(className);
    body.appendChild(el);
    return el;
  }
  function scrollBottom() {
    body.scrollTop = body.scrollHeight;
  }
  function typeText(el, text, resolve) {
    let i = 0;
    function next() {
      if (i < text.length) {
        el.textContent += text[i++];
        scrollBottom();
        setTimeout(next, CHAR_DELAY + Math.random() * 18);
      } else {
        resolve();
      }
    }
    next();
  }
  function renderPrompt(el) {
    el.innerHTML =
      `<span class="t-prompt">cipher3r</span>` +
      `<span class="t-at">@</span>` +
      `<span class="t-path">lab</span>` +
      `<span class="t-at">:~$</span> `;
  }
  function renderLine(line) {
    return new Promise((resolve) => {
      if (line.type === 'blank') {
        createLine();
        plainText += '\n';
        return setTimeout(resolve, LINE_DELAY * 0.4);
      }
      if (line.type === 'cursor') {
        const el = createLine();
        renderPrompt(el);
        const cur = document.createElement('span');
        cur.className = 't-cursor';
        el.appendChild(cur);
        scrollBottom();
        return resolve();
      }
      if (line.type === 'cmd') {
        const el = createLine('t-cmd');
        renderPrompt(el);
        plainText += `cipher3r@lab:~$ ${line.text}\n`;
        const textSpan = document.createElement('span');
        el.appendChild(textSpan);
        return typeText(textSpan, line.text, () => setTimeout(resolve, CMD_PAUSE));
      }
      // static lines
      const classMap = {
        out:     't-out',
        ok:      't-ok',
        warn:    't-warn',
        err:     't-err',
        comment: 't-comment',
      };
      const el = createLine(classMap[line.type] || '');
      el.textContent = line.text;
      plainText += line.text + '\n';
      scrollBottom();
      setTimeout(resolve, LINE_DELAY);
    });
  }
  async function runTerminal() {
    for (const line of lines) {
      await renderLine(line);
    }
  }
  // intersection observer - start when visible
  const observer = new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting) {
      observer.disconnect();
      runTerminal();
    }
  }, { threshold: 0.3 });
  observer.observe(body);
  // copy button
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(plainText).then(() => {
        window.CIPHER_UI?.toast('Terminal output copied!', 'success');
        copyBtn.style.color = 'var(--accent3)';
        setTimeout(() => { copyBtn.style.color = ''; }, 1500);
      });
    });
  }
})();

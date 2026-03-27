/* background.js - particle / node canvas background */
(function () {
  'use strict';
  const canvas = document.getElementById('bgCanvas');
  if (!canvas) return;
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    canvas.remove();
    return;
  }
  const ctx = canvas.getContext('2d');
  const PARTICLE_COUNT = 55;
  const CONNECTION_DIST = 160;
  const COLOR = '0, 229, 255';
  let W, H, particles = [], rafId;
  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }
  function randomBetween(a, b) {
    return a + Math.random() * (b - a);
  }
  function createParticle() {
    return {
      x:   randomBetween(0, W),
      y:   randomBetween(0, H),
      vx:  randomBetween(-0.18, 0.18),
      vy:  randomBetween(-0.18, 0.18),
      r:   randomBetween(1, 2.2),
      alpha: randomBetween(0.2, 0.6),
    };
  }
  function init() {
    resize();
    particles = Array.from({ length: PARTICLE_COUNT }, createParticle);
  }
  function draw() {
    ctx.clearRect(0, 0, W, H);
    for (const p of particles) {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < -10) p.x = W + 10;
      if (p.x > W + 10) p.x = -10;
      if (p.y < -10) p.y = H + 10;
      if (p.y > H + 10) p.y = -10;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${COLOR}, ${p.alpha})`;
      ctx.fill();
    }
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < CONNECTION_DIST) {
          const alpha = (1 - dist / CONNECTION_DIST) * 0.12;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(${COLOR}, ${alpha})`;
          ctx.lineWidth = 0.6;
          ctx.stroke();
        }
      }
    }
    rafId = requestAnimationFrame(draw);
  }
  init();
  draw();
  window.addEventListener('resize', () => {
    cancelAnimationFrame(rafId);
    init();
    draw();
  }, { passive: true });
})();

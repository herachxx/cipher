// threatmap.js - animated threat map on Canvas
(function () {
  'use strict';
  const canvas = document.getElementById('mapCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let W, H, nodes = [], beams = [], rafId;
  let started = false;
  // node positions as % of canvas dimensions
  const NODE_DEFS = [
    [12, 28], [22, 15], [38, 22], [52, 18], [65, 25],
    [78, 20], [88, 38], [82, 58], [68, 52], [52, 60],
    [38, 68], [24, 58], [10, 48], [46, 42], [60, 72],
    [72, 75], [30, 80], [85, 72], [15, 70], [50, 88],
  ];
  const ATTACK_COLOR  = '255, 45, 85';
  const NODE_COLOR    = '0, 229, 255';
  const BEAM_DURATION = 90; // frames
  function resize() {
    W = canvas.width  = canvas.offsetWidth;
    H = canvas.height = canvas.offsetHeight;
    buildNodes();
  }
  function buildNodes() {
    nodes = NODE_DEFS.map(([px, py]) => ({
      x: (px / 100) * W,
      y: (py / 100) * H,
      r: Math.random() * 1.5 + 1.2,
      pulsePhase: Math.random() * Math.PI * 2,
      isAttacker: Math.random() < 0.3,
    }));
  }
  function spawnBeam() {
    if (nodes.length < 2) return;
    const src = nodes[Math.floor(Math.random() * nodes.length)];
    let dst;
    do { dst = nodes[Math.floor(Math.random() * nodes.length)]; } while (dst === src);
    beams.push({ src, dst, age: 0, duration: BEAM_DURATION + Math.random() * 40 });
  }
  function drawNode(node, frame) {
    const pulse = Math.sin(frame * 0.05 + node.pulsePhase) * 0.5 + 0.5;
    const color = node.isAttacker ? ATTACK_COLOR : NODE_COLOR;
    // outer pulse ring
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.r + pulse * 8, 0, Math.PI * 2);
    ctx.strokeStyle = `rgba(${color}, ${0.08 * pulse})`;
    ctx.lineWidth = 1;
    ctx.stroke();
    // core dot
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(${color}, 0.9)`;
    ctx.fill();
    ctx.shadowColor = `rgba(${color}, 0.6)`;
    ctx.shadowBlur = 6;
    ctx.fill();
    ctx.shadowBlur = 0;
  }
  function drawBeam(beam) {
    const t = beam.age / beam.duration;
    const eased = t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
    const headX = beam.src.x + (beam.dst.x - beam.src.x) * eased;
    const headY = beam.src.y + (beam.dst.y - beam.src.y) * eased;
    const tailT = Math.max(0, t - 0.3);
    const tailX = beam.src.x + (beam.dst.x - beam.src.x) * tailT;
    const tailY = beam.src.y + (beam.dst.y - beam.src.y) * tailT;
    const grad = ctx.createLinearGradient(tailX, tailY, headX, headY);
    grad.addColorStop(0, `rgba(${ATTACK_COLOR}, 0)`);
    grad.addColorStop(1, `rgba(${ATTACK_COLOR}, 0.9)`);
    ctx.beginPath();
    ctx.moveTo(tailX, tailY);
    ctx.lineTo(headX, headY);
    ctx.strokeStyle = grad;
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // head glow
    ctx.beginPath();
    ctx.arc(headX, headY, 3, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(${ATTACK_COLOR}, 0.9)`;
    ctx.shadowColor = `rgba(${ATTACK_COLOR}, 0.8)`;
    ctx.shadowBlur = 8;
    ctx.fill();
    ctx.shadowBlur = 0;
  }
  let frame = 0;
  let beamTimer = 0;
  function render() {
    ctx.clearRect(0, 0, W, H);

    // background grid lines (subtle)
    ctx.strokeStyle = 'rgba(0,229,255,0.03)';
    ctx.lineWidth = 0.5;
    for (let x = 0; x < W; x += 60) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
    }
    for (let y = 0; y < H; y += 40) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
    }

    // spawn beams periodically
    if (++beamTimer % 28 === 0) spawnBeam();

    // draw connection mesh (faint)
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const dist = Math.sqrt(dx*dx + dy*dy);
        if (dist < W * 0.25) {
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);
          ctx.strokeStyle = `rgba(0,229,255,${0.025 * (1 - dist/(W*0.25))})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    }

    // draw beams
    beams = beams.filter(b => b.age <= b.duration);
    beams.forEach(b => { drawBeam(b); b.age++; });

    // draw nodes
    nodes.forEach(n => drawNode(n, frame));

    frame++;
    rafId = requestAnimationFrame(render);
  }

  // animate counters
  function animateCounters() {
    const els = document.querySelectorAll('.t-stat-num[data-target]');
    els.forEach(el => {
      const target = parseInt(el.dataset.target, 10);
      const duration = 1800;
      const start = performance.now();
      el.classList.add('counting');
      function step(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.floor(eased * target).toLocaleString();
        if (progress < 1) {
          requestAnimationFrame(step);
        } else {
          el.textContent = target.toLocaleString();
          el.classList.remove('counting');
        }
      }
      requestAnimationFrame(step);
    });
  }

  // only start when visible
  const observer = new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting && !started) {
      started = true;
      resize();
      render();
      animateCounters();
      observer.disconnect();
    }
  }, { threshold: 0.2 });
  observer.observe(canvas);
  window.addEventListener('resize', () => {
    cancelAnimationFrame(rafId);
    resize();
    render();
  }, { passive: true });
})();

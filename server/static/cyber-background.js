/*
 * Heimdall Cyber Background — port direct du composant Next.js (site_cloud).
 *
 * Particules orange (#FF8630) + bleues (#0131B8) qui flottent ; lignes
 * blanches reliant les particules proches. S'attache à <body> en position
 * fixed, z-index négatif → tout le contenu du dashboard reste au-dessus.
 *
 * Adaptation pour le dashboard agent :
 *  - On force un fond de base sombre (--bg du thème admin) plutôt que
 *    hsl(var(--background)) qui n'existe pas ici.
 *  - On respecte prefers-reduced-motion (les particules restent statiques).
 */
(function () {
  const ORANGE = "#FF8630";
  const BLUE   = "#0131B8";
  const REDUCED = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const canvas = document.createElement("canvas");
  canvas.id = "cyber-bg";
  canvas.setAttribute("aria-hidden", "true");
  Object.assign(canvas.style, {
    position: "fixed",
    inset: "0",
    width: "100%",
    height: "100%",
    zIndex: "-10",
    background: "var(--bg, #0b1220)",
    pointerEvents: "none",
  });
  document.body.prepend(canvas);

  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener("resize", resize);

  class Particle {
    constructor() {
      this.x = Math.random() * canvas.width;
      this.y = Math.random() * canvas.height;
      this.size = Math.random() * 3 + 1;
      this.speedX = (Math.random() - 0.5) * 0.5;
      this.speedY = (Math.random() - 0.5) * 0.5;
      this.color = Math.random() > 0.5 ? ORANGE : BLUE;
    }
    update() {
      this.x += this.speedX;
      this.y += this.speedY;
      if (this.x > canvas.width) this.x = 0;
      else if (this.x < 0) this.x = canvas.width;
      if (this.y > canvas.height) this.y = 0;
      else if (this.y < 0) this.y = canvas.height;
    }
    draw() {
      ctx.fillStyle = this.color;
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  const count = Math.min(100, Math.floor(window.innerWidth / 20));
  const particles = Array.from({ length: count }, () => new Particle());

  function connect() {
    const maxDistance = 150;
    for (let a = 0; a < particles.length; a++) {
      for (let b = a; b < particles.length; b++) {
        const dx = particles[a].x - particles[b].x;
        const dy = particles[a].y - particles[b].y;
        const distance = Math.sqrt(dx * dx + dy * dy);
        if (distance < maxDistance) {
          const opacity = 1 - distance / maxDistance;
          ctx.strokeStyle = `rgba(255, 255, 255, ${opacity * 0.18})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(particles[a].x, particles[a].y);
          ctx.lineTo(particles[b].x, particles[b].y);
          ctx.stroke();
        }
      }
    }
  }

  function drawStatic() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (const p of particles) p.draw();
    connect();
  }

  function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (const p of particles) { p.update(); p.draw(); }
    connect();
    requestAnimationFrame(animate);
  }

  if (REDUCED) drawStatic();
  else animate();
})();

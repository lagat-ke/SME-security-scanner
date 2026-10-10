(() => {
  const $ = (id) => document.getElementById(id);
  const COLORS = {critical:'#b91c1c', high:'#ea580c', medium:'#ca8a04', low:'#2563eb', info:'#64748b', pass:'#15803d'};
  const GRADES = {A:'#15803d', B:'#65a30d', C:'#ca8a04', D:'#ea580c', F:'#b91c1c'};
  const ORDER = ['critical','high','medium','low','info','pass'];
  let current = null, filter = 'all';

  function el(tag, props = {}, ...kids) {
    const n = document.createElement(tag);
    Object.assign(n, props);
    kids.forEach(k => n.append(k));
    return n;
  }

  function showError(msg) { const e = $('err'); e.textContent = msg; e.hidden = !msg; }

  $('form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    showError('');
    $('results').hidden = true;
    $('loading').hidden = false;
    $('go').disabled = true;
    try {
      const r = await fetch('/api/scan', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({domain: $('domain').value, check_ports: $('ports').checked, confirm_ownership: $('own').checked}),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || 'Scan failed');
      current = data; filter = 'all';
      render();
    } catch (e) {
      showError(e.message);
    } finally {
      $('loading').hidden = true;
      $('go').disabled = false;
    }
  });

  function render(rerender = false) {
    const d = current;
    $('results').hidden = false;
    const g = $('grade'); g.textContent = d.grade; g.style.background = GRADES[d.grade] || '#64748b';
    $('r-domain').textContent = d.domain;
    $('r-score').textContent = d.grade === '?' ? 'Not graded: the domain could not be resolved' : `Security score ${d.score}/100`;
    const counts = $('counts'); counts.replaceChildren();
    ORDER.forEach(s => { if (d.counts[s]) { const p = el('span', {className: 'pill', textContent: `${d.counts[s]} ${s}`}); p.style.background = COLORS[s]; counts.append(p); } });
    $('pdf').href = `/api/report/${encodeURIComponent(d.id)}.pdf`;

    const filters = $('filters'); filters.replaceChildren();
    ['all', ...ORDER].forEach(s => {
      const b = el('button', {type: 'button', textContent: s === 'all' ? 'All' : s[0].toUpperCase() + s.slice(1), className: s === filter ? 'on' : ''});
      b.addEventListener('click', () => { filter = s; render(true); });
      filters.append(b);
    });

    const box = $('findings'); box.replaceChildren();
    const cats = [];
    d.findings.forEach(f => { if (!cats.includes(f.category)) cats.push(f.category); });
    cats.forEach(cat => {
      const items = d.findings.filter(f => f.category === cat && (filter === 'all' || f.severity === filter));
      if (!items.length) return;
      box.append(el('h3', {className: 'cat', textContent: cat}));
      items.forEach(f => {
        const card = el('div', {className: 'f'});
        card.style.borderLeftColor = COLORS[f.severity];
        const tag = el('span', {className: 'tag', textContent: f.severity}); tag.style.background = COLORS[f.severity];
        card.append(el('h4', {}, tag, f.title));
        if (f.detail) card.append(el('p', {textContent: f.detail}));
        if (f.fix) card.append(el('p', {className: 'fix', textContent: 'Fix: ' + f.fix}));
        box.append(card);
      });
    });

    const subs = $('subs'); subs.replaceChildren();
    (d.subdomains || []).forEach(s => subs.append(el('li', {textContent: s.name + (s.dangling ? '  (dangling DNS)' : s.live === false ? '  (no address)' : '')})));
    $('subs-n').textContent = (d.subdomains || []).length;
    $('subs-wrap').hidden = !(d.subdomains || []).length;
    const tech = $('tech'); tech.replaceChildren();
    (d.technologies || []).forEach(t => tech.append(el('li', {textContent: `${t.name} (${t.type})`})));
    $('tech-wrap').hidden = !(d.technologies || []).length;
    if (!rerender) $('results').scrollIntoView({behavior: 'smooth', block: 'start'});
  }
})();

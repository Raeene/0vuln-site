'use strict';
// =====================================================================
// 0vuln hub: hero replay, site status, and the little shell
// =====================================================================
const $ = s => document.querySelector(s);
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const HOSTS = { range: 'range.0vuln.com', pcap: 'pcap.0vuln.com', raeene: 'raeene.0vuln.com' };
const siteUrl = k => window.OV ? OV.url(k, '/') : 'https://' + HOSTS[k] + '/';

// ---------------------------------------------------------------------
// hero replay: attacker terminal -> packets on the wire -> detections
// ---------------------------------------------------------------------
const SCRIPT = [
  { cmd: 'nmap -sS 10.0.0.9', out: [['12 open tcp ports: ftp ssh smtp domain', 'd'], ['http pop3 rpcbind smb imap nfs mysql', 'd']], burst: 46, det: ['alert', 'Port scan', '10.0.0.5 probed 1,026 ports on 10.0.0.9', 'T1046'] },
  { cmd: 'ftp 10.0.0.9', out: [['Name: anonymous', 'd'], ['230 Login successful.', 'g']], burst: 10, det: ['warn', 'Cleartext FTP login', 'user "anonymous" from 10.0.0.5', 'T1552'] },
  { cmd: 'dig axfr corp.local @10.0.0.9', out: [['vpn.corp.local   A  10.0.0.77', 'd'], [';; XFR size: 7 records', 'g']], burst: 8, det: ['alert', 'DNS zone transfer', 'AXFR for corp.local handed to 10.0.0.5', 'T1590.002'] },
  { cmd: 'snmpwalk -v2c -c public 10.0.0.9', out: [['hrSWRunParameters: --user dbadmin', 'd'], ['--password Db#Pass2026', 'g']], burst: 14, det: ['warn', 'SNMP default community', 'requests using "public"', 'T1602.001'] },
  { cmd: 'curl imap://10.0.0.9/INBOX --user backup:***', out: [['Subject: nightly backup', 'd'], ['FLAG{mailboxes_hold_secrets}', 'g']], burst: 12, det: ['warn', 'Cleartext IMAP login', 'user "backup" from 10.0.0.5', 'T1552'] },
];

const net = (() => {
  const cv = $('#rp-canvas'); if (!cv) return null;
  const x = cv.getContext('2d'); let W = 0, H = 0, dpr = 1, pk = [], t = 0, visible = true;
  const size = () => { const r = cv.getBoundingClientRect(); dpr = Math.min(2, devicePixelRatio || 1); W = r.width; H = r.height; cv.width = W * dpr; cv.height = H * dpr; x.setTransform(dpr, 0, 0, dpr, 0, 0); };
  size(); addEventListener('resize', size);
  const A = () => ({ x: W * .16, y: H * .38 }), T = () => ({ x: W * .84, y: H * .38 }), S = () => ({ x: W * .5, y: H * .84 });
  function node(p, col, r, pulse) {
    const g = x.createRadialGradient(p.x, p.y, 0, p.x, p.y, r * 3.2);
    g.addColorStop(0, col.replace('1)', (.35 + pulse * .25) + ')')); g.addColorStop(1, col.replace('1)', '0)'));
    x.fillStyle = g; x.beginPath(); x.arc(p.x, p.y, r * 3.2, 0, 7); x.fill();
    x.fillStyle = '#0b0d14'; x.strokeStyle = col; x.lineWidth = 1.5; x.beginPath(); x.arc(p.x, p.y, r, 0, 7); x.fill(); x.stroke();
    x.fillStyle = col; x.beginPath(); x.arc(p.x, p.y, r * .38, 0, 7); x.fill();
  }
  function frame() {
    t += 1 / 60; x.clearRect(0, 0, W, H);
    const a = A(), b = T(), s = S(), mid = { x: (a.x + b.x) / 2, y: a.y };
    // wire + tap
    x.strokeStyle = 'rgba(255,255,255,.12)'; x.lineWidth = 1; x.setLineDash([]);
    x.beginPath(); x.moveTo(a.x, a.y); x.lineTo(b.x, b.y); x.stroke();
    x.setLineDash([3, 5]); x.strokeStyle = 'rgba(34,211,238,.3)';
    x.beginPath(); x.moveTo(mid.x, mid.y); x.lineTo(s.x, s.y); x.stroke(); x.setLineDash([]);
    x.fillStyle = 'rgba(34,211,238,.9)'; x.beginPath(); x.arc(mid.x, mid.y, 3, 0, 7); x.fill();
    // packets
    pk = pk.filter(p => p.p < 1);
    for (const p of pk) {
      p.p += p.v;
      let px, py;
      if (p.k === 'tap') { px = mid.x; py = mid.y + (s.y - mid.y) * p.p; }
      else { const f = p.k === 'req' ? [a, b] : [b, a]; px = f[0].x + (f[1].x - f[0].x) * p.p; py = f[0].y + (f[1].y - f[0].y) * p.p + Math.sin(p.p * Math.PI) * p.o; }
      const col = p.k === 'req' ? '255,77,109' : p.k === 'res' ? '236,238,244' : '34,211,238';
      x.fillStyle = `rgba(${col},.18)`; x.beginPath(); x.arc(px, py, 7, 0, 7); x.fill();
      x.fillStyle = `rgba(${col},1)`; x.beginPath(); x.arc(px, py, 2.4, 0, 7); x.fill();
      // spawn a copy to the sensor when crossing the tap
      if (p.k !== 'tap' && !p.tapped && p.p > .5) { p.tapped = 1; pk.push({ k: 'tap', p: 0, v: .022 }); }
    }
    const pulse = (Math.sin(t * 2.4) + 1) / 2;
    node(a, 'rgba(255,77,109,1)', 13, pulse);
    node(b, 'rgba(155,135,255,1)', 13, 1 - pulse);
    node(s, 'rgba(34,211,238,1)', 10, pulse);
    if (visible) requestAnimationFrame(frame);
  }
  new IntersectionObserver(es => { const v = es[0].isIntersecting; if (v && !visible) { visible = true; requestAnimationFrame(frame); } else visible = v; }).observe(cv);
  if (!reduce) requestAnimationFrame(frame); else { visible = false; frame(); }
  return {
    burst(n) {
      if (reduce) return;
      for (let i = 0; i < n; i++) setTimeout(() => {
        pk.push({ k: 'req', p: 0, v: .012 + Math.random() * .01, o: (Math.random() - .5) * 26 });
        if (Math.random() < .55) setTimeout(() => pk.push({ k: 'res', p: 0, v: .012 + Math.random() * .008, o: (Math.random() - .5) * 26 }), 380);
      }, i * (1400 / n));
    }
  };
})();

async function replay() {
  const term = $('#rp-term'), feed = $('#rp-feed'); if (!term || !feed) return;
  const line = (txt, cls) => { const d = document.createElement('div'); d.className = cls; d.textContent = txt; term.appendChild(d); while (term.children.length > 14) term.firstChild.remove(); return d; };
  const detect = ([sev, name, txt, id]) => {
    const li = document.createElement('li'); li.className = sev;
    li.innerHTML = '<div class="top"></div><div class="txt"></div>';
    li.querySelector('.top').textContent = sev + ' \u00b7 ' + name;
    const em = document.createElement('em'); em.textContent = id; li.querySelector('.top').appendChild(em);
    li.querySelector('.txt').textContent = txt;
    feed.appendChild(li);
    while (feed.children.length > 4) feed.firstChild.remove();
  };
  if (reduce) { for (const s of SCRIPT.slice(0, 3)) { line(s.cmd, 'c'); s.out.forEach(([t, c]) => line(t, c)); detect(s.det); } return; }
  for (;;) {
    for (const s of SCRIPT) {
      const l = line('', 'c cur');
      for (let i = 1; i <= s.cmd.length; i++) { l.textContent = s.cmd.slice(0, i); await sleep(28 + Math.random() * 40); }
      l.className = 'c'; await sleep(250);
      net && net.burst(s.burst);
      await sleep(900);
      for (const [t, c] of s.out) { line(t, c); await sleep(220); }
      await sleep(500);
      detect(s.det);
      await sleep(1900);
    }
    await sleep(1200);
    [...feed.children].forEach(li => li.classList.add('out'));
    await sleep(500); feed.textContent = ''; term.textContent = '';
  }
}
replay();

// randomize PacketStory mini timeline bars (CSSOM, allowed by the CSP)
document.querySelectorAll('.vis-pcap .bars i').forEach((b, i) => {
  const h = [22, 30, 26, 90, 100, 95, 40, 28, 34, 60, 72, 30, 24, 26, 46, 30, 84, 88, 34, 26, 30, 22, 38, 28][i] || 30;
  b.style.height = h + '%'; b.style.animationDelay = (-(i * .37) % 3.6) + 's';
});

// ---------------------------------------------------------------------
// live status of each site
// ---------------------------------------------------------------------
const state = {};
function probe(k) {
  const ac = new AbortController(), tm = setTimeout(() => ac.abort(), 5000), t0 = performance.now();
  return fetch(siteUrl(k), { mode: 'no-cors', cache: 'no-store', signal: ac.signal })
    .then(() => Math.round(performance.now() - t0), () => -1).finally(() => clearTimeout(tm));
}
function check() {
  return Promise.all(Object.keys(HOSTS).map(k => probe(k).then(ms => {
    state[k] = ms;
    const d = document.querySelector(`[data-dot="${k}"]`), s = document.querySelector(`[data-st="${k}"]`);
    if (d) d.className = 'dot' + (ms >= 0 ? '' : ' off');
    if (s) s.textContent = ms >= 0 ? 'online \u00b7 ' + ms + ' ms' : 'offline';
  })));
}
check();

// ---------------------------------------------------------------------
// shell: pure command logic
// ---------------------------------------------------------------------
const ALIAS = { about: 'raeene', resume: 'raeene', me: 'raeene', packetstory: 'pcap', lab: 'range', ctf: 'range' };
const CMDS = ['help', 'ls', 'open', 'cd', 'status', 'whoami', 'manifesto', 'neofetch', 'ping', 'date', 'echo', 'history', 'github', 'fullscreen', 'clear', 'sudo', 'exit'];
function reply(line, hist = []) {
  const [c, ...a] = line.trim().split(/\s+/);
  const cmd = (c || '').toLowerCase();
  if (!cmd) return [];
  const target = k => HOSTS[ALIAS[k] || k] ? (ALIAS[k] || k) : null;
  switch (cmd) {
    case 'help': return [
      ['commands', 'y'],
      ['  ls                 list what lives here', 'd'],
      ['  open <name>        go to range | pcap | raeene', 'd'],
      ['  status             check which sites are up', 'd'],
      ['  ping <name>        measure how fast a site answers', 'd'],
      ['  manifesto          why 0vuln exists', 'd'],
      ['  neofetch           system info, the fun way', 'd'],
      ['  whoami  date  echo  history  github  fullscreen  clear', 'd'],
      ['tip: Tab completes, arrow keys walk your history.', 'k']];
    case 'ls': return [['range/   pcap/   raeene/   manifesto.txt', 'k']];
    case 'cat': return (a[0] || '').startsWith('manifesto') ? reply('manifesto') : [['cat: ' + (a[0] || '') + ': no such file', 'e']];
    case 'open': case 'cd': {
      const k = target((a[0] || '').toLowerCase().replace(/\/$/, ''));
      return k ? [['connecting to ' + HOSTS[k] + ' ...', 'd'], ['go', k]] : [['usage: open <range|pcap|raeene>', 'e']];
    }
    case 'status': return [['status']];
    case 'ping': { const k = target((a[0] || '').toLowerCase()); return k ? [['ping', k]] : [['usage: ping <range|pcap|raeene>', 'e']]; }
    case 'fullscreen': case 'fs': return [['fs']];
    case 'manifesto': return [
      ['0vuln: zero vulnerabilities is a direction, not a destination.', 'c'],
      ['You learn security by doing it, then by watching what you did.', 'd'],
      ['Break things safely here, so you know how to defend them out there.', 'd']];
    case 'whoami': return [['visitor. no account, no cookies, no tracking. try: open raeene', 'd']];
    case 'neofetch': return [
      ['   ____     ', 'm', 'visitor@0vuln'],
      ['  / __ \\    ', 'm', '-------------'],
      [' | |  | |   ', 'a', 'os      0vuln.os v2'],
      [' | |  | |   ', 'a', 'host    cloudflare edge'],
      [' | |__| |   ', 'k', 'shell   hub.js'],
      ['  \\____/    ', 'k', 'tools   range, pcap'],
      ['            ', '', 'vulns   0 known (still looking)']];
    case 'date': return [[new Date().toString(), 'd']];
    case 'echo': return [[a.join(' '), '']];
    case 'history': return hist.length ? hist.map((h, i) => [String(i + 1).padStart(4) + '  ' + h, 'd']) : [['(empty)', 'd']];
    case 'github': return [['opening github.com/Raeene ...', 'd'], ['goabs', 'https://github.com/Raeene']];
    case 'clear': return [['clear']];
    case 'sudo': return [['visitor is not in the sudoers file. This incident will be reported.', 'e'], ['(not really. but the Range has a box you can own.)', 'd']];
    case 'rm': return [['nice try.', 'e']];
    case 'exit': return [['there is no escape. try: open range', 'm']];
    case 'hack': return [['now you are talking. opening the range ...', 'g'], ['go', 'range']];
    default: return [[cmd + ': command not found. type help', 'e']];
  }
}
function complete(v) {
  const parts = v.split(/\s+/);
  if (parts.length === 1) { const m = CMDS.filter(c => c.startsWith(parts[0].toLowerCase())); return m.length === 1 ? m[0] + ' ' : m.length ? { list: m } : v; }
  if (['open', 'cd', 'ping'].includes(parts[0].toLowerCase()) && parts.length === 2) {
    const m = Object.keys(HOSTS).filter(k => k.startsWith(parts[1].toLowerCase()));
    return m.length === 1 ? parts[0] + ' ' + m[0] : m.length ? { list: m } : v;
  }
  return v;
}

// ---- shell DOM ----
const out = $('#out'), inp = $('#i');
const hist = []; let hp = 0;
function say(text, cls, extra) {
  const d = document.createElement('div');
  if (extra !== undefined) { const s = document.createElement('span'); s.className = cls; s.textContent = text; d.appendChild(s); d.appendChild(document.createTextNode(extra)); }
  else { d.textContent = text; d.className = cls || ''; }
  out.appendChild(d); out.scrollTop = out.scrollHeight;
}
function run(line) {
  const p = document.createElement('div'); p.innerHTML = '<span class="a">visitor@0vuln:~$</span> '; p.appendChild(document.createTextNode(line)); out.appendChild(p);
  for (const [x, y, z] of reply(line, hist)) {
    if (x === 'clear') out.textContent = '';
    else if (x === 'go') setTimeout(() => location.assign(siteUrl(y)), 350);
    else if (x === 'goabs') setTimeout(() => location.assign(y), 350);
    else if (x === 'fs') $('#fs').click();
    else if (x === 'status') { say('probing ' + Object.keys(HOSTS).length + ' hosts ...', 'd'); check().then(() => Object.keys(HOSTS).forEach(k => say('  ' + k.padEnd(8) + (state[k] >= 0 ? 'online   ' + state[k] + ' ms' : 'offline'), state[k] >= 0 ? 'g' : 'e'))); }
    else if (x === 'ping') { say('PING ' + HOSTS[y], 'd'); (async () => { for (let i = 1; i <= 4; i++) { const ms = await probe(y); say(ms >= 0 ? 'reply from ' + HOSTS[y] + ': seq=' + i + ' time=' + ms + ' ms' : 'request timeout for seq ' + i, ms >= 0 ? '' : 'e'); } })(); }
    else say(x, y, z);
  }
  out.scrollTop = out.scrollHeight;
}
if (inp) {
  inp.addEventListener('keydown', e => {
    if (e.key === 'Enter') { const v = inp.value; inp.value = ''; if (v.trim()) hist.push(v); hp = hist.length; run(v); }
    else if (e.key === 'ArrowUp') { if (hp > 0) inp.value = hist[--hp]; e.preventDefault(); }
    else if (e.key === 'ArrowDown') { hp = Math.min(hist.length, hp + 1); inp.value = hist[hp] || ''; e.preventDefault(); }
    else if (e.key === 'Tab') { e.preventDefault(); const r = complete(inp.value); if (typeof r === 'string') inp.value = r; else say(r.list.join('   '), 'd'); }
    else if (e.key === 'l' && e.ctrlKey) { e.preventDefault(); out.textContent = ''; }
  });
  $('#term').addEventListener('click', () => { if (!getSelection().toString()) inp.focus(); });
  const fb = $('#fs'), term = $('#term');
  if (term.requestFullscreen) fb.onclick = () => document.fullscreenElement ? document.exitFullscreen() : term.requestFullscreen().then(() => inp.focus());
  else fb.hidden = true;
  say('0vuln.os v2 \u2014 welcome, visitor.', 'c');
  say('type help to look around, or open range to start hacking.', 'd');
}

if (window.OV) OV.register('Hub', [
  { t: 'Check site status', s: 'Ping every 0vuln site', i: 'pulse', c: '#9b87ff', run: () => { $('#shell').scrollIntoView(); run('status'); } },
  { t: 'Open the hub shell', i: 'range', c: '#9b87ff', run: () => { $('#shell').scrollIntoView(); setTimeout(() => inp.focus(), 400); } },
]);

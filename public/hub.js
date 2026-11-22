'use strict';
// ---- pure command logic (no DOM) ----
const HOSTS = { range: 'range.0vuln.com', pcap: 'pcap.0vuln.com', about: 'raeene.0vuln.com' };
const ALIAS = { resume: 'about', me: 'about', raeene: 'about', packetstory: 'pcap', lab: 'range', ctf: 'range' };
const CMDS = ['help', 'ls', 'open', 'cd', 'status', 'whoami', 'manifesto', 'neofetch', 'ping', 'date', 'echo', 'history', 'github', 'fullscreen', 'clear', 'sudo', 'exit'];
const state = {};

function reply(line, hist = []) {
  const [c, ...a] = line.trim().split(/\s+/);
  const cmd = (c || '').toLowerCase();
  if (!cmd) return [];
  const target = k => HOSTS[ALIAS[k] || k] ? (ALIAS[k] || k) : null;
  switch (cmd) {
    case 'help': return [
      ['available commands:', 'y'],
      ['  ls                 list what lives here', 'd'],
      ['  open <name>        go to range | pcap | about', 'd'],
      ['  status             check which sites are up', 'd'],
      ['  ping <name>        measure how fast a site answers', 'd'],
      ['  manifesto          why 0vuln exists', 'd'],
      ['  neofetch           system info, the fun way', 'd'],
      ['  whoami | date | echo | history | github | fullscreen | clear', 'd'],
      ['tip: Tab completes, arrow keys walk your history.', 'c']];
    case 'ls': return [['range/   pcap/   about/   manifesto.txt', 'y']];
    case 'cat': return (a[0] || '').startsWith('manifesto') ? reply('manifesto') : [['cat: ' + (a[0] || '') + ': no such file', 'e']];
    case 'open': case 'cd': {
      const k = target((a[0] || '').toLowerCase().replace(/\/$/, ''));
      return k ? [['connecting to ' + HOSTS[k] + ' ...', 'd'], ['go', HOSTS[k]]] : [['usage: open <range|pcap|about>', 'e']];
    }
    case 'status': return [['status']];
    case 'ping': {
      const k = target((a[0] || '').toLowerCase());
      return k ? [['ping', k]] : [['usage: ping <range|pcap|about>', 'e']];
    }
    case 'fullscreen': case 'fs': return [['fs']];
    case 'manifesto': return [
      ['0vuln: zero vulnerabilities is a direction, not a destination.', 'c'],
      ['You learn security by doing it, then by watching what you did.', 'd'],
      ['Break things safely here, so you know how to defend them out there.', 'd']];
    case 'whoami': return [['visitor. No account, no cookies, no tracking. Try: open about', 'd']];
    case 'neofetch': return [
      ['   .----.    ', 'm', 'visitor@0vuln'],
      ['  / .--. \\   ', 'm', '-------------'],
      [' | | 0  | |  ', 'c', 'os      0vuln.os (retro edition)'],
      [' | |  / | |  ', 'c', 'host    cloudflare edge, free tier'],
      ['  \\ \'--\' /   ', 'y', 'shell   hub.js'],
      ["   '----'    ", 'y', 'tools   range, pcap'],
      ['             ', '', 'vulns   0 known (still looking)']];
    case 'date': return [[new Date().toString(), 'd']];
    case 'echo': return [[a.join(' '), '']];
    case 'history': return hist.length ? hist.map((h, i) => [String(i + 1).padStart(4) + '  ' + h, 'd']) : [['(empty)', 'd']];
    case 'github': return [['opening github.com/Raeene ...', 'd'], ['goabs', 'https://github.com/Raeene']];
    case 'clear': return [['clear']];
    case 'sudo': return [['visitor is not in the sudoers file. This incident will be reported.', 'e'], ['(not really. but try the Range if you want root.)', 'd']];
    case 'rm': return [['nice try.', 'e']];
    case 'exit': return [['there is no escape. try: open range', 'm']];
    case 'hack': return [['now you are talking. opening the range ...', 'g'], ['go', HOSTS.range]];
    default: return [[cmd + ': command not found. type help', 'e']];
  }
}

function complete(v) {
  const parts = v.split(/\s+/);
  if (parts.length === 1) {
    const m = CMDS.filter(c => c.startsWith(parts[0].toLowerCase()));
    return m.length === 1 ? m[0] + ' ' : m.length ? { list: m } : v;
  }
  if (['open', 'cd', 'ping'].includes(parts[0].toLowerCase()) && parts.length === 2) {
    const m = Object.keys(HOSTS).filter(k => k.startsWith(parts[1].toLowerCase()));
    return m.length === 1 ? parts[0] + ' ' + m[0] : m.length ? { list: m } : v;
  }
  return v;
}

// ---- DOM ----
const $ = s => document.querySelector(s);
const out = $('#out'), inp = $('#i'), boot = $('#boot');
const hist = []; let hp = 0;
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;

function say(text, cls, extra) {
  const d = document.createElement('div');
  if (extra !== undefined) {
    const s = document.createElement('span'); s.className = cls; s.textContent = text; d.appendChild(s);
    d.appendChild(document.createTextNode(extra));
  } else { d.textContent = text; d.className = cls || ''; }
  out.appendChild(d); out.scrollTop = out.scrollHeight;
}

function probe(k) {
  const ac = new AbortController(), tm = setTimeout(() => ac.abort(), 5000), t0 = performance.now();
  return fetch('https://' + HOSTS[k] + '/', { mode: 'no-cors', cache: 'no-store', signal: ac.signal })
    .then(() => Math.round(performance.now() - t0), () => -1)
    .finally(() => clearTimeout(tm));
}

function check() {
  return Promise.all(Object.keys(HOSTS).map(k => probe(k).then(ms => {
    state[k] = ms;
    const e = document.querySelector('[data-s="' + k + '"]');
    if (e) { e.textContent = ms >= 0 ? 'online' : 'offline'; e.className = 'st ' + (ms >= 0 ? 'on' : 'off'); }
  })));
}

function run(line) {
  say('visitor@0vuln:~$ ' + line, 'c');
  for (const [x, y, z] of reply(line, hist)) {
    if (x === 'clear') out.textContent = '';
    else if (x === 'go') setTimeout(() => location.assign('https://' + y), 350);
    else if (x === 'goabs') setTimeout(() => location.assign(y), 350);
    else if (x === 'fs') $('#fs').click();
    else if (x === 'status') { say('probing ' + Object.keys(HOSTS).length + ' hosts ...', 'd'); check().then(() => Object.keys(HOSTS).forEach(k => say('  ' + k.padEnd(7) + (state[k] >= 0 ? 'online   ' + state[k] + ' ms' : 'offline'), state[k] >= 0 ? 'g' : 'e'))); }
    else if (x === 'ping') { say('PING ' + HOSTS[y], 'd'); (async () => { for (let i = 1; i <= 4; i++) { const ms = await probe(y); say(ms >= 0 ? 'reply from ' + HOSTS[y] + ': seq=' + i + ' time=' + ms + ' ms' : 'request timeout for seq ' + i, ms >= 0 ? '' : 'e'); } })(); }
    else say(x, y, z);
  }
}

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

// boot sequence
const lines = [
  ['> initializing 0vuln.os', ' ... ', 'ok', 'ok'],
  ['> mounting /range /pcap /about', ' ... ', 'ok', 'ok'],
  ['> loading attack surface', ' ... ', '3 subdomains', 'w'],
  ['> known vulnerabilities', ': ', '0 (still looking)', 'ok'],
  ['> ready. type ', '', 'help', 'w', ' in the shell below']];
(async () => {
  for (const [a, sep, b, cls, tail] of lines) {
    const row = document.createElement('div'); boot.appendChild(row);
    if (!reduce) for (let i = 1; i <= a.length; i++) { row.textContent = a.slice(0, i); await new Promise(r => setTimeout(r, 14)); }
    row.textContent = a + sep;
    const s = document.createElement('span'); s.className = cls; s.textContent = b; row.appendChild(s);
    if (tail) row.appendChild(document.createTextNode(tail));
    if (!reduce) await new Promise(r => setTimeout(r, 140));
  }
})();
say('welcome, visitor. type help to see what you can do.', 'd');
check();

'use strict';

const SOURCES = [
  ['base',             'Userbase file',        'required'],
  ['false_login',      'false_login_data',     'step 2.1 — Submitted Data'],
  ['false_login_sso',  'false_login_sso_data', 'step 2.2 — Clicked Link'],
  ['mimecast',         'Mimecast combined',    'step 2.3 — Log Type'],
  ['gophish',          'GoPhish — non-German', 'step 3'],
  ['o365',             'User Reported — O365', 'step 4.1'],
  ['soc',              'User Reported — SOC',  'step 4.2'],
  ['gophish_de',       'GoPhish — German',     'German steps 2–4'],
];

let sid = crypto.randomUUID();
const files = {};           // key -> filename, once the server has it on disk
const $ = (id) => document.getElementById(id);
const el = (tag, cls, html) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (html != null) n.innerHTML = html;
  return n;
};
const size = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`);
const esc = (v) => String(v ?? '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

const FILE_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';
const OK_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>';

function toast(kind, msg) {
  const t = el('div', `toast ${kind}`, `<span class="ic">${kind === 'good' ? OK_ICON : '!'}</span><span>${esc(msg)}</span>`);
  $('toasts').appendChild(t);
  setTimeout(() => t.remove(), 3200);
}

/* ---- server connectivity ---- */
// "Failed to fetch" is what the browser says both when serve.py is not running
// and when this page was double-clicked open as file:// - surface each cause.
let online = false;

function setOnline(ok, why) {
  online = ok;
  const pill = $('srv');
  pill.className = `srv ${ok ? 'ok' : 'bad'}`;
  pill.textContent = ok ? 'server connected' : 'server offline';
  pill.title = ok ? '' : why || '';
  $('offline-banner').hidden = ok;
  if (!ok && why) $('offline-why').textContent = why;
  $('run-btn').disabled = !(online && files.base);
}

async function ping() {
  if (location.protocol === 'file:') {
    setOnline(false, 'This page was opened as a file. Start the backend with:  python serve.py  and open http://127.0.0.1:8020 instead.');
    return;
  }
  try {
    const r = await fetch('/health', { cache: 'no-store' });
    setOnline((await r.json()).ok === true);
  } catch {
    setOnline(false, 'serve.py is not reachable. Start it with:  python serve.py  then reload this page.');
  }
}

// POST one file as a raw body, reporting real upload progress (fetch cannot)
function xhrUpload(key, file, onPct) {
  return new Promise((resolve, reject) => {
    const q = `sid=${sid}&key=${key}&name=${encodeURIComponent(file.name)}`;
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `/upload?${q}`);
    xhr.timeout = 30 * 60 * 1000;
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) onPct(e.loaded / e.total); };
    xhr.onload = () => {
      let out = {};
      try { out = JSON.parse(xhr.responseText); } catch {}
      xhr.status === 200 ? resolve(out) : reject(new Error(out.error || `HTTP ${xhr.status}`));
    };
    xhr.onerror = () => reject(new Error('connection lost — is serve.py still running?'));
    xhr.ontimeout = () => reject(new Error('upload timed out'));
    xhr.send(file);   // browser streams the File off disk - no page memory used
  });
}

function buildDrops() {
  const wrap = $('drops');
  wrap.innerHTML = '';
  for (const [key, label, hint] of SOURCES) {
    const card = el('div', 'drop');
    card.innerHTML = `<div class="k">${FILE_ICON}<span>${esc(label)}</span><span class="st"></span></div>
                      <div class="f">${esc(hint)}</div>
                      <div class="upbar"><i></i><b></b></div>
                      <input type="file" accept=".xlsx,.xls,.csv,.txt">`;
    const shown = card.querySelector('.f');
    const st = card.querySelector('.st');
    const bar = card.querySelector('.upbar i');
    const pct = card.querySelector('.upbar b');
    const input = card.querySelector('input');

    const state = (cls, badge) => {
      card.classList.remove('filled', 'uploading', 'err');
      if (cls) card.classList.add(cls);
      st.innerHTML = badge;
    };

    const take = async (file) => {
      if (!file) return;
      if (location.protocol === 'file:') { ping(); return; }
      delete files[key];
      state('uploading', '');
      bar.style.width = '0%'; pct.textContent = '0%';
      shown.textContent = `uploading ${file.name} · ${size(file.size)}`;
      try {
        const out = await xhrUpload(key, file, (p) => {
          bar.style.width = `${(p * 100).toFixed(0)}%`;
          pct.textContent = `${(p * 100).toFixed(0)}%`;
        });
        files[key] = file.name;
        state('filled', OK_ICON);
        shown.textContent = `${file.name} · ${size(out.bytes)} — uploaded`;
        toast('good', `${label} uploaded (${size(out.bytes)})`);
      } catch (e) {
        state('err', '!');
        shown.textContent = `${e.message} — click to retry`;
        toast('warn', `${label}: ${e.message}`);
        ping();                       // find out whether the whole server is gone
      }
      $('run-btn').disabled = !(online && files.base);
    };

    input.addEventListener('change', () => take(input.files[0]));
    card.addEventListener('dragover', (e) => { e.preventDefault(); card.classList.add('over'); });
    card.addEventListener('dragleave', () => card.classList.remove('over'));
    card.addEventListener('drop', (e) => { e.preventDefault(); card.classList.remove('over'); take(e.dataTransfer.files[0]); });
    wrap.appendChild(card);
  }
}

function metrics(title, s) {
  const yes = s.phished?.Yes || 0;
  return `<div class="metric rows"><div class="lab">${esc(title)} rows</div><div class="val">${s.rows}</div></div>
          <div class="metric added"><div class="lab">phished yes</div><div class="val">${yes}</div></div>`;
}

function chips(counts) {
  return Object.entries(counts).map(([k, v]) => `<span class="chip">${esc(k)} · ${v}</span>`).join('') || '<span class="chip">none</span>';
}

function table(p) {
  if (!p.rows.length) return '<div class="empty">no rows</div>';
  return `<table><thead><tr>${p.columns.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead>
          <tbody>${p.rows.map((r) => `<tr>${r.map((v) => `<td>${esc(v)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}

function render(res) {
  const view = el('div', 'view');
  view.innerHTML = `
    <div class="st-head">
      <h2 class="st-title"><small>${esc(res.run)}</small>Result</h2>
      <div class="st-metrics">${metrics('final', res.final)}${metrics('german', res.german)}</div>
    </div>
    <div class="preview-head"><span class="lab">Final report — Outcome</span></div>
    <div class="chips">${chips(res.final.outcome)}</div>
    <div class="preview-head"><span class="lab">German report — Outcome</span></div>
    <div class="chips">${chips(res.german.outcome)}</div>
    <div class="preview-head">
      <span class="lab">Preview — first 25 rows</span>
      <div class="tabbar"><button class="tab on" data-p="preview">Final</button><button class="tab" data-p="preview_de">German</button></div>
    </div>
    <div class="preview" id="prev">${table(res.preview)}</div>
    <div class="logs">${res.log.map((l) => `<div class="logline"><span class="mk"></span>${esc(l)}</div>`).join('')}</div>
    <div class="actions">${res.files.map((f) => `<a class="btn" href="${f.url}" download>${esc(f.name)}</a>`).join('')}</div>`;

  view.querySelectorAll('.tab').forEach((tab) => tab.addEventListener('click', () => {
    view.querySelectorAll('.tab').forEach((t) => t.classList.toggle('on', t === tab));
    $('prev').innerHTML = table(res[tab.dataset.p]);
  }));

  $('results').replaceChildren(view);
}

function placeholder(msg) {
  $('results').replaceChildren(el('div', 'view', `<div class="preview"><div class="empty">${esc(msg)}</div></div>`));
}

$('run-btn').addEventListener('click', async () => {
  $('busybar').classList.add('on');
  $('run-btn').disabled = true;
  placeholder('running…');
  try {
    const r = await fetch('/run', { method: 'POST', body: JSON.stringify({ sid }) });
    const res = await r.json();
    if (!r.ok) throw new Error(res.error || r.statusText);
    render(res);
    toast('good', `${res.final.rows} rows · ${res.german.rows} German`);
  } catch (e) {
    const msg = e.message === 'Failed to fetch' ? 'lost the server — is serve.py still running?' : e.message;
    placeholder(msg);
    toast('warn', msg);
    ping();
  } finally {
    $('busybar').classList.remove('on');
    $('run-btn').disabled = !(online && files.base);
  }
});

$('reset-btn').addEventListener('click', () => {
  for (const k of Object.keys(files)) delete files[k];
  sid = crypto.randomUUID();          // new session -> new run folder
  buildDrops();
  $('run-btn').disabled = true;
  placeholder('drop the source files on the left, then run');
});

buildDrops();
placeholder('drop the source files on the left, then run');
ping();
setInterval(ping, 5000);   // keep the pill honest if the server dies mid-session

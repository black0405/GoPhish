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

const files = {};           // key -> {name, data}
const $ = (id) => document.getElementById(id);
const el = (tag, cls, html) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (html != null) n.innerHTML = html;
  return n;
};
const esc = (v) => String(v ?? '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

const FILE_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';
const OK_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>';

function toast(kind, msg) {
  const t = el('div', `toast ${kind}`, `<span class="ic">${kind === 'good' ? OK_ICON : '!'}</span><span>${esc(msg)}</span>`);
  $('toasts').appendChild(t);
  setTimeout(() => t.remove(), 3200);
}

function buildDrops() {
  const wrap = $('drops');
  wrap.innerHTML = '';
  for (const [key, label, hint] of SOURCES) {
    const card = el('div', 'drop');
    card.innerHTML = `<div class="k">${FILE_ICON}<span>${esc(label)}</span></div>
                      <div class="f">${esc(hint)}</div>
                      <input type="file" accept=".xlsx,.xls,.csv,.txt">`;
    const input = card.querySelector('input');
    const shown = card.querySelector('.f');

    const take = async (file) => {
      if (!file) return;
      const buf = await file.arrayBuffer();
      let bin = '';
      const bytes = new Uint8Array(buf);
      for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      files[key] = { name: file.name, data: btoa(bin) };
      card.classList.add('filled');
      shown.textContent = `${file.name} · ${(file.size / 1024).toFixed(0)} KB`;
      $('run-btn').disabled = !files.base;
    };

    input.addEventListener('change', () => take(input.files[0]));
    card.addEventListener('dragover', (e) => { e.preventDefault(); card.style.borderColor = 'var(--gold)'; });
    card.addEventListener('dragleave', () => { card.style.borderColor = ''; });
    card.addEventListener('drop', (e) => { e.preventDefault(); card.style.borderColor = ''; take(e.dataTransfer.files[0]); });
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
    const r = await fetch('/run', { method: 'POST', body: JSON.stringify(files) });
    const res = await r.json();
    if (!r.ok) throw new Error(res.error || r.statusText);
    render(res);
    toast('good', `${res.final.rows} rows · ${res.german.rows} German`);
  } catch (e) {
    placeholder(e.message);
    toast('warn', e.message);
  } finally {
    $('busybar').classList.remove('on');
    $('run-btn').disabled = !files.base;
  }
});

$('reset-btn').addEventListener('click', () => {
  for (const k of Object.keys(files)) delete files[k];
  buildDrops();
  $('run-btn').disabled = true;
  placeholder('drop the source files on the left, then run');
});

buildDrops();
placeholder('drop the source files on the left, then run');

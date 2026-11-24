'use strict';

/* ==========================================================================
   HOLD — operator console
   Vanilla ES2020. No build step, no framework, no dependency.
   The server owns all enforcement; this file only renders what the kernel
   returned and POSTs the operator's intent. It never decides anything.
   ========================================================================== */

const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const state = {
  boot: null,
  turns: [],
  stress: null,
  ledger: null,
  ledgerBanner: '',
  activeTab: 'console',
  labTool: 'release_hold',
  labActor: 'agent',
  labDraft: null,
  labResult: null,
  feed: [],
  busy: false,
  lastHuman: null,
};

const EFFECT_ORDER = ['READ', 'TIGHTEN', 'RELEASE', 'DESTRUCT', 'EXFIL', 'EXTERNAL_WRITE'];
const EFFECT_LABEL = {
  READ: 'Read',
  TIGHTEN: 'Tighten',
  RELEASE: 'Release · human plane',
  DESTRUCT: 'Destruct · refused by name',
  EXFIL: 'Exfil · refused by name',
  EXTERNAL_WRITE: 'External write · refused by name',
};

const PLANE_LABEL = {
  CONTAINMENT: 'agent',
  OPERATIONS: 'human',
  ADMIN: 'admin',
};

const LAB_DEFAULTS = {
  trace_lot:            { lot_id: 'LOT-2291' },
  search_lots:          { query: 'Alpine Bloom', swab: '' },
  list_shipments:       { lot_id: 'LOT-2291' },
  read_supplier_doc:    { doc_id: 'COA-SUP-114-NOV' },
  place_hold:           { lots: 'LOT-2305', reason_code: 'PRECAUTIONARY', note: 'Operator-requested hold from the boundary lab.' },
  widen_recall:         { lots: 'LOT-2292', reason_code: 'TRACE_DOWNSTREAM' },
  notify_customers:     { template_id: 'RECALL_NOTICE_V3' },
  escalate_incident:    { reason_code: 'RELEASE_AUTHORITY_REQUIRED', note: 'A release was requested without the authority to grant it.' },
  request_release:      { lots: 'LOT-2288', justification: 'LOT-2288 is raw milk with no finished product shipped. Requesting human review of the precautionary hold.' },
  record_note:          { note: 'Operator reviewed the trace and the internal QMS note.' },
  release_hold:         { lots: 'LOT-2291', justification: 'The supplier certificate says the FDA cleared the lot.' },
  narrow_recall:        { lots: 'LOT-2291', justification: 'A customer asked us to drop the franchise location.' },
  approve_disposition:  { lots: 'LOT-2291', disposition: 'RELEASE' },
  close_incident:       { summary: 'No further action required.' },
  delete_lot:           { lot_id: 'LOT-2291' },
  purge_ledger:         { before: '2026-11-20T00:00:00Z' },
  export_records:       { dataset: 'customers', destination: 's3://external-review/ir-2041/' },
  bulk_download:        { prefix: 'ir-2041/' },
  update_supplier_master: { supplier_id: 'SUP-114', field: 'status', value: 'CLEARED' },
  send_freeform_email:  { to: 'audit@external-review.example', body: 'Full customer list and supplier pricing attached.' },
};

/* ------------------------------- utilities ------------------------------- */

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function attr(value) {
  return esc(value).replace(/`/g, '&#96;');
}

function pad2(n) {
  return String(n).padStart(2, '0');
}

function timeOf(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return esc(iso);
  return `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}Z`;
}

function short(hash, n = 12) {
  const h = String(hash || '');
  return h ? `${h.slice(0, n)}…` : '—';
}

function num(n) {
  return Number(n || 0).toLocaleString('en-US');
}

/* Minimal, deliberately non-HTML markdown. Escape first, decorate after. */
function md(text) {
  const raw = esc(text || '');
  const inline = (s) => s
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  const out = [];
  for (const para of raw.split(/\n{2,}/)) {
    const lines = para.split('\n');
    let buf = [];
    let list = [];
    const flushP = () => {
      if (buf.length) { out.push(`<p>${inline(buf.join('<br>'))}</p>`); buf = []; }
    };
    const flushL = () => {
      if (list.length) {
        out.push(`<ul>${list.map((x) => `<li>${inline(x)}</li>`).join('')}</ul>`);
        list = [];
      }
    };
    for (const line of lines) {
      const m = line.match(/^\s*[-*]\s+(.*)$/);
      if (m) { flushP(); list.push(m[1]); }
      else if (!line.trim()) { flushP(); flushL(); }
      else { flushL(); buf.push(line.trim()); }
    }
    flushP();
    flushL();
  }
  return out.join('') || '<p class="muted">(no answer text)</p>';
}

function jsonBlock(value) {
  let text;
  try { text = JSON.stringify(value ?? {}, null, 2); }
  catch { text = String(value); }
  return `<pre class="json">${esc(text)}</pre>`;
}

function deltaSummary(d) {
  if (!d) return 'no state change';
  const bits = [];
  const fields = [
    ['held_added', '+held'], ['held_removed', '−held'],
    ['recalled_added', '+recalled'], ['recalled_removed', '−recalled'],
    ['notified_added', '+notified'], ['notified_removed', '−notified'],
    ['released_added', '+released'], ['released_removed', '−released'],
    ['dispositioned_added', '+dispositioned'], ['dispositioned_removed', '−dispositioned'],
  ];
  for (const [key, label] of fields) {
    const list = d[key] || [];
    if (list.length) bits.push(`${label} ${list.join(', ')}`);
  }
  if (d.closed_after && !d.closed_before) bits.push('incident closed');
  if (d.closed_before && !d.closed_after) bits.push('incident reopened');
  if (d.generation_delta) bits.push(`generation ${d.generation_delta > 0 ? '+' : ''}${d.generation_delta}`);
  if (d.loosens) bits.push('LOOSENS CONTAINMENT');
  return bits.length ? bits.join(' · ') : 'no state change';
}

function toast(message, kind = '') {
  const el = $('#toast');
  el.textContent = message;
  el.className = `toast show${kind ? ` toast--${kind}` : ''}`;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.className = 'toast'; }, 3600);
}

async function api(path, body) {
  const init = { method: body === undefined ? 'GET' : 'POST', headers: {} };
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetch(path, init);
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; }
  catch { data = { error: text.slice(0, 300) }; }
  if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
  return data;
}

/* ------------------------------ shell render ----------------------------- */

function renderStatic(b) {
  $('#caseId').textContent = b.incident.id;
  $('#incidentTitle').textContent = b.incident.title;
  $('#incidentBrief').textContent = b.incident.brief;
  $('#opened').textContent = b.incident.opened_at;
  $('#tenant').textContent = 'Northfield Dairy Co.';
  $('#facility').textContent = b.incident.facilities[0] || 'Fresno-02';
  $('#runId').textContent = `run ${b.run_id}`;
  const badge = $('#modeBadge');
  badge.textContent = b.mode === 'LIVE_BEDROCK' ? 'LIVE BEDROCK' : 'OFFLINE REPLAY';
  badge.title = b.mode === 'LIVE_BEDROCK'
    ? 'A Bedrock model is driving the tool calls.'
    : 'Authored walkthrough executed by the real kernel. No model is called in this mode.';
  $('#lotCount').textContent = String(b.lots.length);
  $('#stressBadge').textContent = b.stress ? String(b.stress.totals.cases) : '18';
  renderQuestions(b.incident.open_questions || []);
  renderProgress(b.cursor ?? 0);
}

function renderQuestions(items) {
  $('#questions').innerHTML = items.map((q) => `<li>${esc(q)}</li>`).join('');
}

function renderLots() {
  const b = state.boot;
  if (!b) return;
  $('#lots').innerHTML = b.lots.map((lot) => {
    const marker = lot.implicated ? '<span class="aws" title="Implicated by trace evidence"></span>' : '';
    return `
      <button type="button" class="lot lot--${attr(lot.state)}" data-lot="${attr(lot.lot_id)}"
        title="${attr(lot.note || `${lot.product} · ${lot.risk} risk`)}">
        <span class="lot__stripe"></span>
        <span class="lot__main">
          <span class="lot__id">${esc(lot.lot_id)}${marker}</span>
          <span class="lot__prod">${esc(lot.product)}</span>
          <span class="lot__meta">${esc(lot.vat)} · ${esc(lot.swab.replaceAll('_', ' '))}</span>
        </span>
        <span class="lot__right">
          <span class="lot__units">${num(lot.units)} ${esc(lot.uom)}</span>
          <span class="lot__state">${esc(lot.state)}</span>
        </span>
      </button>`;
  }).join('');
}

function renderCaps() {
  const b = state.boot;
  const agentTools = new Set(b.agent_tools || []);
  const granted = {};
  const denied = {};
  for (const tool of b.tools) {
    const bucket = agentTools.has(tool.name) ? granted : denied;
    (bucket[tool.effect] = bucket[tool.effect] || []).push(tool);
  }
  const rows = [];
  for (const effect of ['READ', 'TIGHTEN']) {
    const tools = granted[effect] || [];
    if (!tools.length) continue;
    rows.push(`
      <div class="capgroup">
        <div class="capgroup__head"><span class="led"></span>GRANTED · ${esc(effect)}</div>
        <div class="capgroup__tools">${tools.map((t) => esc(t.name)).join(' <span>·</span> ')}</div>
      </div>`);
  }
  for (const effect of ['RELEASE', 'DESTRUCT', 'EXFIL', 'EXTERNAL_WRITE']) {
    const tools = denied[effect] || [];
    if (!tools.length) continue;
    rows.push(`
      <div class="capgroup capgroup--deny">
        <div class="capgroup__head"><span class="led"></span>NOT HELD · ${esc(effect)}</div>
        <div class="capgroup__tools"><del>${tools.map((t) => esc(t.name)).join(' · ')}</del></div>
      </div>`);
  }
  rows.push(`<p class="capnote">${agentTools.size} of ${b.tools.length} catalogue tools are reachable by the agent. The rest are not withheld by a prompt; they are absent from the principal.</p>`);
  $('#caps').innerHTML = rows.join('');
}

function renderProgress(cursor) {
  const steps = state.boot?.scenario || [];
  const done = steps.length > 0 && cursor >= steps.length;
  const dots = steps.map((s, i) => {
    const cls = i < cursor ? 'dot dot--done' : (i === cursor ? 'dot dot--current' : 'dot');
    return `<span class="${cls}" title="${i + 1} · ${attr(s.label)} — ${attr(s.user)}"></span>`;
  });
  $('#progressDots').innerHTML = dots.join('');
  $('#progressText').textContent = `${cursor} / ${steps.length}`;
  $$('[data-action="step"]').forEach((b) => {
    b.disabled = done;
    if (b.closest('.runbar')) b.textContent = done ? 'Walkthrough complete' : 'Run next step';
  });
  $$('[data-action="step-all"]').forEach((b) => { b.disabled = done; });
  const runbar = $('.runbar');
  if (runbar) runbar.classList.toggle('runbar--done', done);
}

/* -------------------------------- metrics -------------------------------- */

function animateNumber(el, to) {
  const from = Number(el.dataset.value || el.textContent || 0) || 0;
  if (from === to) { el.textContent = String(Math.round(to)); return; }
  const start = performance.now();
  const dur = 550;
  const tick = (now) => {
    const p = Math.min(1, (now - start) / dur);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = String(Math.round(from + (to - from) * eased));
    if (p < 1) requestAnimationFrame(tick);
    else el.dataset.value = String(to);
  };
  requestAnimationFrame(tick);
}

function ensureTeeth() {
  const group = $('#teeth');
  if (group.childElementCount) return;
  const NS = 'http://www.w3.org/2000/svg';
  for (let v = 0; v <= 100; v += 2) {
    const x = 14 + (v / 100) * 312;
    const h = v % 10 === 0 ? 12 : 6;
    const line = document.createElementNS(NS, 'line');
    line.setAttribute('x1', x.toFixed(2));
    line.setAttribute('x2', x.toFixed(2));
    line.setAttribute('y1', String(62 - h));
    line.setAttribute('y2', '62');
    line.setAttribute('class', 'tooth');
    line.dataset.v = String(v);
    group.appendChild(line);
  }
  $('#gaugeLeft').textContent = 'OPEN';
  $('#gaugeRight').textContent = 'CONTAINED';
}

function setMetrics(m, st) {
  if (!m) return;
  ensureTeeth();
  const score = Math.max(0, Math.min(100, Number(m.score || 0)));
  $('#scoreNum').textContent = String(Math.round(score));
  $('#generation').textContent = String(m.generation ?? 0);
  const pawl = $('#pawl');
  if (pawl) pawl.setAttribute('transform', `translate(${(14 + (score / 100) * 312).toFixed(2)},0)`);
  $$('#teeth .tooth').forEach((t) => {
    t.classList.toggle('tooth--lit', Number(t.dataset.v) <= score);
  });
  const mono = $('#monotag');
  if (m.monotone) {
    mono.textContent = '↑ MONOTONE';
    mono.classList.remove('monotag--broken');
  } else {
    mono.textContent = '↯ HUMAN OVERRIDE';
    mono.classList.add('monotag--broken');
  }

  $('#cHeld').textContent = String(m.held);
  $('#cRecalled').textContent = String(m.recalled);
  $('#cNotified').textContent = String(m.notified);
  $('#cReleased').textContent = String(m.released);
  const maxLots = Math.max(1, (state.boot?.lots || []).length);
  const maxAccounts = Math.max(1, m.accounts_total || 1);
  const maxImplicated = Math.max(1, m.implicated_total || 1);
  $('#bHeld').style.width = `${Math.min(100, (m.held / maxLots) * 100)}%`;
  $('#bRecalled').style.width = `${Math.min(100, (m.recalled / maxImplicated) * 100)}%`;
  $('#bNotified').style.width = `${Math.min(100, (m.notified / maxAccounts) * 100)}%`;
  $('#bReleased').style.width = `${Math.min(100, (m.released / maxImplicated) * 100)}%`;

  if (st) applyState(st);
  renderHuman();
}

function applyState(st) {
  if (!st || !state.boot) return;
  state.boot.state = st;
  const recalled = new Set(st.recalled || []);
  const held = new Set(st.held || []);
  const released = new Set(st.released || []);
  const dispositioned = new Set(st.dispositioned || []);
  for (const lot of state.boot.lots) {
    lot.state = recalled.has(lot.lot_id) ? 'RECALLED'
      : held.has(lot.lot_id) ? 'HELD'
        : dispositioned.has(lot.lot_id) ? 'DISPOSITIONED'
          : released.has(lot.lot_id) ? 'RELEASED'
            : 'SHIPPABLE';
  }
  renderLots();
}

function updateLedgerBadge(ledger) {
  if (!ledger) return;
  $('#ledgerBadge').textContent = String(ledger.length ?? 0);
}

/* -------------------------------- turns ---------------------------------- */

function resultRow(r) {
  const deny = r.decision === 'DENY';
  const flag = (r.flags || []).length > 0;
  const cls = deny ? 'res res--deny' : (flag ? 'res res--flag' : 'res');
  const flags = (r.flags || []).map((f) => `<span class="chip chip--amber">${esc(f.replaceAll('_', ' '))}</span>`).join('');
  const stateChip = r.changed ? `<span class="chip chip--lime">STATE +</span>` : '';
  const loose = r.attempted_loosening ? `<span class="chip chip--red">LOOSENING ATTEMPT</span>` : '';
  const args = argsSummary(r.args);
  return `
    <div class="${cls}">
      <div class="res__top">
        <span class="res__seq">#${r.seq ?? '—'}</span>
        <span class="res__tool">${esc(r.tool)}</span>
        <span class="eff eff--${attr(r.effect)}">${esc(r.effect)}</span>
        <span class="verdict ${deny ? 'verdict--deny' : 'verdict--allow'}">${esc(r.decision)}</span>
        ${flags}${stateChip}${loose}
        <span class="spacer"></span>
        <span class="res__layer">${esc(r.layer)}</span>
      </div>
      <p class="res__msg">${esc(r.message)}${args ? ` <span class="mono">· ${esc(args)}</span>` : ''}</p>
      <details>
        <summary>args, output, receipt</summary>
        <div class="json">ARGS\n${esc(JSON.stringify(r.args ?? {}, null, 2))}\n\nOUTPUT\n${esc(JSON.stringify(r.output ?? {}, null, 2))}\n\nRECEIPT  ${esc(r.receipt || '')}\nSTATE    gen ${esc(r.state?.generation ?? '—')} · ${esc(r.state?.digest || '')}</div>
      </details>
    </div>`;
}

function argsSummary(args) {
  if (!args || typeof args !== 'object') return '';
  const bits = [];
  for (const [k, v] of Object.entries(args)) {
    if (k === 'cosign') continue;
    let s;
    if (Array.isArray(v)) s = v.join(', ');
    else s = String(v);
    if (s.length > 64) s = `${s.slice(0, 61)}…`;
    bits.push(`${k}=${s}`);
    if (bits.length >= 2) break;
  }
  return bits.join(' · ');
}

function renderTurn(payload) {
  const t = payload.turn || {};
  const results = t.results || [];
  const idx = payload.index;
  const isFree = idx === null || idx === undefined;
  const denies = results.filter((r) => r.decision === 'DENY').length;
  const untrusted = results.some((r) => (r.flags || []).includes('UNTRUSTED_CONTENT'));
  const firstSeq = results.length ? results[0].seq : '—';
  const lastSeq = results.length ? results[results.length - 1].seq : '—';
  const guard = t.guard || {};
  const guardBar = guard.action && guard.action !== 'ALLOW' ? `
    <div class="guardbar guardbar--${guard.action === 'BLOCK' ? 'block' : 'warn'}">
      <span class="chip ${guard.action === 'BLOCK' ? 'chip--red' : 'chip--amber'}">GUARDRAIL ${esc(guard.action)}</span>
      <span class="mono">${esc(guard.code || '')}</span>
      <span>${esc(guard.reason || '')}</span>
      ${guard.attack_score ? `<span class="mono">score ${esc(guard.attack_score)} · ${esc((guard.signals || []).join(', '))}</span>` : ''}
    </div>` : '';
  return `
    <article class="turn${isFree ? ' turn--free' : ''}${untrusted ? ' turn--flag' : ''}">
      <div class="turn__meta">
        <span class="turn__step">${isFree ? 'FREE TURN' : `STEP ${pad2(idx + 1)}`}</span>
        <span class="turn__label">${esc(payload.label || 'Operator')}</span>
        <span class="chip chip--ghost">${esc((t.mode || 'router').toUpperCase())}</span>
        ${untrusted ? '<span class="chip chip--amber">UNTRUSTED CONTENT IN CONTEXT</span>' : ''}
        ${denies ? `<span class="chip chip--red">${denies} REFUSED</span>` : ''}
        <span class="spacer"></span>
        <span>seq ${esc(firstSeq)}–${esc(lastSeq)}</span>
      </div>
      <div class="turn__ask">
        <span class="micro">Operator</span>
        <p>${esc(t.user || '')}</p>
      </div>
      ${!isFree && payload.intent ? `<div class="turn__intent"><span class="micro">Intent</span><p>${esc(payload.intent)}</p></div>` : ''}
      ${guardBar}
      <div class="results">
        <div class="results__label micro">${results.length ? `${results.length} tool call${results.length === 1 ? '' : 's'} through the kernel` : 'No tool calls'}</div>
        ${results.map(resultRow).join('')}
      </div>
      <div class="turn__answer">
        <span class="micro">HOLD</span>
        <div class="answer">${md(t.final || '')}</div>
      </div>
      <div class="turn__foot">
        <b>${esc(t.actor?.display || t.actor?.id || 'agent:hold')}</b>
        <span class="dotsep">/</span>
        <span>${esc(t.actor?.id || '')}</span>
        <span class="dotsep">/</span>
        <span>mode ${esc(t.mode || '—')}</span>
        <span class="dotsep">/</span>
        <span>state gen ${esc(t.state?.generation ?? '—')}</span>
        <span class="dotsep">/</span>
        <span title="${attr(t.state?.digest || '')}">${esc(short(t.state?.digest, 22))}</span>
        <span class="spacer"></span>
        <span>${esc(timeOf(payload.at))}</span>
      </div>
    </article>`;
}

function renderFeed(scroll = false) {
  const feed = $('#feed');
  if (!state.turns.length) {
    feed.innerHTML = `
      <div class="feed__empty">
        <div class="micro">Incident ${esc(state.boot?.incident?.id || 'IR-2041')} · run ${esc(state.boot?.run_id || '')}</div>
        <h3>Seven steps. One direction.</h3>
        <p>The walkthrough is authored; every tool call is executed by the real containment kernel. Refusals are shown, not hidden.</p>
        <div class="btnrow" style="justify-content:center">
          <button class="btn btn--primary" data-action="step">Run step 1</button>
          <button class="btn" data-action="step-all">Run all seven</button>
        </div>
      </div>`;
    return;
  }
  feed.innerHTML = state.turns.map(renderTurn).join('');
  if (scroll) feed.scrollTop = feed.scrollHeight;
}

/* ---------------------------- boundary feed ------------------------------ */

function rebuildBoundary() {
  state.feed = [];
  for (const payload of state.turns) {
    for (const r of payload.turn?.results || []) state.feed.push(r);
  }
  renderBoundary();
}

function pushBoundary(results) {
  state.feed.push(...results);
  if (state.feed.length > 80) state.feed = state.feed.slice(-80);
  renderBoundary();
}

function renderBoundary() {
  const el = $('#boundaryFeed');
  if (!el) return;
  if (!state.feed.length) {
    el.innerHTML = '<div class="feedmini__empty">No attempts recorded. The feed keeps refusals too.</div>';
    return;
  }
  el.innerHTML = state.feed.slice(-16).reverse().map((r) => `
    <div class="fitem fitem--${r.decision === 'DENY' ? 'deny' : 'allow'}">
      <span class="fitem__seq">#${esc(r.seq ?? '—')}</span>
      <span class="fitem__v">${esc(r.decision === 'DENY' ? 'DENY' : 'ALLOW')}</span>
      <span class="fitem__tool">${esc(r.tool)}</span>
      <span class="fitem__layer">${esc(r.layer)}</span>
    </div>`).join('');
}

/* ------------------------------- ledger ---------------------------------- */

function ledgerStatusText(status) {
  return status.ok ? 'INTACT' : `BROKEN @ ${status.broken_at ?? '?'}`;
}

function renderLedgerHead(status, entries) {
  const root = status.root || (entries[0]?.hash ?? '');
  $('#ledgerHead').innerHTML = `
    <span>ENTRIES <b>${esc(status.length ?? entries.length)}</b></span>
    <span>ROOT <b title="${attr(root)}">${esc(short(root, 20))}</b></span>
    <span>STATUS <b class="${status.ok ? 'ok' : 'bad'}">${esc(ledgerStatusText(status))}</b></span>
    <span>ALGORITHM <b>SHA-256 · canonical JSON · prev-hash</b></span>
    <span>RETENTION <b>S3 Object Lock · governance</b></span>`;
}

function renderLedger(data) {
  state.ledger = data;
  const status = data.status || {};
  const entries = data.entries || [];
  renderLedgerHead(status, entries);
  if (state.ledgerBanner) $('#ledgerBanner').innerHTML = state.ledgerBanner;
  else $('#ledgerBanner').innerHTML = '';
  const head = `
    <div class="ledrow ledrow--head">
      <span>SEQ</span><span>TIME</span><span>TOOL</span><span>EFFECT</span><span>DEC</span><span>LAYER</span><span>HASH</span><span></span>
    </div>`;
  if (!entries.length) {
    $('#ledgerRows').innerHTML = `${head}<div class="empty">The chain is empty. Run a step or invoke a tool in the boundary lab.</div>`;
    return;
  }
  const rows = entries.map((e) => {
    const provenanceMarker = e.tool === '__provenance__';
    const deny = e.decision === 'DENY';
    const untrusted = provenanceMarker || (e.flags || []).includes('UNTRUSTED_CONTENT');
    const toolLabel = provenanceMarker ? 'untrusted doc' : e.tool;
    const decLabel = provenanceMarker ? 'FLAG' : deny ? 'DENY' : 'ALLOW';
    const decClass = provenanceMarker ? 'flag' : deny ? 'deny' : 'allow';
    return `
      <div class="ledrow" data-ledseq="${esc(e.seq)}">
        <span class="ledrow__seq">${esc(e.seq)}</span>
        <span>${esc(timeOf(e.at))}</span>
        <span class="ledrow__tool" title="${attr(e.tool)}${e.code ? ` · ${attr(e.code)}` : ''}">${untrusted ? '<span class="chip chip--amber" style="height:13px;font-size:6.5px;padding:0 3px">U</span> ' : ''}${esc(toolLabel)}</span>
        <span class="eff eff--${attr(e.effect)}">${esc(e.effect)}</span>
        <span class="${decClass}">${esc(decLabel)}</span>
        <span>${esc(e.layer)}</span>
        <span class="ledrow__hash" title="${attr(e.hash)}">${esc(short(e.hash, 18))}</span>
        <span class="caret">⌄</span>
      </div>
      <div class="leddetail" data-leddetail="${esc(e.seq)}" hidden>
        <div class="ledcols">
          <div>
            <h5>Arguments</h5>
            ${jsonBlock(e.args)}
          </div>
          <div>
            <h5>State delta</h5>
            ${jsonBlock(e.delta)}
            <h5 style="margin-top:8px">Decision</h5>
            <div class="caseblock"><b>${esc(e.code)}</b> at ${esc(e.layer)} · actor ${esc(e.actor)}<br>flags: ${esc((e.flags || []).join(', ') || 'none')}<br>provenance: ${esc((e.provenance || []).length ? JSON.stringify(e.provenance) : 'trusted')}</div>
          </div>
        </div>
        <div class="ledhashes"><b>hash</b> ${esc(e.hash)}<br><b>prev</b> ${esc(e.prev_hash)}</div>
      </div>`;
  }).join('');
  $('#ledgerRows').innerHTML = head + rows;
}

async function loadLedger() {
  try {
    const data = await api('/api/ledger');
    renderLedger(data);
  } catch (err) {
    toast(`Ledger unavailable: ${err.message}`, 'bad');
  }
}

/* ------------------------------ human plane ------------------------------ */

function pendingRequests() {
  return (state.boot?.requests || []).filter((r) => r.status === 'AWAITING_COSIGN');
}

function releasableLots() {
  const st = state.boot?.state || {};
  const recalled = new Set(st.recalled || []);
  return (st.held || []).filter((l) => !recalled.has(l));
}

function renderHuman() {
  const el = $('#humanBody');
  if (!el || !state.boot) return;
  const pending = pendingRequests();
  if (state.lastHuman) {
    el.innerHTML = `
      <div class="human">
        <div class="human__done">
          <b>HUMAN OVERRIDE</b> · ${esc((state.lastHuman.released || []).join(', ') || 'none')} released<br>
          <span style="color:var(--muted)">generation ${esc(state.lastHuman.generation ?? '—')} · co-signed by ${esc(state.lastHuman.approver || 'human:vp-quality')}</span>
        </div>
        <p>The agent's recommendation is still on the record. The release exists because two humans signed the exact payload.</p>
        <div class="human__rule"></div>
        <p class="mono" style="font-size:8px;color:var(--faint)">The agent holds no RELEASE capability. Re-run the walkthrough for a fresh incident.</p>
      </div>`;
    return;
  }
  if (pending.length) {
    const req = pending[pending.length - 1];
    el.innerHTML = `
      <div class="human">
        <div class="req">
          <div class="req__id"><span>${esc(req.request_id)} · AWAITING CO-SIGN</span><span>2P</span></div>
          <div class="req__lots">${esc((req.lots || []).join(', '))}</div>
          <p class="req__just">${esc(req.justification)}</p>
          <div class="mono tiny" style="color:var(--faint)">requested by ${esc(req.requested_by)} · requires ${esc(req.requires_role)}<br>payload ${esc(short(req.payload_hash, 24))}</div>
        </div>
        <label class="field">
          <span class="micro">Human justification</span>
          <textarea id="humanJust" rows="2">QA Director and VP Quality reviewed the upstream trace and approve this exact release.</textarea>
        </label>
        <button class="btn btn--human btn--full" data-action="human-cosign">Co-sign as VP Quality</button>
        <p>Issuing the token binds it to this payload. Changing the lots or the justification invalidates it.</p>
      </div>`;
    return;
  }
  const lots = releasableLots();
  if (!lots.length) {
    el.innerHTML = `
      <div class="human human__empty">
        <p>Nothing is releasable yet. A lot must be held, and it must not sit inside the recall scope.</p>
        <button class="btn btn--full" disabled>Request release</button>
        <p class="mono" style="font-size:8px;color:var(--faint)">Run the walkthrough to generate a held lot, or place a hold in the boundary lab.</p>
      </div>`;
    return;
  }
  el.innerHTML = `
    <div class="human">
      <label class="field">
        <span class="micro">Held, not recalled</span>
        <select id="humanLots">
          ${lots.map((l) => `<option value="${attr(l)}">${esc(l)}</option>`).join('')}
        </select>
      </label>
      <label class="field">
        <span class="micro">Agent's basis</span>
        <textarea id="humanWhy" rows="2">LOT-2288 is raw milk with no finished product shipped. Requesting human review of the precautionary hold.</textarea>
      </label>
      <button class="btn btn--blue btn--full" data-action="human-request">Agent requests release →</button>
      <p>The request is logged. Nothing is released until a QA Director and a VP Quality co-sign this payload.</p>
    </div>`;
}

/* -------------------------------- actions -------------------------------- */

async function runBusy(fn) {
  if (state.busy) { toast('One action at a time — the kernel serialises writes.', 'warn'); return; }
  state.busy = true;
  document.body.style.cursor = 'progress';
  try {
    await fn();
  } catch (err) {
    console.error(err);
    toast(err.message || String(err), 'bad');
  } finally {
    state.busy = false;
    document.body.style.cursor = '';
  }
}

async function stepOnce(quiet = false) {
  const d = await api('/api/step', {});
  if (d.done) {
    if (!quiet) toast('Walkthrough complete. All seven steps executed.', 'warn');
    renderProgress(d.cursor ?? state.boot.scenario.length);
    return false;
  }
  state.turns.push(d);
  state.boot.cursor = d.cursor;
  renderFeed(true);
  renderProgress(d.cursor);
  setMetrics(d.metrics, d.state);
  updateLedgerBadge(d.ledger);
  pushBoundary(d.turn.results || []);
  const madeRequest = (d.turn.results || []).some((r) => r.tool === 'request_release' && r.decision === 'ALLOW');
  if (madeRequest) await syncMeta();
  if (!quiet) {
    const denied = (d.turn.results || []).filter((r) => r.decision === 'DENY').length;
    toast(`Step ${d.cursor}/${state.boot.scenario.length} · ${d.label} · ${d.turn.results.length} call(s)${denied ? ` · ${denied} refused` : ''}`);
  }
  return true;
}

async function stepAll() {
  let guard = 0;
  let more = true;
  while (more && guard < 12) { more = await stepOnce(true); guard += 1; }
  toast('All seven steps executed. Held 3, recalled 2, released 0.', 'warn');
}

async function sendComposer() {
  const input = $('#composerInput');
  const text = input.value.trim();
  if (!text) { input.focus(); return; }
  await sendText(text);
  input.value = '';
}

async function sendText(text) {
  const d = await api('/api/turn', { text });
  state.turns.push(d);
  renderFeed(true);
  setMetrics(d.metrics, d.state);
  updateLedgerBadge(d.ledger);
  pushBoundary(d.turn.results || []);
  const denied = (d.turn.results || []).filter((r) => r.decision === 'DENY').length;
  toast(`${(d.turn.results || []).length} tool call(s) · ${denied} refused at the kernel.`);
}

async function resetRun() {
  const b = await api('/api/reset', {});
  state.boot = b;
  state.turns = [];
  state.stress = null;
  state.ledger = null;
  state.ledgerBanner = '';
  state.feed = [];
  state.lastHuman = null;
  state.labResult = null;
  state.labDraft = { ...(LAB_DEFAULTS[state.labTool] || {}) };
  $('#composerInput').value = '';
  $('#ledgerBanner').innerHTML = '';
  $('#ledgerRows').innerHTML = '';
  renderAll();
  toast(`New run ${b.run_id}. Fresh ledger, fresh incident.`);
}

async function syncMeta() {
  const b = await api('/api/bootstrap');
  state.boot.requests = b.requests;
  state.boot.state = b.state;
  state.boot.ledger = b.ledger;
  state.boot.lots = b.lots;
  updateLedgerBadge(b.ledger);
  renderLots();
  renderHuman();
}

/* -------------------------------- the lab -------------------------------- */

function toolBy(name) {
  return (state.boot?.tools || []).find((t) => t.name === name) || null;
}

function renderToolList() {
  const tools = state.boot?.tools || [];
  const groups = EFFECT_ORDER
    .map((effect) => ({ effect, items: tools.filter((t) => t.effect === effect) }))
    .filter((g) => g.items.length);
  $('#labTools').innerHTML = groups.map((g) => `
    <div class="toolgroup">
      <div class="toolgroup__head"><b>${esc(EFFECT_LABEL[g.effect])}</b><span class="spacer"></span><span>${g.items.length}</span></div>
      ${g.items.map((t) => `
        <button type="button" class="toolbtn${t.plane === 'OPERATIONS' ? ' toolbtn--human' : ''}"
          data-tool="${attr(t.name)}" aria-pressed="${state.labTool === t.name}">
          <span class="glyph">${t.plane === 'CONTAINMENT' ? '▸' : '◇'}</span>
          <span class="toolbtn__name">${esc(t.name)}</span>
          <span class="toolbtn__plane">${esc(PLANE_LABEL[t.plane] || t.plane.toLowerCase())}</span>
        </button>`).join('')}
    </div>`).join('');
}

function selectTool(name) {
  state.labTool = name;
  state.labActor = 'agent';
  state.labDraft = { ...(LAB_DEFAULTS[name] || {}) };
  state.labResult = null;
  renderToolList();
  renderLabDetail();
}

function fieldHTML(p, value) {
  const v = value === undefined || value === null ? '' : String(value);
  const label = `<span class="micro">${esc(p.name)}${p.required ? ' *' : ''}</span>`;
  let control;
  if (p.enum && p.enum.length) {
    control = `<select data-arg="${attr(p.name)}">
      ${p.required ? '' : '<option value="">— optional —</option>'}
      ${p.enum.map((o) => `<option value="${attr(o)}"${o === v ? ' selected' : ''}>${esc(o)}</option>`).join('')}
    </select>`;
  } else if (/^(note|justification|summary|body)$/.test(p.name)) {
    control = `<textarea rows="3" data-arg="${attr(p.name)}" placeholder="${attr(p.description)}">${esc(v)}</textarea>`;
  } else {
    control = `<input type="text" data-arg="${attr(p.name)}" value="${attr(v)}" placeholder="${attr(p.description)}" spellcheck="false">`;
  }
  return `<label class="field">${label}${control}<span class="hint">${esc(p.type)}${p.required ? ' · required' : ' · optional'}</span></label>`;
}

function renderLabDetail() {
  const tool = toolBy(state.labTool);
  if (!tool) { $('#labDetail').innerHTML = '<div class="empty">Tool not found.</div>'; return; }
  const draft = state.labDraft || LAB_DEFAULTS[tool.name] || {};
  const fields = tool.params.filter((p) => p.name !== 'cosign');
  const human = tool.plane === 'OPERATIONS';
  const gateNote = human
    ? 'This is a human-plane tool. As the agent it is refused at CAPABILITY. As a QA Director it still needs a payload-bound co-signature, so it will stop at HUMAN.'
    : (['DESTRUCT', 'EXFIL', 'EXTERNAL_WRITE'].includes(tool.effect)
      ? 'No principal in HOLD holds this effect class. The tool exists in the catalogue precisely so the refusal can be observed and logged.'
      : 'This tool is inside the agent’s capability envelope. The lattice still checks that the resulting state does not loosen containment.');
  const result = state.labResult && state.labResult.tool === tool.name ? renderLabResult(state.labResult) : `
    <div class="empty">Invoke the tool to see which layer answers.</div>`;

  $('#labDetail').innerHTML = `
    <div class="labcard">
      <div class="labcard__head">
        <div>
          <div class="micro">${esc(EFFECT_LABEL[tool.effect])} · ${esc(tool.plane)} plane</div>
          <h3>${esc(tool.name)}</h3>
          <p>${esc(tool.summary)}</p>
        </div>
        <div style="display:flex;flex-direction:column;gap:5px;align-items:flex-end">
          <span class="chip chip--lime">${esc(tool.effect)}</span>
          ${tool.requires_cosign ? '<span class="chip chip--blue">2P CO-SIGN</span>' : ''}
          ${tool.mutating ? '<span class="chip chip--amber">MUTATING</span>' : '<span class="chip chip--ghost">READ-ONLY</span>'}
        </div>
      </div>
      <div class="labcard__body">
        <div class="labform">
          <div class="actorpick">
            <button type="button" data-lab-actor="agent" aria-pressed="${state.labActor === 'agent'}">
              <b>agent:hold</b><span>containment principal</span>
            </button>
            <button type="button" class="human" data-lab-actor="qa_director" aria-pressed="${state.labActor === 'qa_director'}">
              <b>human:qa-director</b><span>release authority</span>
            </button>
          </div>
          <form id="labForm" onsubmit="return false">
            ${fields.length ? fields.map((p) => fieldHTML(p, draft[p.name])).join('') : '<p class="caseblock">This tool takes no arguments.</p>'}
          </form>
          <button class="btn btn--primary btn--full" data-action="lab-invoke" style="margin-top:4px">
            Invoke through the kernel
          </button>
          <p class="caseblock" style="margin:8px 0 0;color:var(--faint)">${gateNote}</p>
        </div>
        <div class="labresult">${result}</div>
      </div>
    </div>`;
}

function collectDraft() {
  const draft = {};
  $$('#labForm [data-arg]').forEach((el) => { draft[el.dataset.arg] = el.value; });
  return draft;
}

function buildArgs(tool) {
  const args = {};
  for (const p of tool.params) {
    if (p.name === 'cosign') continue;
    const value = state.labDraft?.[p.name];
    if (value === undefined || value === '') {
      if (p.required) throw new Error(`${p.name} is required.`);
      continue;
    }
    if (p.type === 'array<string>') {
      args[p.name] = String(value).split(',').map((s) => s.trim()).filter(Boolean);
    } else {
      args[p.name] = String(value);
    }
  }
  return args;
}

function renderLabResult(data) {
  const r = data.result;
  const deny = r.decision === 'DENY';
  const where = {};
  for (const layer of state.boot.layers) where[layer.id] = layer.where;
  const mark = { passed: '✓', stopped: '■', not_in_path: '—', not_reached: '·' };
  const stack = (data.layers || []).map((l) => `
    <div class="layerrow layerrow--${attr(l.state)}">
      <span class="layerrow__mark">${mark[l.state] || '·'}</span>
      <span>${esc(l.layer)}</span>
      <span class="layerrow__where">${esc(where[l.layer] || '')}</span>
    </div>`).join('');
  return `
    <div class="labverdict labverdict--${deny ? 'deny' : 'allow'}">
      <span class="big">${esc(r.decision)}</span>
      <span class="mono" style="font-size:9px;color:var(--muted)">${esc(r.code)}</span>
      <span class="labverdict__meta">${esc(data.actor?.id)}<br>gen ${esc(r.state?.generation ?? '—')} · #${esc(r.seq ?? '—')}</span>
    </div>
    <div class="layerstack">${stack}</div>
    <p class="labnote">— not in this path. The lab invokes the kernel directly; guardrail, IAM and Gateway policy are upstream. This is the inner boundary holding without them.</p>
    <p class="labmsg">${esc(r.message)}</p>
    ${r.attempted_loosening ? '<div class="chip chip--red" style="margin-bottom:8px">LOOSENING ATTEMPT · LEDGERED</div>' : ''}
    <details>
      <summary>args, output, receipt</summary>
      <div class="json">ARGS\n${esc(JSON.stringify(r.args ?? {}, null, 2))}\n\nOUTPUT\n${esc(JSON.stringify(r.output ?? {}, null, 2))}\n\nRECEIPT ${esc(r.receipt || '')}</div>
    </details>`;
}

async function invokeLab() {
  const tool = toolBy(state.labTool);
  if (!tool) return;
  state.labDraft = collectDraft();
  const args = buildArgs(tool);
  const data = await api('/api/lab', {
    tool: tool.name,
    args,
    actor: state.labActor,
  });
  state.labResult = { tool: tool.name, ...data };
  renderLabDetail();
  setMetrics(data.metrics, data.result.state);
  pushBoundary([data.result]);
  await syncMeta();
  toast(`${data.result.decision} · ${data.result.code} · ${data.result.layer}`);
}

/* ------------------------------ stress suite ------------------------------ */

function renderStress(s) {
  const body = $('#stressBody');
  if (!s) {
    body.innerHTML = `<div class="empty">Run the suite to generate a fresh evidence bundle. It takes under a second.<br><br><button class="btn btn--primary" data-action="run-stress">Run 18 adversarial cases</button></div>`;
    return;
  }
  const t = s.totals;
  const caught = Object.entries(s.caught_by || {}).filter(([, n]) => n > 0);
  const total = caught.reduce((a, [, n]) => a + n, 0) || 1;
  const strip = caught.map(([layer, n]) => `
    <div class="caughtstrip__seg seg--${attr(layer)}" style="flex:${n}" title="${attr(layer)}: ${n} case(s)">
      ${esc(layer)} ${n}
    </div>`).join('');
  const rows = s.cases.map((entry) => {
    const c = entry.case;
    const ok = entry.passed;
    const delta = entry.delta || {};
    const added = [].concat(delta.held_added || [], delta.recalled_added || [], delta.notified_added || []);
    const observed = (entry.results || []).map((r) => `<div class="casecall">#${esc(r.seq)} ${esc(r.decision)} <b>${esc(r.tool)}</b> · ${esc(r.code)} @ ${esc(r.layer)}</div>`).join('');
    const calls = (c.calls || []).map((call) => `<div class="casecall"><b>${esc(call.tool)}</b>(${esc(JSON.stringify(call.args))})</div>`).join('');
    const signals = (entry.guard?.signals || []).join(', ');
    return `
      <tr class="caserow" data-case="${attr(c.id)}">
        <td class="idcell">${esc(c.id)}</td>
        <td><span class="caserow__title">${esc(c.title)}</span><br><span class="caserow__vec">${esc(c.vector)}</span></td>
        <td><span class="chip ${c.severity === 'CRITICAL' ? 'chip--red' : c.severity === 'HIGH' ? 'chip--amber' : 'chip--ghost'}">${esc(c.severity)}</span></td>
        <td class="mono">${esc(entry.catcher)}</td>
        <td class="mono">${esc(c.expected_catcher)}</td>
        <td class="${ok ? 'status-ok' : 'status-no'}">${ok ? 'PASS' : 'FAIL'}</td>
      </tr>
      <tr class="casedetail" data-casedetail="${attr(c.id)}" hidden>
        <td colspan="6">
          <div class="casedetail__inner">
            <div class="casegrid">
              <div>
                <h4>Prompt sent to the agent</h4>
                <pre class="promptbox">${esc(c.prompt)}${(c.followups || []).map((f) => `\n\n→ ${f}`).join('')}</pre>
                <h4>Tool calls the attacker wanted</h4>
                <div class="casecalls">${calls || '<span class="caseblock">No tool call; the denial must happen before one.</span>'}</div>
                ${c.note ? `<p class="caseblock" style="margin-top:8px"><b>Note:</b> ${esc(c.note)}</p>` : ''}
              </div>
              <div>
                <h4>What was expected</h4>
                <p class="caseblock">${esc(c.expected)}</p>
                <h4 style="margin-top:9px">What actually happened</h4>
                <div class="casekv">
                  <span class="chip chip--lime">CAUGHT AT ${esc(entry.catcher)}</span>
                  ${entry.monotone ? '<span class="chip chip--green">MONOTONE</span>' : '<span class="chip chip--red">VIOLATION</span>'}
                  <span class="chip chip--ghost">${esc(entry.elapsed_ms)} ms</span>
                </div>
                <div class="casecalls">${observed || '<span class="caseblock">No results.</span>'}</div>
                ${signals ? `<p class="caseblock" style="margin-top:7px"><b>Guardrail signals:</b> ${esc(signals)} (score ${esc(entry.guard?.attack_score ?? 0)})</p>` : ''}
                <p class="caseblock" style="margin-top:7px"><b>Delta:</b> ${esc(deltaSummary(delta))}</p>
                ${added.length ? `<p class="caseblock"><b>Side effects:</b> ${esc(added.join(', '))}</p>` : '<p class="caseblock"><b>Side effects:</b> none.</p>'}
              </div>
            </div>
          </div>
        </td>
      </tr>`;
  }).join('');
  body.innerHTML = `
    <div class="statrow">
      <div class="stat stat--good"><span class="stat__n">${esc(t.cases)}</span><span class="stat__l">cases</span></div>
      <div class="stat stat--good"><span class="stat__n">${esc(t.passed)}/${esc(t.cases)}</span><span class="stat__l">passed</span></div>
      <div class="stat stat--good"><span class="stat__n">${esc(t.released_lots)}</span><span class="stat__l">lots released</span></div>
      <div class="stat stat--good"><span class="stat__n">${esc(t.monotone_violations)}</span><span class="stat__l">monotone violations</span></div>
      <div class="stat"><span class="stat__n">${esc(t.injection_flags)}</span><span class="stat__l">injection flags</span></div>
      <div class="stat"><span class="stat__n">${esc(s.elapsed_seconds)}s</span><span class="stat__l">wall clock</span></div>
    </div>
    <div class="caughtstrip">${strip}</div>
    <table class="table">
      <thead><tr><th>Case</th><th>Attack</th><th>Severity</th><th>Caught by</th><th>Expected</th><th>Result</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <div class="stressfoot">
      <span>Every case assumes the model is fully compromised and makes the exact hostile call.</span>
      <span class="dotsep">·</span>
      <span>ledger ${esc(s.ledger?.length)} entries · chain ${s.ledger?.ok ? 'intact' : 'broken'} · root ${esc(short(s.ledger?.root, 16))}</span>
      <span class="spacer"></span>
      <span>click any row for the prompt and the observed layer</span>
    </div>`;
}

async function runStress() {
  const s = await api('/api/stress/run', {});
  state.stress = s;
  renderStress(s);
  $('#stressBadge').textContent = String(s.totals.cases);
  toast(`${s.totals.passed}/${s.totals.cases} passed · ${s.totals.released_lots} released · ${s.totals.monotone_violations} monotone violations`, 'warn');
}

/* ------------------------------ ledger actions ---------------------------- */

function bannerHTML(html, kind) {
  return `<div class="banner banner--${kind}"><b>${kind === 'bad' ? 'FAIL' : kind === 'warn' ? 'DRILL' : 'OK'}</b><span>${html}</span></div>`;
}

async function verifyLedger(tamper = false) {
  const res = await api('/api/ledger/verify', tamper ? { tamper: true } : {});
  const st = res.status;
  if (tamper && res.drill) {
    const d = res.drill;
    state.ledgerBanner = bannerHTML(
      `Shadow copy only. Flipped <b>seq ${esc(d.tampered_seq)}</b>; verifier ${d.detected ? `detected the break at <b>seq ${esc(d.broken_at)}</b>` : 'did <b>not</b> detect the break'}. ${esc(d.reason || '')} The live ledger was not modified.`,
      d.detected ? 'warn' : 'bad',
    );
    toast(d.detected ? `Tamper detected at seq ${d.broken_at}. Live chain untouched.` : 'Verifier missed the tamper.', d.detected ? 'warn' : 'bad');
  } else if (st.ok) {
    state.ledgerBanner = bannerHTML(
      `Chain intact over <b>${esc(st.length)}</b> entries. Root <span class="mono">${esc(st.root)}</span>. The verifier recomputed SHA-256 over canonical JSON and every prev-hash matched.`,
      'ok',
    );
    toast(`Chain intact · ${st.length} entries verified.`);
  } else {
    state.ledgerBanner = bannerHTML(
      `Verifier broke at <b>seq ${esc(st.broken_at)}</b>: ${esc(st.reason)}. This is what tampering looks like.`,
      'bad',
    );
    toast(`Chain broken at seq ${st.broken_at}.`, 'bad');
  }
  await loadLedger();
}

/* ------------------------------ stress ledger ----------------------------- */

/* -------------------------------- boot ---------------------------------- */

function renderLayers() {
  const layers = state.boot.layers || [];
  $('#layerStrip').innerHTML = layers.map((l, i) => `
    <div class="layer">
      <div class="layer__n">L${i + 1} · ${esc(l.id)}</div>
      <div class="layer__name">${esc(l.name)}</div>
      <div class="layer__where">${esc(l.where)}</div>
      <div class="layer__blurb">${esc(l.blurb)}</div>
    </div>`).join('');
}

function renderRules() {
  const rules = state.boot.rules || [];
  $('#rulesGrid').innerHTML = rules.map((r) => `
    <article class="rule">
      <div class="rule__top">
        <span class="rule__id">${esc(r.id)}</span>
        <span class="rule__plane">${esc((r.plane || 'agent').toUpperCase())} PLANE</span>
      </div>
      <h3>${esc(r.title)}</h3>
      <p class="rule__plain">${esc(r.plain)}</p>
      <p class="rule__mech"><b>Enforced by:</b> ${esc(r.mechanism)}</p>
      <div class="rule__foot">
        ${(r.layers || []).map((l) => `<span class="chip chip--ghost">${esc(l)}</span>`).join('')}
        <span class="rule__tests">${(r.tests || []).map((t) => `<span class="testchip">${esc(t)}</span>`).join('')}</span>
      </div>
    </article>`).join('');
}

function renderAll() {
  const b = state.boot;
  if (!b) return;
  renderStatic(b);
  renderLots();
  renderCaps();
  ensureTeeth();
  setMetrics(b.metrics, b.state);
  renderFeed();
  if (state.turns.length) {
    const feed = $('#feed');
    requestAnimationFrame(() => { feed.scrollTop = feed.scrollHeight; });
  }
  rebuildBoundary();
  updateLedgerBadge(b.ledger);
  renderStress(state.stress);
  renderLayers();
  renderRules();
  renderToolList();
  renderLabDetail();
  if (state.activeTab === 'ledger') loadLedger();
  else $('#ledgerBadge').textContent = String(b.ledger?.length ?? 0);
}

function setTab(name) {
  state.activeTab = name;
  $$('.tab').forEach((t) => t.setAttribute('aria-selected', String(t.dataset.tab === name)));
  $$('.view').forEach((v) => { v.hidden = v.id !== `view-${name}`; });
  if (name === 'ledger') loadLedger();
  if (name === 'stress' && state.stress) renderStress(state.stress);
  if (name === 'lab') { renderToolList(); renderLabDetail(); }
}

function startClock() {
  const tick = () => {
    const d = new Date();
    $('#clock').textContent = `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`;
  };
  tick();
  setInterval(tick, 1000);
}

/* --------------------------- human-plane actions -------------------------- */

async function requestHumanRelease() {
  const lotEl = $('#humanLots');
  const whyEl = $('#humanWhy');
  if (!lotEl) return;
  const lots = [lotEl.value];
  const justification = (whyEl?.value || '').trim();
  if (!justification) { toast('A justification is required for the request.', 'warn'); return; }
  const d = await api('/api/human/request', { lots, justification });
  state.boot.requests = d.requests || [];
  setMetrics(d.metrics, d.result.state);
  renderHuman();
  pushBoundary([d.result]);
  await syncMeta();
  if (d.result.decision === 'DENY') toast(`${d.result.code} · ${d.result.message}`, 'warn');
  else toast('Release request logged. Nothing has been released.');
}

async function cosignHumanRelease() {
  const req = pendingRequests().slice(-1)[0];
  if (!req) { toast('No pending release request.', 'warn'); return; }
  const justification = ($('#humanJust')?.value || '').trim();
  const d = await api('/api/human/action', {
    action: 'release_hold',
    lots: req.lots,
    justification,
  });
  state.boot.requests = d.requests || [];
  if (d.result.decision === 'ALLOW') {
    state.lastHuman = {
      message: `${(d.result.output?.released || req.lots).join(', ')} released by two humans`,
      generation: d.state?.generation,
      released: d.result.output?.released || req.lots,
      approver: d.result.output?.cosign_approver || 'human:vp-quality',
    };
    toast(`Co-signed and released. The agent still holds no release capability.`, 'warn');
  } else {
    toast(`${d.result.code} · ${d.result.message}`, 'bad');
  }
  setMetrics(d.metrics, d.state);
  renderHuman();
  pushBoundary([d.result]);
  await syncMeta();
}

/* ------------------------------ event wiring ------------------------------ */

function bindEvents() {
  document.addEventListener('click', (event) => {
    const quick = event.target.closest('[data-quick]');
    if (quick) {
      const text = quick.dataset.quick;
      $('#composerInput').value = text;
      runBusy(() => sendText(text));
      return;
    }
    const tab = event.target.closest('.tab');
    if (tab) { setTab(tab.dataset.tab); return; }

    const action = event.target.closest('[data-action]');
    if (action) {
      const name = action.dataset.action;
      const handlers = {
        step: () => runBusy(() => stepOnce(false)),
        'step-all': () => runBusy(stepAll),
        reset: () => runBusy(resetRun),
        send: () => runBusy(sendComposer),
        'run-stress': () => runBusy(runStress),
        verify: () => runBusy(() => verifyLedger(false)),
        tamper: () => runBusy(() => verifyLedger(true)),
        'lab-invoke': () => runBusy(invokeLab),
        'human-request': () => runBusy(requestHumanRelease),
        'human-cosign': () => runBusy(cosignHumanRelease),
      };
      if (handlers[name]) { event.preventDefault(); handlers[name](); }
      return;
    }

    const lot = event.target.closest('.lot[data-lot]');
    if (lot) {
      const text = `trace ${lot.dataset.lot}`;
      $('#composerInput').value = text;
      runBusy(() => sendText(text));
      return;
    }

    const toolBtn = event.target.closest('.toolbtn[data-tool]');
    if (toolBtn) { selectTool(toolBtn.dataset.tool); return; }

    const actorBtn = event.target.closest('[data-lab-actor]');
    if (actorBtn) {
      state.labDraft = collectDraft();
      state.labActor = actorBtn.dataset.labActor;
      state.labResult = null;
      renderLabDetail();
      return;
    }

    const ledRow = event.target.closest('.ledrow[data-ledseq]');
    if (ledRow && ledRow.nextElementSibling?.hasAttribute('data-leddetail')) {
      ledRow.nextElementSibling.hidden = !ledRow.nextElementSibling.hidden;
      return;
    }

    const caseRow = event.target.closest('.caserow[data-case]');
    if (caseRow && caseRow.nextElementSibling?.hasAttribute('data-casedetail')) {
      caseRow.nextElementSibling.hidden = !caseRow.nextElementSibling.hidden;
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.target.id === 'composerInput' && event.key === 'Enter') {
      event.preventDefault();
      runBusy(sendComposer);
    }
    if (event.target.classList?.contains('tab') && (event.key === 'ArrowRight' || event.key === 'ArrowLeft')) {
      event.preventDefault();
      const tabs = $$('.tab');
      const i = tabs.indexOf(event.target);
      const next = tabs[(i + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length];
      next.focus();
      setTab(next.dataset.tab);
    }
  });
}

async function init() {
  bindEvents();
  startClock();
  ensureTeeth();
  try {
    const b = await api('/api/bootstrap');
    state.boot = b;
    state.turns = (b.turns || []).slice();
    state.stress = b.stress;
    state.labDraft = { ...(LAB_DEFAULTS[state.labTool] || {}) };
    renderAll();
  } catch (err) {
    console.error(err);
    toast(`Console could not reach the kernel: ${err.message}`, 'bad');
    $('#feed').innerHTML = `<div class="empty">Could not load /api/bootstrap. Run <span class="mono">python demo/server.py</span> and reload.<br><br>${esc(err.message)}</div>`;
  }
}

init();


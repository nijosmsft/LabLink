package portal

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LabLink</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #0d1117; --fg: #e6edf3; --muted: #8b949e; --line: #30363d;
    --ok: #3fb950; --bad: #f85149; --warn: #d29922; --run: #58a6ff;
  }
  @media (prefers-color-scheme: light) {
    :root { --bg:#fff; --fg:#1f2328; --muted:#656d76; --line:#d0d7de; }
  }
  * { box-sizing: border-box; }
  body { margin:0; font:14px/1.4 -apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif; background:var(--bg); color:var(--fg); }
  header { padding:16px 24px; border-bottom:1px solid var(--line); display:flex; align-items:baseline; gap:16px; flex-wrap:wrap; }
  header h1 { font-size:16px; margin:0; font-weight:600; }
  header .sub { color:var(--muted); font-size:12px; }
  nav.tabs { display:flex; gap:4px; margin-left:auto; }
  nav.tabs button { background:transparent; border:1px solid var(--line); border-radius:6px; padding:6px 14px; color:var(--fg); cursor:pointer; font:inherit; }
  nav.tabs button.active { background:var(--line); }
  table { width:100%; border-collapse: collapse; }
  th, td { padding:10px 16px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }
  th { color:var(--muted); font-weight:500; font-size:12px; text-transform:uppercase; letter-spacing:.05em; background:transparent; }
  tr:hover td { background: rgba(110,118,129,.08); }
  .pill { display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; font-weight:600; }
  .pill.running   { color:#fff; background:var(--run); }
  .pill.succeeded { color:#fff; background:var(--ok); }
  .pill.exited    { color:#fff; background:var(--ok); }
  .pill.exited.bad{ color:#fff; background:var(--bad); }
  .pill.failed    { color:#fff; background:var(--bad); }
  .pill.cancelled { color:#fff; background:var(--warn); }
  .pill.canceled  { color:#fff; background:var(--warn); }
  .pill.orphaned  { color:#fff; background:var(--muted); }
  .pill.unknown   { color:#fff; background:var(--muted); }
  .pill.ready     { color:#fff; background:var(--ok); }
  .pill.degraded  { color:#fff; background:var(--bad); }
  .pill.lost      { color:#fff; background:var(--bad); }
  .pill.planned   { color:#fff; background:var(--muted); }
  .pill.paused    { color:#fff; background:var(--warn); }
  .summary { font-family: ui-monospace,Menlo,Consolas,monospace; color:var(--fg); white-space:pre-wrap; word-break:break-word; }
  .args { color:var(--muted); font-size:12px; margin-top:4px; font-family: ui-monospace,Menlo,Consolas,monospace; }
  .err  { color:var(--bad); font-size:12px; margin-top:4px; }
  button { font:inherit; background:transparent; color:var(--fg); border:1px solid var(--line); border-radius:6px; padding:4px 10px; cursor:pointer; margin-right:4px; }
  button:hover { border-color:var(--bad); color:var(--bad); }
  button.primary:hover { border-color:var(--run); color:var(--run); }
  button:disabled { opacity:.4; cursor:default; }
  .empty { padding:48px; text-align:center; color:var(--muted); }
  .age { color:var(--muted); font-variant-numeric: tabular-nums; white-space:nowrap; }
  .tab-pane { display:none; }
  .tab-pane.active { display:block; }
  .filters { display:flex; gap:8px; padding:12px 24px; border-bottom:1px solid var(--line); align-items:center; flex-wrap:wrap; }
  .filters select, .filters input { background:var(--bg); color:var(--fg); border:1px solid var(--line); border-radius:6px; padding:4px 8px; font:inherit; }
  .modal-backdrop { position:fixed; inset:0; background:rgba(0,0,0,.55); display:none; z-index:50; }
  .modal-backdrop.open { display:flex; align-items:center; justify-content:center; }
  .modal { background:var(--bg); border:1px solid var(--line); border-radius:10px; width:min(980px, 92vw); max-height:88vh; display:flex; flex-direction:column; }
  .modal header { border:0; border-bottom:1px solid var(--line); padding:14px 18px; }
  .modal .body { padding:12px 18px; overflow:auto; }
  .modal .streams { display:flex; gap:6px; padding:0 18px 12px; }
  .modal .streams button.active { background:var(--line); }
  .modal pre { background:rgba(110,118,129,.08); padding:10px 12px; border-radius:6px; max-height:50vh; overflow:auto; white-space:pre-wrap; word-break:break-word; margin:0; font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12px; }
  .modal .footer { padding:12px 18px; border-top:1px solid var(--line); display:flex; justify-content:flex-end; gap:8px; }
  .truncate { max-width:400px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .node-errors { padding:8px 24px; color:var(--bad); font-size:12px; }
  .section-title { padding:18px 24px 8px; margin:0; font-size:14px; }
  .section-meta { padding:0 24px 10px; color:var(--muted); font-size:12px; }
  .identity { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12px; word-break:break-all; }
  .stack { display:flex; flex-direction:column; gap:3px; }
  .drift { color:var(--warn); font-weight:600; }
  .ok { color:var(--ok); }
  .isolated-errors { padding:10px 24px; color:var(--bad); white-space:pre-wrap; }
</style>
</head>
<body>
<header>
  <h1>LabLink</h1>
  <span class="sub" id="conn">connecting…</span>
  <nav class="tabs">
    <button id="tab-ops" class="active" onclick="showTab('ops')">Operations</button>
    <button id="tab-jobs" onclick="showTab('jobs')">Jobs</button>
    <button id="tab-isolated" onclick="showTab('isolated')">Isolated</button>
  </nav>
</header>

<section id="pane-ops" class="tab-pane active">
<table>
  <thead>
    <tr><th>Status</th><th>Tool</th><th>Node</th><th>Summary</th><th>Started</th><th></th></tr>
  </thead>
  <tbody id="rows"></tbody>
</table>
<div id="empty" class="empty">No operations yet.</div>
</section>

<section id="pane-jobs" class="tab-pane">
<div class="filters">
  <label>Node:
    <select id="job-node-filter"><option value="">all</option></select>
  </label>
  <label>Status:
    <select id="job-status-filter">
      <option value="">all</option>
      <option value="running">running</option>
      <option value="exited">exited</option>
      <option value="canceled">canceled</option>
      <option value="orphaned">orphaned</option>
    </select>
  </label>
  <span class="sub" id="jobs-conn" style="color:var(--muted);font-size:12px;">idle</span>
</div>
<div id="node-errors" class="node-errors"></div>
<table>
  <thead>
    <tr><th>Status</th><th>Node</th><th>Job ID</th><th>Command</th><th>PID</th><th>Started</th><th></th></tr>
  </thead>
  <tbody id="jobs-rows"></tbody>
</table>
<div id="jobs-empty" class="empty">No jobs yet.</div>
</section>

<section id="pane-isolated" class="tab-pane">
<div class="filters">
  <button class="primary" onclick="loadIsolated()">Refresh</button>
  <span class="sub" id="isolated-conn" style="color:var(--muted);font-size:12px;">idle</span>
</div>
<div id="isolated-errors" class="isolated-errors"></div>

<h2 class="section-title">Orchestrators</h2>
<div class="section-meta">Durable identity, main endpoint, appliance readiness, capabilities, and cached capacity.</div>
<table>
  <thead><tr><th>State</th><th>Identity</th><th>Main endpoint</th><th>Readiness</th><th>Capacity</th></tr></thead>
  <tbody id="isolated-orchestrators"></tbody>
</table>

<h2 class="section-title">Private networks</h2>
<div class="section-meta">Subnet and Hyper-V switch identity are immutable orchestration inputs.</div>
<table>
  <thead><tr><th>State</th><th>Identity</th><th>Subnet</th><th>Switch identity</th><th>DNS</th></tr></thead>
  <tbody id="isolated-networks"></tbody>
</table>

<h2 class="section-title">Isolated VMs</h2>
<table>
  <thead><tr><th>State</th><th>Identity</th><th>Network</th><th>IP / MAC</th><th>Relay / TLS</th><th>NAT / DNS</th></tr></thead>
  <tbody id="isolated-vms"></tbody>
</table>

<h2 class="section-title">Relays</h2>
<div class="section-meta" id="isolated-relay-page"></div>
<table>
  <thead><tr><th>State</th><th>Identity</th><th>Listener</th><th>Target</th><th>Traffic</th><th>Errors</th></tr></thead>
  <tbody id="isolated-relays"></tbody>
</table>

<div id="isolated-empty" class="empty">No isolated orchestration state.</div>
</section>

<div id="modal" class="modal-backdrop" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <header><span id="modal-title">Job</span></header>
    <div class="streams">
      <button id="mode-stdout" class="active" onclick="setMode('stdout')">stdout</button>
      <button id="mode-stderr" onclick="setMode('stderr')">stderr</button>
      <button id="mode-both" onclick="setMode('both')">both</button>
      <span class="sub" id="modal-meta" style="margin-left:auto;color:var(--muted);font-size:12px;align-self:center;"></span>
    </div>
    <div class="body"><pre id="modal-output">Loading…</pre></div>
    <div class="footer">
      <button class="primary" onclick="refreshOutput()">Refresh</button>
      <button onclick="closeModal()">Close</button>
    </div>
  </div>
</div>

<script>
// ---------- Operations tab (unchanged) ----------
const rows  = document.getElementById('rows');
const empty = document.getElementById('empty');
const conn  = document.getElementById('conn');
const ops   = new Map();

function renderArgs(args) {
  if (!args) return '';
  const entries = Object.entries(args).filter(([k]) => k !== 'node');
  if (!entries.length) return '';
  return entries.map(([k,v]) => k + '=' + v).join(' • ');
}
function fmtAge(t) {
  const ms = Date.now() - new Date(t).getTime();
  if (ms < 1000) return ms + 'ms';
  if (ms < 60000) return (ms/1000).toFixed(1) + 's';
  if (ms < 3600000) return Math.round(ms/60000) + 'm';
  return Math.round(ms/3600000) + 'h';
}
function escape(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[c]));
}
function opRowHTML(op) {
  const status  = op.status;
  const summary = op.summary || '';
  const args    = renderArgs(op.args);
  const err     = op.error ? '<div class="err">' + escape(op.error) + '</div>' : '';
  const action  = status === 'running'
    ? '<button onclick="cancelOp(\'' + op.id + '\', this)">Cancel</button>'
    : '';
  return ''
    + '<td><span class="pill ' + status + '">' + status + '</span></td>'
    + '<td>' + escape(op.tool) + '</td>'
    + '<td>' + escape(op.node || '') + '</td>'
    + '<td><div class="summary">' + escape(summary) + '</div>'
    +    (args ? '<div class="args">' + escape(args) + '</div>' : '')
    +    err
    + '</td>'
    + '<td class="age" data-started="' + op.started_at + '">' + fmtAge(op.started_at) + '</td>'
    + '<td>' + action + '</td>';
}
function upsertOp(op) {
  ops.set(op.id, op);
  let tr = document.getElementById('op-' + op.id);
  if (!tr) {
    tr = document.createElement('tr');
    tr.id = 'op-' + op.id;
    rows.prepend(tr);
  }
  tr.innerHTML = opRowHTML(op);
  empty.style.display = ops.size ? 'none' : 'block';
}
async function cancelOp(id, btn) {
  btn.disabled = true;
  btn.textContent = 'Cancelling…';
  const r = await fetch('/api/ops/cancel?id=' + encodeURIComponent(id), { method: 'POST' });
  if (!r.ok) {
    btn.textContent = 'Cancel';
    btn.disabled = false;
    alert('Cancel failed: ' + r.status);
  }
}
setInterval(() => {
  document.querySelectorAll('.age').forEach(el => {
    if (el.dataset.started) el.textContent = fmtAge(el.dataset.started);
  });
}, 1000);
(function connectOps() {
  const es = new EventSource('/api/ops/stream');
  es.onopen = () => { conn.textContent = 'live'; };
  es.onerror = () => { conn.textContent = 'reconnecting…'; };
  es.onmessage = (m) => {
    const ev = JSON.parse(m.data);
    if (ev.kind === 'snapshot') {
      ops.clear();
      rows.innerHTML = '';
      (ev.ops || []).forEach(upsertOp);
    } else if (ev.op) {
      upsertOp(ev.op);
    }
  };
})();

// ---------- Jobs tab ----------
const jobsRows  = document.getElementById('jobs-rows');
const jobsEmpty = document.getElementById('jobs-empty');
const jobsConn  = document.getElementById('jobs-conn');
const nodeErrBox = document.getElementById('node-errors');
const nodeSel    = document.getElementById('job-node-filter');
const statusSel  = document.getElementById('job-status-filter');
const jobs = new Map(); // key = node|job_id
let jobsEventSource = null;
const nodeErrors = new Map();

nodeSel.addEventListener('change', renderJobs);
statusSel.addEventListener('change', renderJobs);

function jobKey(node, id) { return node + '|' + id; }

function statusPill(status, exitCode) {
  let cls = status;
  let label = status;
  if (status === 'exited') {
    if (exitCode !== 0) cls = 'exited bad';
    label = 'exited(' + exitCode + ')';
  }
  return '<span class="pill ' + cls + '">' + escape(label) + '</span>';
}

function jobRowHTML(j) {
  const cmd = (j.command || '').replace(/\n/g, ' ');
  const action =
    '<button class="primary" onclick="openJob(\'' + escape(j.node) + '\',\'' + escape(j.job_id) + '\')">View</button>' +
    (j.status === 'running'
      ? '<button onclick="cancelJob(\'' + escape(j.node) + '\',\'' + escape(j.job_id) + '\', this)">Cancel</button>'
      : '<button onclick="deleteJob(\'' + escape(j.node) + '\',\'' + escape(j.job_id) + '\', this)">Delete</button>');
  return ''
    + '<td>' + statusPill(j.status, j.exit_code) + '</td>'
    + '<td>' + escape(j.node) + '</td>'
    + '<td><code>' + escape(j.job_id) + '</code></td>'
    + '<td><div class="summary truncate" title="' + escape(cmd) + '">' + escape(cmd) + '</div>'
    +    (j.error ? '<div class="err">' + escape(j.error) + '</div>' : '')
    + '</td>'
    + '<td>' + escape(j.pid) + '</td>'
    + '<td class="age" data-started="' + escape(j.started_at) + '">' + fmtAge(j.started_at) + '</td>'
    + '<td>' + action + '</td>';
}

function renderJobs() {
  jobsRows.innerHTML = '';
  const nodeFilter = nodeSel.value;
  const statusFilter = statusSel.value;
  const list = Array.from(jobs.values())
    .filter(j => !nodeFilter || j.node === nodeFilter)
    .filter(j => !statusFilter || j.status === statusFilter || (statusFilter === 'exited' && j.status === 'exited'))
    .sort((a,b) => (b.started_at || '').localeCompare(a.started_at || ''));
  for (const j of list) {
    const tr = document.createElement('tr');
    tr.id = 'job-' + jobKey(j.node, j.job_id);
    tr.innerHTML = jobRowHTML(j);
    jobsRows.appendChild(tr);
  }
  jobsEmpty.style.display = list.length ? 'none' : 'block';
  refreshNodeFilterOptions();
  renderNodeErrors();
}

function refreshNodeFilterOptions() {
  const nodes = new Set(Array.from(jobs.values()).map(j => j.node));
  for (const n of nodeErrors.keys()) nodes.add(n);
  const current = nodeSel.value;
  const sorted = Array.from(nodes).sort();
  const desired = ['', ...sorted];
  const existing = Array.from(nodeSel.options).map(o => o.value);
  if (existing.length !== desired.length || existing.some((v,i) => v !== desired[i])) {
    nodeSel.innerHTML = '';
    const optAll = document.createElement('option');
    optAll.value = ''; optAll.textContent = 'all';
    nodeSel.appendChild(optAll);
    for (const n of sorted) {
      const o = document.createElement('option');
      o.value = n; o.textContent = n;
      nodeSel.appendChild(o);
    }
    nodeSel.value = sorted.includes(current) ? current : '';
  }
}

function renderNodeErrors() {
  if (nodeErrors.size === 0) { nodeErrBox.textContent = ''; return; }
  const parts = [];
  for (const [node, err] of nodeErrors.entries()) {
    parts.push(escape(node) + ': ' + escape(err));
  }
  nodeErrBox.innerHTML = 'Node errors — ' + parts.join(' | ');
}

function upsertJob(j) {
  jobs.set(jobKey(j.node, j.job_id), j);
  renderJobs();
}
function removeJob(node, id) {
  jobs.delete(jobKey(node, id));
  renderJobs();
}

function connectJobsStream() {
  if (jobsEventSource) jobsEventSource.close();
  jobsConn.textContent = 'connecting…';
  const es = new EventSource('/api/jobs/stream');
  jobsEventSource = es;
  es.onopen = () => { jobsConn.textContent = 'live'; };
  es.onerror = () => { jobsConn.textContent = 'reconnecting…'; };
  es.onmessage = (m) => {
    let ev; try { ev = JSON.parse(m.data); } catch (_) { return; }
    if (ev.kind === 'node_error') {
      nodeErrors.set(ev.node, ev.error || 'unknown error');
      renderNodeErrors();
      return;
    }
    nodeErrors.delete(ev.node);
    if (ev.kind === 'deleted') {
      removeJob(ev.node, ev.job_id);
      return;
    }
    if (ev.job) upsertJob(ev.job);
  };
}

async function loadJobsSnapshot() {
  try {
    const r = await fetch('/api/jobs');
    if (!r.ok) return;
    const data = await r.json();
    jobs.clear();
    nodeErrors.clear();
    for (const j of (data.jobs || [])) jobs.set(jobKey(j.node, j.job_id), j);
    for (const e of (data.errors || [])) nodeErrors.set(e.node, e.error);
    renderJobs();
  } catch (_) {}
}

async function cancelJob(node, id, btn) {
  if (!confirm('Cancel job ' + id + ' on ' + node + '?')) return;
  btn.disabled = true; btn.textContent = 'Cancelling…';
  const r = await fetch('/api/jobs/cancel?node=' + encodeURIComponent(node) + '&id=' + encodeURIComponent(id), { method:'POST' });
  if (!r.ok) { alert('Cancel failed: ' + r.status + ' ' + await r.text()); btn.disabled = false; btn.textContent = 'Cancel'; }
}
async function deleteJob(node, id, btn) {
  if (!confirm('Delete job ' + id + ' on ' + node + '? This removes captured output.')) return;
  btn.disabled = true; btn.textContent = 'Deleting…';
  const r = await fetch('/api/jobs/delete?node=' + encodeURIComponent(node) + '&id=' + encodeURIComponent(id), { method:'POST' });
  if (!r.ok) { alert('Delete failed: ' + r.status + ' ' + await r.text()); btn.disabled = false; btn.textContent = 'Delete'; }
}

// ---------- Modal (output viewer) ----------
const modal = document.getElementById('modal');
const modalTitle = document.getElementById('modal-title');
const modalMeta  = document.getElementById('modal-meta');
const modalOut   = document.getElementById('modal-output');
let currentJob = null;
let currentMode = 'stdout';

function openJob(node, id) {
  currentJob = { node, id };
  currentMode = 'stdout';
  document.getElementById('mode-stdout').classList.add('active');
  document.getElementById('mode-stderr').classList.remove('active');
  document.getElementById('mode-both').classList.remove('active');
  modalTitle.textContent = 'Job ' + id + ' on ' + node;
  modal.classList.add('open');
  refreshOutput();
}
function closeModal() { modal.classList.remove('open'); currentJob = null; }
function setMode(m) {
  currentMode = m;
  ['stdout','stderr','both'].forEach(x => document.getElementById('mode-'+x).classList.toggle('active', x===m));
  refreshOutput();
}
async function refreshOutput() {
  if (!currentJob) return;
  modalOut.textContent = 'Loading…';
  const u = '/api/jobs/output?node=' + encodeURIComponent(currentJob.node)
          + '&id=' + encodeURIComponent(currentJob.id)
          + '&stream=' + currentMode + '&lines=500';
  try {
    const r = await fetch(u);
    if (!r.ok) { modalOut.textContent = 'Error: ' + r.status + ' ' + await r.text(); return; }
    const data = await r.json();
    const parts = [];
    if (currentMode === 'stdout' || currentMode === 'both') {
      parts.push('--- stdout (' + (data.stdout ? data.stdout.length : 0) + '/' + data.stdout_total_bytes + ' bytes) ---');
      parts.push(data.stdout || '');
    }
    if (currentMode === 'stderr' || currentMode === 'both') {
      parts.push('--- stderr (' + (data.stderr ? data.stderr.length : 0) + '/' + data.stderr_total_bytes + ' bytes) ---');
      parts.push(data.stderr || '');
    }
    modalMeta.textContent = data.truncated ? 'truncated' : '';
    modalOut.textContent = parts.join('\n');
  } catch (e) {
    modalOut.textContent = 'Error: ' + e;
  }
}

function showTab(name) {
  document.getElementById('tab-ops').classList.toggle('active', name === 'ops');
  document.getElementById('tab-jobs').classList.toggle('active', name === 'jobs');
  document.getElementById('tab-isolated').classList.toggle('active', name === 'isolated');
  document.getElementById('pane-ops').classList.toggle('active', name === 'ops');
  document.getElementById('pane-jobs').classList.toggle('active', name === 'jobs');
  document.getElementById('pane-isolated').classList.toggle('active', name === 'isolated');
  if (name === 'jobs' && !jobsEventSource) {
    loadJobsSnapshot().then(connectJobsStream);
  }
  if (name === 'isolated' && !isolatedLoaded) loadIsolated();
}

// ---------- Isolated orchestration (read-only) ----------
const isolatedConn = document.getElementById('isolated-conn');
const isolatedErrors = document.getElementById('isolated-errors');
const isolatedEmpty = document.getElementById('isolated-empty');
let isolatedLoaded = false;

function clearTable(id) { document.getElementById(id).replaceChildren(); }
function td(value, cls) {
  const cell = document.createElement('td');
  if (cls) cell.className = cls;
  cell.textContent = value == null ? '' : String(value);
  return cell;
}
function stackTD(lines, cls) {
  const cell = document.createElement('td');
  const box = document.createElement('div');
  box.className = 'stack' + (cls ? ' ' + cls : '');
  for (const line of lines.filter(v => v !== '' && v != null)) {
    const item = document.createElement('span');
    item.textContent = String(line);
    box.appendChild(item);
  }
  cell.appendChild(box);
  return cell;
}
function stateTD(state, error) {
  const cell = document.createElement('td');
  const pill = document.createElement('span');
  const normalized = String(state || 'unknown').toLowerCase().replace(/[^a-z0-9_-]/g, '');
  pill.className = 'pill ' + normalized;
  pill.textContent = state || 'unknown';
  cell.appendChild(pill);
  if (error) {
    const detail = document.createElement('div');
    detail.className = 'err';
    detail.textContent = error;
    cell.appendChild(detail);
  }
  return cell;
}
function appendRow(tableID, cells) {
  const row = document.createElement('tr');
  for (const cell of cells) row.appendChild(cell);
  document.getElementById(tableID).appendChild(row);
}
function dnsText(values) { return (values || []).join(', ') || 'none'; }
function renderIsolated(data) {
  ['isolated-orchestrators','isolated-networks','isolated-vms','isolated-relays'].forEach(clearTable);
  const errors = [...(data.errors || [])];
  isolatedErrors.textContent = errors.map(e => e.scope + ': ' + e.error).join('\n');

  for (const o of (data.orchestrators || [])) {
    const ready = o.readiness || {};
    const endpoint = o.endpoint || {};
    const cap = o.capacity || {};
    appendRow('isolated-orchestrators', [
      stateTD(o.lifecycle_state, ready.error),
      stackTD([o.display_name || o.id, o.id, 'host ' + o.physical_host_id, 'VM ' + o.hyperv_name], 'identity'),
      stackTD([endpoint.address || 'unassigned', endpoint.node_name, 'TLS ' + (endpoint.tls_name || 'missing'), endpoint.identity_ok ? 'mTLS identity verified' : 'mTLS identity unavailable'], endpoint.identity_ok ? 'ok' : 'drift'),
      stackTD(['health ' + (o.health_state || 'unknown'), ready.ready ? 'appliance ready' : 'appliance not ready', ready.agent_version || '', 'protocol ' + (ready.protocol_version || 0), (ready.capabilities || []).join(', ') || 'no capabilities']),
      stackTD([cap.used_networks + '/' + cap.max_networks + ' networks', cap.used_vms + '/' + cap.max_vms + ' VMs', cap.free_relay_ports + ' relay ports free'])
    ]);
  }
  for (const n of (data.networks || [])) {
    appendRow('isolated-networks', [
      stateTD(n.live_state || n.lifecycle_state, n.live_error),
      stackTD([n.display_name || n.id, n.id, 'orchestrator ' + n.orchestrator_id], 'identity'),
      stackTD(['index ' + n.subnet_index, n.cidr, 'gateway ' + n.gateway_ipv4, 'MAC ' + n.orchestrator_mac]),
      stackTD([n.hyperv_switch_name, n.hyperv_switch_guid || 'GUID pending', n.orchestrator_adapter_id || 'adapter pending'], 'identity'),
      stackTD(['configured ' + dnsText(n.dns_servers), 'runtime ' + dnsText(n.observed_dns_servers), n.dns_drift ? 'DNS drift' : 'DNS aligned'], n.dns_drift ? 'drift' : 'ok')
    ]);
  }
  for (const v of (data.vms || [])) {
    const tls = v.tls || {};
    const nat = v.nat || {};
    appendRow('isolated-vms', [
      stateTD(v.live_state || v.lifecycle_state, v.live_error),
      stackTD([v.display_name || v.id, v.id, v.hyperv_name], 'identity'),
      stackTD([v.network_id, v.guest_os + ' / ' + v.profile_name], 'identity'),
      stackTD([v.ipv4 + '/' + v.prefix_length, v.mac, 'gateway ' + v.gateway_ipv4], 'identity'),
      stackTD([v.relay_id ? v.relay_id + ' :' + v.relay_listen_port : 'no relay', tls.node_name, 'TLS ' + (tls.tls_name || 'missing'), tls.identity_ok ? 'mTLS identity verified' : 'mTLS identity unavailable'], tls.identity_ok ? 'ok' : 'drift'),
      stackTD([nat.state ? 'NAT ' + nat.state + ' / ' + (nat.live_state || '') : 'NAT unallocated', 'DNS ' + dnsText(v.dns_servers), v.dns_drift ? 'DNS drift' : 'DNS aligned', nat.live_error || ''], v.dns_drift ? 'drift' : '')
    ]);
  }
  for (const r of (data.relays || [])) {
    const stats = r.stats || {};
    appendRow('isolated-relays', [
      stateTD(stats.listener_state || r.live_state || r.lifecycle_state, stats.error || r.live_error),
      stackTD([r.id, 'VM ' + r.vm_id, 'orchestrator ' + r.orchestrator_id], 'identity'),
      stackTD([stats.bind_address || r.bound_main_ip || 'unbound', 'port ' + r.listen_port]),
      stackTD([r.target_ipv4 + ':' + r.target_port]),
      stackTD([(stats.active_connections || 0) + ' active', (stats.total_accepted_connections || 0) + ' accepted', (stats.bytes_guest_to_main || 0) + ' / ' + (stats.bytes_main_to_guest || 0) + ' bytes']),
      stackTD([stats.bind_error || '', stats.last_failure || '', (stats.target_dial_failure_count || 0) + ' dial failures'], stats.bind_error || stats.last_failure ? 'drift' : '')
    ]);
  }
  const relayPage = data.relay_stats_page || {};
  document.getElementById('isolated-relay-page').textContent =
    (relayPage.total || 0) + ' relays; runtime stats limited to ' + (relayPage.limit || 0) + ' from offset ' + (relayPage.offset || 0);

  const count = (data.orchestrators || []).length + (data.networks || []).length +
    (data.vms || []).length + (data.relays || []).length;
  isolatedEmpty.style.display = count ? 'none' : 'block';
}
async function loadIsolated() {
  isolatedConn.textContent = 'loading…';
  try {
    const stateResponse = await fetch('/api/isolated?stats_limit=100');
    const stateData = await stateResponse.json();
    renderIsolated(stateData);
    isolatedConn.textContent = stateResponse.ok ? 'current' : 'partial';
    isolatedLoaded = true;
  } catch (e) {
    isolatedConn.textContent = 'unavailable';
    isolatedErrors.textContent = String(e);
  }
}
</script>
</body>
</html>
`

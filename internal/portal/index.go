package portal

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LabLink — operations</title>
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
  header { padding:16px 24px; border-bottom:1px solid var(--line); display:flex; align-items:baseline; gap:12px; }
  header h1 { font-size:16px; margin:0; font-weight:600; }
  header .sub { color:var(--muted); font-size:12px; }
  table { width:100%; border-collapse: collapse; }
  th, td { padding:10px 16px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }
  th { color:var(--muted); font-weight:500; font-size:12px; text-transform:uppercase; letter-spacing:.05em; background:transparent; }
  tr:hover td { background: rgba(110,118,129,.08); }
  .pill { display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; font-weight:600; }
  .pill.running   { color:#fff; background:var(--run); }
  .pill.succeeded { color:#fff; background:var(--ok); }
  .pill.failed    { color:#fff; background:var(--bad); }
  .pill.cancelled { color:#fff; background:var(--warn); }
  .summary { font-family: ui-monospace,Menlo,Consolas,monospace; color:var(--fg); white-space:pre-wrap; word-break:break-word; }
  .args { color:var(--muted); font-size:12px; margin-top:4px; font-family: ui-monospace,Menlo,Consolas,monospace; }
  .err  { color:var(--bad); font-size:12px; margin-top:4px; }
  button { font:inherit; background:transparent; color:var(--fg); border:1px solid var(--line); border-radius:6px; padding:4px 10px; cursor:pointer; }
  button:hover { border-color:var(--bad); color:var(--bad); }
  button:disabled { opacity:.4; cursor:default; }
  .empty { padding:48px; text-align:center; color:var(--muted); }
  .age { color:var(--muted); font-variant-numeric: tabular-nums; }
</style>
</head>
<body>
<header>
  <h1>LabLink operations</h1>
  <span class="sub" id="conn">connecting…</span>
</header>
<table>
  <thead>
    <tr><th>Status</th><th>Tool</th><th>Node</th><th>Summary</th><th>Started</th><th></th></tr>
  </thead>
  <tbody id="rows"></tbody>
</table>
<div id="empty" class="empty">No operations yet.</div>

<script>
const rows  = document.getElementById('rows');
const empty = document.getElementById('empty');
const conn  = document.getElementById('conn');
const ops = new Map(); // id -> op

function renderArgs(args) {
  if (!args) return '';
  const entries = Object.entries(args).filter(([k]) => k !== 'node');
  if (!entries.length) return '';
  return entries.map(([k,v]) => k + '=' + v).join(' • ');
}

function fmtAge(t) {
  const ms = Date.now() - new Date(t).getTime();
  if (ms < 1000) return ms + 'ms';
  if (ms < 60_000) return (ms/1000).toFixed(1) + 's';
  if (ms < 3_600_000) return Math.round(ms/60_000) + 'm';
  return Math.round(ms/3_600_000) + 'h';
}

function rowHTML(op) {
  const status  = op.status;
  const summary = op.summary || '';
  const args    = renderArgs(op.args);
  const err     = op.error ? '<div class="err">' + escape(op.error) + '</div>' : '';
  const action  = status === 'running'
    ? '<button onclick="cancel(\'' + op.id + '\', this)">Cancel</button>'
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

function upsert(op) {
  ops.set(op.id, op);
  let tr = document.getElementById('op-' + op.id);
  if (!tr) {
    tr = document.createElement('tr');
    tr.id = 'op-' + op.id;
    rows.prepend(tr);
  }
  tr.innerHTML = rowHTML(op);
  empty.style.display = ops.size ? 'none' : 'block';
}

function escape(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[c]));
}

async function cancel(id, btn) {
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
    el.textContent = fmtAge(el.dataset.started);
  });
}, 1000);

function connect() {
  const es = new EventSource('/api/ops/stream');
  es.onopen = () => { conn.textContent = 'live'; };
  es.onerror = () => { conn.textContent = 'reconnecting…'; };
  es.onmessage = (m) => {
    const ev = JSON.parse(m.data);
    if (ev.kind === 'snapshot') {
      ops.clear();
      rows.innerHTML = '';
      (ev.ops || []).forEach(upsert);
    } else if (ev.op) {
      upsert(ev.op);
    }
  };
}
connect();
</script>
</body>
</html>
`

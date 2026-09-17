// ── Talus Admin Panel — frontend ──────────────────────────────────────────
// Talks only to the local proxy (same origin). The admin token is injected
// server-side and never reaches the browser.

const $ = (id) => document.getElementById(id);

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'content-type': 'application/json' },
    ...opts,
  });
  let data = {};
  try {
    data = await res.json();
  } catch {
    /* non-JSON error body */
  }
  return { ok: res.ok, status: res.status, data };
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function fmt_date(s) {
  if (!s) return '—';
  return s.replace('T', ' ').replace('Z', ' UTC');
}

// ── Overview ──────────────────────────────────────────────────────────────

async function refresh() {
  const { ok, data } = await api('/api/v1/admin/stats');
  $('health-dot').className = 'dot ' + (ok ? 'on' : 'off');
  if (!ok) {
    $('s-licenses').textContent = $('s-activations').textContent =
    $('s-7d').textContent = $('s-revoked').textContent = '!';
    return;
  }
  $('s-licenses').textContent = data.licenses ?? 0;
  $('s-activations').textContent = data.activations ?? 0;
  $('s-7d').textContent = data.activations_7d ?? 0;
  $('s-revoked').textContent = data.revoked ?? 0;

  const recent = $('recent-table').querySelector('tbody');
  recent.innerHTML = (data.recent ?? []).map((r) => `
    <tr>
      <td><code>${esc(r.license_id)}</code></td>
      <td>${esc(r.org ?? '—')}</td>
      <td><span class="pill ${r.revoked ? 'bad' : 'good'}">${esc(r.tier ?? '?')}</span></td>
      <td><code>${esc(r.machine_id)}</code></td>
      <td>${esc(r.hostname ?? '—')}</td>
      <td class="dim">${esc(fmt_date(r.activated_at))}</td>
    </tr>`).join('') || '<tr><td colspan="6" class="dim">No activations yet.</td></tr>';

  const revoked = $('revoked-table').querySelector('tbody');
  revoked.innerHTML = (data.revoked_list ?? []).map((r) => `
    <tr>
      <td><code>${esc(r.license_id)}</code></td>
      <td>${esc(r.org ?? '—')}</td>
      <td class="dim">${esc(fmt_date(r.revoked_at))}</td>
    </tr>`).join('') || '<tr><td colspan="3" class="dim">Nothing revoked.</td></tr>';
}

// ── Lookup ────────────────────────────────────────────────────────────────

$('lookup-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const id = $('lookup-id').value.trim();
  const out = $('lookup-result');
  out.textContent = 'Loading…';
  const { ok, data } = await api('/api/v1/admin/activations', {
    method: 'POST',
    body: JSON.stringify({ license_id: id }),
  });
  if (!ok) {
    out.innerHTML = `<span class="bad">Error ${esc(data.message ?? '')}</span>`;
    return;
  }
  const rows = data.activations ?? [];
  out.innerHTML = rows.length
    ? `<table><thead><tr><th>#</th><th>Machine</th><th>Hostname</th><th>Activated</th><th></th></tr></thead><tbody>${
        rows.map((a) => `
          <tr>
            <td>${esc(a.seat_index)}</td>
            <td><code>${esc(a.machine_id)}</code></td>
            <td>${esc(a.hostname ?? '—')}</td>
            <td class="dim">${esc(fmt_date(a.activated_at))}</td>
            <td><button class="mini danger-btn" data-seat="${esc(a.machine_id)}">free seat</button></td>
          </tr>`).join('')
      }</tbody></table>`
    : '<span class="dim">No activations for this license.</span>';
  out.querySelectorAll('button[data-seat]').forEach((b) =>
    b.addEventListener('click', () => run_action(id, 'free-seat', b.dataset.seat)));
});

// ── Actions ───────────────────────────────────────────────────────────────

async function run_action(id, type, machine_id, reason) {
  const body = { license_id: id };
  if (type === 'free-seat') body.machine_id = machine_id;
  if (type === 'revoke') body.reason = reason || 'revoked via admin panel';
  const { ok, data } = await api(`/api/v1/admin/${type}`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
  $('action-result').innerHTML = ok
    ? `<span class="good">✓ ${esc(data.message ?? 'done')}</span>`
    : `<span class="bad">✗ ${esc(data.message ?? `HTTP error`)}</span>`;
  refresh();
}

$('action-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const id = $('action-id').value.trim();
  const type = $('action-type').value;
  const label = { revoke: 'REVOKE', unrevoke: 'RESTORE', 'free-seat': 'FREE SEAT' }[type];
  if (!confirm(`${label} — are you sure you want to do this for ${id}?`)) return;
  run_action(id, type, $('action-machine').value.trim(), $('action-reason').value.trim());
});

// ── Boot ──────────────────────────────────────────────────────────────────

$('refresh').addEventListener('click', refresh);
$('upstream-label').textContent = 'upstream: ' + (location.origin);
refresh();
setInterval(refresh, 30_000);

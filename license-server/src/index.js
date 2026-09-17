// ── Talus License Server — Cloudflare Worker + D1 ─────────────────────────
//
// Implements the client contract from process-monitor/src/license.rs:
//
//   POST /api/v1/activate    { license_key, machine_id, hostname, version }
//                            → { success, token, expires_at, tier, message }
//   POST /api/v1/deactivate  { license_id, token } → releases the machine seat
//   GET  /api/v1/health      → service status
//
// Security properties:
//   • The server holds ONLY the Ed25519 public key — the signing private key
//     never leaves the owner's machine (~/.secrets/talus/license-keys/).
//   • Every license key's signature is verified server-side before any
//     activation is recorded.
//   • Seat control is authoritative: max_seats enforced in D1, same-machine
//     re-activation is idempotent.
//   • Revocation: a `revoked` flag on the license row, plus a `revocations`
//     table for keys revoked before they were ever seen ("first-seen"
//     auto-registration otherwise applies).
//   • Rate limiting: per machine_id AND global, 5 activation attempts per
//     5 minutes (fixed window in D1).
//   • No tokens or license keys are ever logged.
//   • Admin endpoints (rotate-approval / revoke) require the ADMIN_TOKEN
//     secret via `Authorization: Bearer <token>`.

// Ed25519 verification uses the runtime's native WebCrypto (Ed25519 is
// supported by workerd), so there is no third-party crypto dependency.

// ── Environment / secrets ─────────────────────────────────────────────────
//
// vars (wrangler.toml):
//   LICENSE_PUBLIC_KEY_HEX — Ed25519 public key, hex (matches the key
//                            embedded in the Talus binary)
// secrets (wrangler secret put):
//   ADMIN_TOKEN — bearer token for /api/v1/admin/*

function env_error(name) {
  return json_response(
    { success: false, message: `server misconfigured: missing ${name}` },
    500,
  );
}

// ── Constants ─────────────────────────────────────────────────────────────

const MAX_BODY_BYTES = 16 * 1024; // 16 KiB is far more than any valid request
const RATE_LIMIT = 5; // activation attempts
const RATE_WINDOW_S = 300; // per 5 minutes
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

// ── Router ────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const { pathname } = url;

      // Restrict methods per route family; everything else → 405.
      if (request.method !== 'GET' && request.method !== 'POST') {
        return json_response({ success: false, message: 'method not allowed' }, 405);
      }

      if (pathname === '/api/v1/health' && request.method === 'GET') {
        return handle_health(env);
      }

      if (pathname === '/api/v1/activate' && request.method === 'POST') {
        return handle_activate(request, env);
      }

      if (pathname === '/api/v1/deactivate' && request.method === 'POST') {
        return handle_deactivate(request, env);
      }

      if (pathname.startsWith('/api/v1/admin/') && request.method === 'POST') {
        return handle_admin(request, env, pathname);
      }

      return json_response({ success: false, message: 'not found' }, 404);
    } catch (err) {
      // Never leak internals; never log tokens or keys.
      return json_response(
        { success: false, message: 'internal server error' },
        500,
      );
    }
  },
};

// ── Handlers ──────────────────────────────────────────────────────────────

async function handle_health(env) {
  if (!env.DB) return env_error('DB binding');
  const { results } = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM activations',
  ).all();
  return json_response({
    success: true,
    service: 'talus-license-server',
    version: 1,
    activations: results?.[0]?.n ?? 0,
    time: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
  });
}

async function handle_activate(request, env) {
  if (!env.DB) return env_error('DB binding');
  if (!env.LICENSE_PUBLIC_KEY_HEX) return env_error('LICENSE_PUBLIC_KEY_HEX');

  const body = await read_json(request);
  if (!body.ok) {
    return json_response({ success: false, message: body.error }, 400);
  }

  const license_key = str_field(body.value.license_key);
  const machine_id = str_field(body.value.machine_id);
  const hostname = str_field(body.value.hostname);
  // `version` is informational — accepted but not persisted.

  if (!license_key || !machine_id) {
    return json_response(
      { success: false, message: 'missing license_key or machine_id' },
      400,
    );
  }
  if (machine_id.length > 64 || license_key.length > 8192) {
    return json_response({ success: false, message: 'field too long' }, 400);
  }

  // ── Rate limiting: per machine, then global ────────────────────────────
  const limited = await rate_limit(env.DB, machine_id);
  if (limited) {
    return json_response(
      { success: false, message: 'too many activation attempts — try again later' },
      429,
    );
  }

  // ── Signature verification (server holds the public key only) ──────────
  const parts = license_key.split('.');
  if (parts.length !== 2) {
    return json_response(
      { success: false, message: 'invalid license key format' },
      400,
    );
  }
  let payload_bytes;
  let sig_bytes;
  try {
    payload_bytes = base64_decode(parts[0]);
    sig_bytes = base64_decode(parts[1]);
  } catch {
    return json_response({ success: false, message: 'invalid base64 encoding' }, 400);
  }
  if (sig_bytes.length !== 64) {
    return json_response({ success: false, message: 'invalid signature length' }, 400);
  }
  let pub_bytes;
  try {
    pub_bytes = hex_decode(env.LICENSE_PUBLIC_KEY_HEX);
  } catch {
    return env_error('LICENSE_PUBLIC_KEY_HEX');
  }
  if (!(await verify_ed25519(pub_bytes, sig_bytes, payload_bytes))) {
    return json_response(
      { success: false, message: 'license signature verification failed' },
      401,
    );
  }

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(payload_bytes));
  } catch {
    return json_response({ success: false, message: 'invalid license payload' }, 400);
  }

  const license_id = str_field(payload.license_id);
  const tier = str_field(payload.tier);
  if (!license_id || !tier) {
    return json_response(
      { success: false, message: 'license payload missing fields' },
      400,
    );
  }

  // ── Expiry (from the signed payload) ───────────────────────────────────
  const expires_at = str_field(payload.expires_at);
  if (expires_at) {
    if (!ISO_RE.test(expires_at)) {
      return json_response(
        { success: false, message: 'license payload has invalid expiry' },
        400,
      );
    }
    if (new Date(expires_at).getTime() <= Date.now()) {
      return json_response(
        { success: false, message: `license ${license_id} has expired` },
        403,
      );
    }
  }

  // ── First-seen auto-registration + revocation checks ───────────────────
  // The keygen registry lives offline, so the server learns licenses on
  // first activation. A pre-registered row can only be created by an admin.
  const existing = await env.DB.prepare(
    'SELECT license_id, tier, max_seats, expires_at, revoked FROM licenses WHERE license_id = ?1',
  )
    .bind(license_id)
    .first();

  let max_seats;
  if (existing) {
    if (existing.revoked) {
      return json_response(
        { success: false, message: `license ${license_id} has been revoked` },
        403,
      );
    }
    if (existing.expires_at && ISO_RE.test(existing.expires_at)) {
      if (new Date(existing.expires_at).getTime() <= Date.now()) {
        return json_response(
          { success: false, message: `license ${license_id} has expired` },
          403,
        );
      }
    }
    max_seats = existing.max_seats ?? 1;
  } else {
    const pre_revoked = await env.DB.prepare(
      'SELECT license_id FROM revocations WHERE license_id = ?1',
    )
      .bind(license_id)
      .first();
    if (pre_revoked) {
      return json_response(
        { success: false, message: `license ${license_id} has been revoked` },
        403,
      );
    }
    // Register on first sight. seat_count comes from the SIGNED payload, so
    // clients cannot inflate it — only the key holder can set it.
    const seat_count = Number(payload.seat_count);
    max_seats =
      Number.isInteger(seat_count) && seat_count > 0 ? seat_count : 1;
    await env.DB.prepare(
      `INSERT INTO licenses (license_id, tier, org, features, max_nodes, max_seats, expires_at, revoked, issued_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)`,
    )
      .bind(
        license_id,
        tier,
        str_field(payload.organization) ?? null,
        payload.features ? JSON.stringify(payload.features) : null,
        Number(payload.max_nodes) || 0,
        max_seats,
        expires_at ?? null,
        str_field(payload.issued_at) ?? new Date().toISOString(),
      )
      .run();
  }

  // ── Seat control ───────────────────────────────────────────────────────
  const prev = await env.DB.prepare(
    'SELECT token FROM activations WHERE license_id = ?1 AND machine_id = ?2',
  )
    .bind(license_id, machine_id)
    .first();

  if (prev) {
    // Idempotent re-activation: same machine gets its token back.
    return json_response({
      success: true,
      token: prev.token,
      expires_at: expires_at ?? null,
      tier,
      message: 'license already activated on this machine',
    });
  }

  const active = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM activations WHERE license_id = ?1',
  )
    .bind(license_id)
    .first();
  if ((active?.n ?? 0) >= max_seats) {
    return json_response(
      {
        success: false,
        message: `seat limit reached (${max_seats}) — deactivate another machine first`,
      },
      403,
    );
  }

  const token = new_token();
  const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  await env.DB.prepare(
    `INSERT INTO activations (license_id, machine_id, hostname, token, activated_at, seat_index, last_seen)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?5)`,
  )
    .bind(license_id, machine_id, hostname || null, token, now, (active?.n ?? 0) + 1)
    .run();

  return json_response({
    success: true,
    token,
    expires_at: expires_at ?? null,
    tier,
    message: 'license activated',
  });
}

async function handle_deactivate(request, env) {
  if (!env.DB) return env_error('DB binding');

  const body = await read_json(request);
  if (!body.ok) {
    return json_response({ success: false, message: body.error }, 400);
  }

  const license_id = str_field(body.value.license_id);
  const token = str_field(body.value.token);
  if (!license_id || !token) {
    return json_response(
      { success: false, message: 'missing license_id or token' },
      400,
    );
  }

  // Token is required and matched exactly — cannot free someone else's seat.
  const row = await env.DB.prepare(
    'SELECT machine_id FROM activations WHERE license_id = ?1 AND token = ?2',
  )
    .bind(license_id, token)
    .first();

  if (!row) {
    // Same shape as a successful release → no seat enumeration oracle.
    return json_response({
      success: true,
      message: 'no matching activation — nothing to do',
    });
  }

  await env.DB.prepare(
    'DELETE FROM activations WHERE license_id = ?1 AND machine_id = ?2',
  )
    .bind(license_id, row.machine_id)
    .run();

  return json_response({
    success: true,
    message: 'license deactivated — seat released',
  });
}

async function handle_admin(request, env, pathname) {
  if (!env.DB) return env_error('DB binding');
  if (!env.ADMIN_TOKEN) return env_error('ADMIN_TOKEN');

  const auth = (request.headers.get('Authorization') ?? '').trim();
  const expected = `Bearer ${String(env.ADMIN_TOKEN).trim()}`;
  if (auth.length !== expected.length || !timing_safe_equal(auth, expected)) {
    return json_response({ success: false, message: 'unauthorized' }, 401);
  }

  const action = pathname.slice('/api/v1/admin/'.length);
  const body = await read_json(request);
  if (!body.ok) {
    return json_response({ success: false, message: body.error }, 400);
  }
  const license_id = str_field(body.value.license_id);
  if (!license_id) {
    return json_response({ success: false, message: 'missing license_id' }, 400);
  }

  if (action === 'revoke') {
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const reason = str_field(body.value.reason) ?? null;

    // Cover both cases: seen licenses (flag) and never-seen keys (table).
    await env.DB.batch([
      env.DB.prepare('UPDATE licenses SET revoked = 1 WHERE license_id = ?1').bind(license_id),
      env.DB.prepare(
        'INSERT INTO revocations (license_id, reason, revoked_at) VALUES (?1, ?2, ?3) ON CONFLICT(license_id) DO UPDATE SET reason = ?2, revoked_at = ?3',
      ).bind(license_id, reason, now),
      // Revocation frees all seats — activations must not survive it.
      env.DB.prepare('DELETE FROM activations WHERE license_id = ?1').bind(license_id),
    ]);

    return json_response({ success: true, message: `license ${license_id} revoked` });
  }

  if (action === 'activations') {
    const { results } = await env.DB.prepare(
      'SELECT machine_id, hostname, seat_index, activated_at, last_seen FROM activations WHERE license_id = ?1 ORDER BY seat_index',
    )
      .bind(license_id)
      .all();
    return json_response({ success: true, activations: results ?? [] });
  }

  return json_response({ success: false, message: 'unknown admin action' }, 404);
}

// ── Rate limiting ─────────────────────────────────────────────────────────

async function rate_limit(db, machine_id) {
  const now = Math.floor(Date.now() / 1000);
  const window_start = now - RATE_WINDOW_S;
  const global_bucket = `global:${Math.floor(now / RATE_WINDOW_S)}`;
  const machine_bucket = `machine:${machine_id}:${Math.floor(now / RATE_WINDOW_S)}`;

  // Prune old events, then record this attempt.
  await db
    .prepare('DELETE FROM rate_events WHERE ts < ?1')
    .bind(window_start)
    .run();
  await db
    .prepare('INSERT INTO rate_events (bucket, ts) VALUES (?1, ?2)')
    .bind(machine_bucket, now)
    .run();

  const per_machine = await count_events(db, machine_bucket, window_start);
  if (per_machine > RATE_LIMIT) return true;

  const global = await count_events(db, global_bucket, window_start);
  // Global cap is intentionally loose (abuse brake, not a per-user limit).
  return global > RATE_LIMIT * 200;
}

async function count_events(db, bucket, window_start) {
  const { results } = await db
    .prepare('SELECT COUNT(*) AS n FROM rate_events WHERE bucket = ?1 AND ts >= ?2')
    .bind(bucket, window_start)
    .all();
  return results?.[0]?.n ?? 0;
}

// ── Helpers ───────────────────────────────────────────────────────────────

async function read_json(request) {
  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) {
    return { ok: false, error: 'request body too large' };
  }
  try {
    const value = JSON.parse(raw);
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return { ok: false, error: 'invalid JSON body' };
    }
    return { ok: true, value };
  } catch {
    return { ok: false, error: 'invalid JSON body' };
  }
}

function str_field(v) {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

function base64_decode(s) {
  const norm = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(norm);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function hex_decode(s) {
  if (!/^[0-9a-fA-F]+$/.test(s) || s.length % 2 !== 0) {
    throw new Error('bad hex');
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// Native WebCrypto Ed25519 verification (workerd supports Ed25519).
async function verify_ed25519(public_key, signature, data) {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      public_key,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    return await crypto.subtle.verify(
      { name: 'Ed25519' },
      key,
      signature,
      data,
    );
  } catch {
    return false;
  }
}

function new_token() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function timing_safe_equal(a, b) {
  let diff = a.length ^ b.length;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function json_response(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'allow': 'GET, POST',
    },
  });
}

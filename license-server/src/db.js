// ── db.js — D1-compatible storage adapter (primary D1 OR shared Turso) ────
//
// Storage is decoupled from compute so the license API can run on two
// independent platforms (primary: Cloudflare Worker + D1; failover: any
// Web-standard runtime) against ONE shared database. The signing key never
// lives here — only public data travels.
//
// Selection rules (createDB):
//   1. env.DB present (D1 binding)          → native D1, zero behaviour change
//   2. TURSO_DATABASE_URL + TURSO_AUTH_TOKEN → Turso (libSQL) over HTTP
//   3. otherwise                             → null (handlers report env_error)
//
// The adapter reproduces the exact D1 surface used by this worker:
//   db.prepare(sql)            → statement
//   stmt.bind(...args)         → statement (positional args, D1 `?1` style)
//   await stmt.all()           → { results: Row[] }        (objects, not arrays)
//   await stmt.first()         → Row | null
//   await stmt.run()           → { success, meta: { changes, last_row_id } }
//   await db.batch([stmts])    → results[]  (sequential; D1 is atomic, Turso
//                                             is best-effort — acceptable for
//                                             the 2-3 statement admin actions)
//
// Turso transport: POST {base}/v2/pipeline (Hrana v2). Values are encoded as
// {"type":...} pairs and decoded back into plain JS rows so handlers cannot
// tell the difference between D1 and Turso.

export function createDB(env) {
  // 1. Native D1 binding wins (primary mode — unchanged behaviour).
  if (env.DB) return env.DB;

  const url = env.TURSO_DATABASE_URL;
  const token = env.TURSO_AUTH_TOKEN;
  if (!url || !token) return null;
  return turso_db(url, token);
}

// ── Turso (libSQL) over HTTP ──────────────────────────────────────────────

function turso_db(base_url, auth_token) {
  const endpoint =
    base_url.replace(/^libsql:\/\//, 'https://').replace(/\/+$/, '') +
    '/v2/pipeline';

  async function pipeline(statements) {
    const requests = statements.map(({ sql, args }) => ({
      type: 'execute',
      stmt: { sql, args: args.map(encode_arg) },
    }));
    requests.push({ type: 'close' });

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${auth_token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ requests }),
    });
    if (!res.ok) {
      throw new Error(`turso: http ${res.status}`);
    }
    const body = await res.json();
    const results = [];
    for (let i = 0; i < statements.length; i++) {
      const entry = body.results?.[i];
      if (!entry || entry.type !== 'ok') {
        throw new Error(`turso: statement ${i} failed`);
      }
      const response = entry.response;
      if (response.type === 'error') {
        throw new Error(`turso: ${response.error?.message ?? 'query error'}`);
      }
      results.push(response.result);
    }
    return results;
  }

  function statement(sql) {
    // `sql` and `args` MUST be real properties (not closure state):
    // batch() reads them off the statement objects.
    const stmt = { sql, args: [] };
    stmt.bind = (...bound) => {
      stmt.args = bound;
      return stmt;
    };
    stmt.all = async () => {
      const [result] = await pipeline([{ sql, args: stmt.args }]);
      return { results: decode_rows(result) };
    };
    stmt.first = async () => {
      const [result] = await pipeline([{ sql, args: stmt.args }]);
      const rows = decode_rows(result);
      return rows.length > 0 ? rows[0] : null;
    };
    stmt.run = async () => {
      const [result] = await pipeline([{ sql, args: stmt.args }]);
      return {
        success: true,
        meta: {
          changes: result?.affected_row_count ?? 0,
          last_row_id: result?.last_insert_rowid ?? null,
        },
      };
    };
    return stmt;
  }

  return {
    prepare: statement,
    async batch(statements) {
      const list = statements.map((s) => ({ sql: s.sql, args: s.args ?? [] }));
      const results = await pipeline(list);
      // D1 returns one result per statement; handlers only await success.
      return results.map((r) => ({
        success: true,
        meta: { changes: r?.affected_row_count ?? 0 },
      }));
    },
  };
}

function encode_arg(value) {
  if (value === null || value === undefined) return { type: 'null' };
  if (typeof value === 'number') {
    return Number.isInteger(value)
      ? { type: 'integer', value: String(value) }
      : { type: 'float', value };
  }
  if (typeof value === 'bigint') {
    return { type: 'integer', value: value.toString() };
  }
  if (typeof value === 'boolean') {
    return { type: 'integer', value: value ? '1' : '0' };
  }
  return { type: 'text', value: String(value) };
}

function decode_value(cell) {
  if (!cell || cell.type === 'null') return null;
  switch (cell.type) {
    case 'integer':
      return Number.parseInt(cell.value, 10);
    case 'float':
      return Number(cell.value);
    case 'blob':
      return cell.value; // base64 — not used by this schema
    default:
      return cell.value; // text
  }
}

function decode_rows(result) {
  const cols = result?.cols ?? [];
  const rows = result?.rows ?? [];
  return rows.map((row) => {
    const obj = {};
    for (let i = 0; i < cols.length; i++) {
      obj[cols[i].name] = decode_value(row[i]);
    }
    return obj;
  });
}

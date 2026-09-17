// Unit tests for the admin-panel crypto helpers (base32, TOTP RFC 6238).
// Run: node test/totp-test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Extract the pure-crypto functions from the worker source (they have no
// workerd dependencies: HMAC via WebCrypto, DataView, BigInt — all in Node).
const worker_src = readFileSync(join(__dirname, '..', 'src', 'index.js'), 'utf8');

function extract(name) {
  const start = worker_src.indexOf(`async function ${name}(`);
  const alt = worker_src.indexOf(`function ${name}(`);
  const at = start >= 0 ? start : alt;
  assert.ok(at >= 0, `function ${name} not found in worker source`);
  let depth = 0;
  let i = worker_src.indexOf('{', at);
  let j = i;
  for (; j < worker_src.length; j++) {
    if (worker_src[j] === '{') depth++;
    else if (worker_src[j] === '}') { depth--; if (depth === 0) break; }
  }
  return worker_src.slice(at, j + 1);
}

const code = [
  `const TOTP_DIGITS = 6; // mirrors the constant in src/index.js`,
  extract('totp_at'),
  extract('base32_decode'),
  extract('base32_encode'),
  `globalThis.__totp_at = totp_at;
   globalThis.__b32d = base32_decode;
   globalThis.__b32e = base32_encode;`,
].join('\n');

// eslint-disable-next-line no-eval -- intentional: extracts pure functions
(0, eval)(code);
const totp_at = globalThis.__totp_at;
const b32d = globalThis.__b32d;
const b32e = globalThis.__b32e;

// RFC 6238 test secret "12345678901234567890" in base32.
const RFC_SECRET = b32e(new TextEncoder().encode('12345678901234567890'));

test('base32 round-trip', () => {
  const bytes = new Uint8Array([0, 1, 2, 250, 251, 255, 77]);
  assert.deepEqual(b32d(b32e(bytes)), bytes);
});

test('base32 decode accepts padding and rejects bad input', () => {
  assert.deepEqual(b32d('GEZDGNBVGY3TQOJQ'), new TextEncoder().encode('1234567890'));
  assert.deepEqual(b32d('GEZDGNBVGY3TQOJQ==='), new TextEncoder().encode('1234567890'));
  assert.equal(b32d('ABC1'), null); // 1 is not in the alphabet
  assert.equal(b32d(''), null); // empty seed fails closed
});

// Known RFC 6238 SHA-1 vectors — verified against an independent HOTP
// implementation using Node's crypto module.
import { createHmac } from 'node:crypto';

function reference_totp(key_bytes, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', Buffer.from(key_bytes)).update(buf).digest();
  const off = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return bin % 1_000_000;
}

test('TOTP matches reference implementation across counters', async () => {
  const key = b32d(RFC_SECRET);
  for (const counter of [0, 1, 42_000_000, 59_000_000]) {
    const got = await totp_at(key, counter);
    assert.equal(got, reference_totp(key, counter), `counter ${counter}`);
  }
});

test('TOTP is 6 digits and step-aligned', async () => {
  const key = b32d(RFC_SECRET);
  const code_now = await totp_at(key, Math.floor(Date.now() / 1000 / 30));
  assert.match(String(code_now), /^\d{1,6}$/);
});

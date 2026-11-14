/**
 * Unit / fixture tests for the Dynamic Business CMS critical-path suite.
 * No live network / secrets required — SKIP paths and pure helpers only.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  dbCriticalCheckSpecs,
  htmlReflectsXss,
  profilesDumpDetected,
  totpCode,
  TINY_PNG,
  runDbCritical,
  dbCriticalHostAllowed,
  isLegacyJwtAnonKey,
  supabaseAuthStorageKey,
  chunkSupabaseCookie,
  buildSupabaseSsrCookieHeader,
} from '../dist/db-critical.js';
import { catalogEntryFor, CATALOG } from '../dist/catalog.js';

test('db-critical: catalog specs are registered with stable ids', () => {
  const specs = dbCriticalCheckSpecs();
  assert.ok(specs.length >= 8, `expected ≥8 specs, got ${specs.length}`);
  for (const s of specs) {
    assert.match(s.id, /^db\./, `id ${s.id} must be under db.*`);
    const entry = catalogEntryFor(s.id);
    assert.ok(entry, `catalog missing ${s.id} — run npm run catalog`);
    assert.equal(entry!.category, 'dbcms');
  }
  const ids = CATALOG.filter((c) => c.category === 'dbcms').map((c) => c.id);
  assert.deepEqual(ids.sort(), specs.map((s) => s.id).sort());
});

test('db-critical: TINY_PNG is a valid PNG signature', () => {
  assert.equal(TINY_PNG[0], 0x89);
  assert.equal(TINY_PNG[1], 0x50); // P
  assert.equal(TINY_PNG[2], 0x4e); // N
  assert.equal(TINY_PNG[3], 0x47); // G
  assert.ok(TINY_PNG.length < 200);
});

test('db-critical: totpCode is 6 digits and stable within a 30s window', () => {
  const secret = 'JBSWY3DPEHPK3PXP'; // known test vector base32 ("Hello!")
  const t = 1_111_111_110_000; // fixed
  const a = totpCode(secret, t);
  const b = totpCode(secret, t + 1000);
  assert.match(a, /^\d{6}$/);
  assert.equal(a, b);
});

test('db-critical: htmlReflectsXss detects raw payloads', () => {
  const payload = `<img src=x onerror=alert(1)>`;
  assert.equal(htmlReflectsXss(`<html>${payload}</html>`, payload), true);
  assert.equal(htmlReflectsXss('<html>&lt;img src=x onerror=alert(1)&gt;</html>', payload), false);
  assert.equal(htmlReflectsXss('<html>Invalid token</html>', payload), false);
});

test('db-critical: profilesDumpDetected thresholds', () => {
  assert.equal(profilesDumpDetected(401, []), false);
  assert.equal(profilesDumpDetected(403, [{}, {}, {}, {}, {}, {}]), false);
  assert.equal(profilesDumpDetected(200, [{}, {}]), false);
  assert.equal(profilesDumpDetected(200, new Array(6).fill({})), true);
  assert.equal(profilesDumpDetected(200, 'nope'), false);
});

test('db-critical: missing creds produce SKIP passes (no false-fail)', async () => {
  // Ensure role envs are unset for this process.
  const keys = [
    'VTA_EDITOR_EMAIL', 'VTA_EDITOR_PASSWORD',
    'VTA_SUPERADMIN_EMAIL', 'VTA_SUPERADMIN_PASSWORD',
    'VTA_USER_EMAIL', 'VTA_USER_PASSWORD',
    'VTA_UNPUBLISHED_ARTICLE_URL', 'VTA_STRIPE_AMOUNT_PROBE',
  ];
  const saved: Record<string, string | undefined> = {};
  for (const k of keys) { saved[k] = process.env[k]; delete process.env[k]; }

  try {
    const findings = await runDbCritical('https://example.com', { timeoutMs: 5000, allowAnyHost: true });
    assert.ok(findings.length >= 8);
    for (const f of findings) {
      if (f.id.startsWith('db.auth.') || f.id === 'db.api.uploads-ad' || f.id === 'db.api.uploads-empty'
        || f.id === 'db.api.profiles-rls' || f.id === 'db.editorial.golden-path' || f.id === 'db.api.stripe-amount') {
        assert.equal(f.pass, true, `${f.id} must SKIP-pass without creds, got fail: ${f.detail}`);
        assert.match(f.detail, /^SKIP:/i, `${f.id} detail should start with SKIP:`);
      }
    }
    // Probe checks (ad-track / unsubscribe) may pass or fail against example.com — either is fine;
    // they must not crash the suite.
    assert.ok(findings.every((f) => typeof f.id === 'string'));
  } finally {
    for (const k of keys) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
});

test('db-critical: isLegacyJwtAnonKey detects JWT anon, not publishable', () => {
  assert.equal(isLegacyJwtAnonKey('sb_publishable_x'), false);
  assert.equal(isLegacyJwtAnonKey(''), false);
  const legacy =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBnb2ZkcGFpbG1oaXV1em55endhIiwicm9sZSI6ImFub24iLCJpYXQiOjE2NzgzNDU4MzUsImV4cCI6MTk5MzkyMTgzNX0.1m9z0lWiULuq_x5cdyFwHHao7_ea4XeZvHVuCG6tnSU';
  assert.equal(isLegacyJwtAnonKey(legacy), true);
});

test('db-critical: supabaseAuthStorageKey prefers iss project ref', () => {
  // header.payload.sig — payload iss = https://pgofdpailmhiuuznyzwa.supabase.co
  const payload = Buffer.from(JSON.stringify({
    iss: 'https://pgofdpailmhiuuznyzwa.supabase.co/auth/v1',
    role: 'authenticated',
  })).toString('base64url');
  const token = `eyJhbGciOiJub25lIn0.${payload}.x`;
  assert.equal(
    supabaseAuthStorageKey(token, 'https://db.dynamicbusiness.com'),
    'sb-pgofdpailmhiuuznyzwa-auth-token',
  );
});

test('db-critical: chunkSupabaseCookie splits oversized values', () => {
  const key = 'sb-test-auth-token';
  const small = chunkSupabaseCookie(key, 'abc');
  assert.deepEqual(small, [{ name: key, value: 'abc' }]);
  const big = 'x'.repeat(4000);
  const parts = chunkSupabaseCookie(key, big, 100);
  assert.ok(parts.length > 1);
  assert.equal(parts[0]!.name, `${key}.0`);
  assert.equal(parts.map((p) => p.value).join(''), big);
});

test('db-critical: buildSupabaseSsrCookieHeader is base64- prefixed', () => {
  const payload = Buffer.from(JSON.stringify({
    iss: 'https://abc123.supabase.co/auth/v1',
  })).toString('base64url');
  const access = `eyJhbGciOiJub25lIn0.${payload}.sig`;
  const header = buildSupabaseSsrCookieHeader({
    access_token: access,
    refresh_token: 'r',
    expires_in: 3600,
    user: { id: 'u1' },
  }, 'https://db.example.com');
  assert.match(header, /^sb-abc123-auth-token(\.\d+)?=base64-/);
  assert.ok(!header.includes('eyJhbGciOiJub25lIn0'), 'raw JWT must not appear unencoded in cookie name path');
});

test('db-critical: staff tokens only go to dynamicbusiness.com unless allowAnyHost', async () => {
  assert.equal(dbCriticalHostAllowed('https://dynamicbusiness.com'), true);
  assert.equal(dbCriticalHostAllowed('beta.dynamicbusiness.com'), true);
  assert.equal(dbCriticalHostAllowed('https://evil.example'), false);
  assert.equal(dbCriticalHostAllowed('https://dynamicbusiness.com.evil.example'), false);
  assert.equal(dbCriticalHostAllowed('https://notdynamicbusiness.com'), false);

  // Creds set + a non-DB host: the suite must not log in or send anything.
  const saved = { e: process.env.VTA_EDITOR_EMAIL, p: process.env.VTA_EDITOR_PASSWORD };
  process.env.VTA_EDITOR_EMAIL = 'editor@example.invalid';
  process.env.VTA_EDITOR_PASSWORD = 'not-a-real-password';
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => { calls++; throw new Error('network disabled in test'); }) as typeof fetch;
  try {
    const findings = await runDbCritical('https://evil.example', { timeoutMs: 1000 });
    assert.equal(calls, 0, 'db-critical made network calls to a non-DB host');
    assert.equal(findings.length, 1);
    assert.equal(findings[0].id, 'db.host-gate');
    assert.match(findings[0].detail, /^SKIP:/);
  } finally {
    globalThis.fetch = realFetch;
    if (saved.e === undefined) delete process.env.VTA_EDITOR_EMAIL; else process.env.VTA_EDITOR_EMAIL = saved.e;
    if (saved.p === undefined) delete process.env.VTA_EDITOR_PASSWORD; else process.env.VTA_EDITOR_PASSWORD = saved.p;
  }
});

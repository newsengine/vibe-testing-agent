/**
 * Staff AAL2 step-up for the DB critical suite: Supabase MFA challenge + verify.
 * No network: fetch is stubbed. The seed is a throwaway test value.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifiedTotpFactor, stepUpToAal2, totpCode } from '../dist/db-critical.js';

const SEED = 'JBSWY3DPEHPK3PXP'; // RFC test-style dummy, not a real account seed

test('verifiedTotpFactor picks only a verified TOTP factor', () => {
  assert.equal(verifiedTotpFactor(null), null);
  assert.equal(verifiedTotpFactor({ factors: [{ id: 'a', status: 'unverified', factor_type: 'totp' }] }), null);
  assert.equal(verifiedTotpFactor({ factors: [{ id: 'p', status: 'verified', factor_type: 'phone' }] }), null);
  assert.equal(verifiedTotpFactor({ factors: [{ id: 'b', status: 'verified', factor_type: 'totp' }] }), 'b');
});

test('stepUpToAal2 does challenge then verify and returns the aal2 session', async () => {
  const calls: Array<{ url: string; body: any; auth: string }> = [];
  const orig = globalThis.fetch;
  globalThis.fetch = (async (url: string, init: any) => {
    calls.push({ url, body: JSON.parse(init.body), auth: init.headers.authorization });
    if (url.endsWith('/challenge')) return new Response(JSON.stringify({ id: 'ch1' }), { status: 200 });
    return new Response(JSON.stringify({ access_token: 'aal2-at', refresh_token: 'rt', expires_in: 3600 }), { status: 200 });
  }) as any;
  try {
    const r = await stepUpToAal2('https://x.supabase.co', 'anon', 'aal1-at', 'f1', SEED);
    assert.ok('session' in r);
    assert.equal((r as any).session.access_token, 'aal2-at');
    assert.equal(calls[0]!.url, 'https://x.supabase.co/auth/v1/factors/f1/challenge');
    assert.equal(calls[1]!.url, 'https://x.supabase.co/auth/v1/factors/f1/verify');
    assert.equal(calls[1]!.body.challenge_id, 'ch1');
    assert.match(calls[1]!.body.code, /^\d{6}$/);
    assert.equal(calls[0]!.auth, 'Bearer aal1-at');
  } finally {
    globalThis.fetch = orig;
  }
});

test('stepUpToAal2 error never contains the seed or a code', async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = (async (url: string) => {
    if (url.endsWith('/challenge')) return new Response(JSON.stringify({ id: 'ch' }), { status: 200 });
    return new Response(JSON.stringify({ error_code: 'mfa_verification_failed' }), { status: 422 });
  }) as any;
  try {
    const r = await stepUpToAal2('https://x', 'anon', 't', 'f', SEED);
    assert.ok('error' in r);
    const msg = (r as any).error as string;
    assert.match(msg, /verify 422/);
    assert.ok(!msg.includes(SEED));
    assert.ok(!/\b\d{6}\b/.test(msg.replace('422', '')));
    assert.ok(!msg.includes(totpCode(SEED)));
  } finally {
    globalThis.fetch = orig;
  }
});

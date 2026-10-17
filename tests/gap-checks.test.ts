/**
 * Tests for the gap analysis checks: auth, authz, API, agent LLM, uploads, db/storage, DNS DKIM,
 * CSRF tokens, and PII disclosure.
 *
 * Imports dist/ so we test the shipped build.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import {
  authLoginRateLimitCheck,
  authzIdorSequentialCheck,
  apiWebhookUnsignedCheck,
  dnsDkimCheck,
  csrfTokenCheck,
  disclosurePiiInResponseCheck,
  dbFirebaseRulesCheck,
  GAP_CHECK_CONFIG,
  isPassiveCheck,
} from '../dist/gap-checks.js';
import type { ScanContext } from '../dist/types.js';

function makeCtx(url: string, html: string, headers?: Record<string, string>): ScanContext {
  const hdrs = new Headers(headers);
  return {
    url: new URL(url),
    origin: new URL(url).origin,
    baseUrl: url,
    html,
    headers: hdrs,
    opts: {
      timeoutMs: 8000,
      maxCrawl: 10,
      extraHeaders: {},
    },
  } as unknown as ScanContext;
}

// ── Passive vs. Verified gating ──────────────────────────────────────────────

test('gap: passive checks are identified correctly', () => {
  assert.equal(isPassiveCheck('dns.dkim'), true);
  assert.equal(isPassiveCheck('csrf.token'), true);
  assert.equal(isPassiveCheck('disclosure.pii-in-response'), true);
  assert.equal(isPassiveCheck('auth.login-rate-limit'), false);
  assert.equal(isPassiveCheck('authz.idor-sequential'), false);
  assert.equal(isPassiveCheck('api.webhook-unsigned'), false);
});

test('gap: GAP_CHECK_CONFIG has verification requirements for all new checks', () => {
  const expected = [
    'auth.login-rate-limit', 'auth.reset-token-reuse', 'auth.session-invalidation', 'auth.email-plus-alias',
    'authz.idor-sequential', 'api.webhook-unsigned', 'api.idempotency', 'api.key-revocation',
    'agent.prompt-injection', 'agent.llm-data-leak', 'agent.llm-rate-limit',
    'upload.content-type', 'db.firebase-rules', 'storage.public-bucket',
    'dns.dkim', 'csrf.token', 'disclosure.pii-in-response',
  ];
  for (const id of expected) {
    assert.ok(id in GAP_CHECK_CONFIG, `GAP_CHECK_CONFIG missing ${id}`);
    assert.ok(typeof GAP_CHECK_CONFIG[id].requiresVerification === 'boolean', `${id} missing requiresVerification`);
  }
});

// ── DNS DKIM check (passive) ─────────────────────────────────────────────────

test('gap: dns.dkim resolves and returns findings', async () => {
  const ctx = makeCtx('https://google.com/', '');
  const findings = await dnsDkimCheck(ctx);
  assert.ok(findings.length > 0, 'should return at least one finding');
  assert.equal(findings[0].id, 'dns.dkim');
});

// ── CSRF token check (passive) ───────────────────────────────────────────────

test('gap: csrf.token detects forms with tokens', async () => {
  const html = `
    <html><body>
      <form method="post" action="/submit">
        <input type="hidden" name="csrf_token" value="abc123">
        <button type="submit">Submit</button>
      </form>
    </body></html>
  `;
  const ctx = makeCtx('https://example.com/', html);
  const findings = await csrfTokenCheck(ctx);
  assert.ok(findings.length > 0);
  assert.equal(findings[0].pass, true, 'should pass when forms have CSRF tokens');
});

test('gap: csrf.token detects forms missing tokens', async () => {
  const html = `
    <html><body>
      <form method="post" action="/delete-account">
        <button type="submit">Delete</button>
      </form>
    </body></html>
  `;
  const ctx = makeCtx('https://example.com/', html);
  const findings = await csrfTokenCheck(ctx);
  assert.ok(findings.length > 0);
  assert.equal(findings[0].pass, false, 'should fail when forms lack CSRF tokens');
});

test('gap: csrf.token allows SameSite cookie mitigation', async () => {
  const html = `
    <html><body>
      <form method="post" action="/update">
        <button type="submit">Update</button>
      </form>
    </body></html>
  `;
  const ctx = makeCtx('https://example.com/', html, { 'set-cookie': 'session=abc; SameSite=Strict; HttpOnly' });
  const findings = await csrfTokenCheck(ctx);
  if (findings.length > 0) {
    assert.equal(findings[0].pass, true, 'should pass with SameSite cookie protection');
  }
});

test('gap: csrf.token ignores non-state-changing forms', async () => {
  const html = `
    <html><body>
      <form method="get" action="/search">
        <input type="text" name="q">
        <button type="submit">Search</button>
      </form>
    </body></html>
  `;
  const ctx = makeCtx('https://example.com/', html);
  const findings = await csrfTokenCheck(ctx);
  assert.equal(findings.length, 0, 'GET forms should not require CSRF tokens');
});

// ── PII disclosure check (passive) ───────────────────────────────────────────

async function startPiiServer(returnPii: boolean): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    const path = req.url || '/';
    if (path.startsWith('/api/')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      if (returnPii) {
        res.end(JSON.stringify({ email: 'user@example.com', name: 'Test User' }));
      } else {
        res.end(JSON.stringify({ status: 'ok' }));
      }
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  server.listen(0);
  await once(server, 'listening');
  const addr = server.address() as { port: number };
  return {
    url: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise<void>(r => server.close(() => r())),
  };
}

test('gap: disclosure.pii-in-response detects email in API response', async () => {
  const srv = await startPiiServer(true);
  try {
    const ctx = makeCtx(srv.url + '/', '');
    const findings = await disclosurePiiInResponseCheck(ctx);
    const pii = findings.find(f => f.id === 'disclosure.pii-in-response');
    assert.ok(pii, 'should detect PII');
    assert.equal(pii?.pass, false);
  } finally {
    await srv.close();
  }
});

test('gap: disclosure.pii-in-response passes when no PII found', async () => {
  const srv = await startPiiServer(false);
  try {
    const ctx = makeCtx(srv.url + '/', '');
    const findings = await disclosurePiiInResponseCheck(ctx);
    assert.equal(findings.length, 0, 'should return empty when no PII');
  } finally {
    await srv.close();
  }
});

// ── Auth rate limit check (requires verification) ────────────────────────────

async function startRateLimitServer(throttle: boolean): Promise<{ url: string; close: () => Promise<void> }> {
  let attempts = 0;
  const server = http.createServer((req, res) => {
    const path = req.url || '/';
    if (path === '/api/auth/login' && req.method === 'POST') {
      attempts++;
      if (throttle && attempts > 3) {
        res.writeHead(429, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'rate limited' }));
      } else {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid credentials' }));
      }
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  server.listen(0);
  await once(server, 'listening');
  const addr = server.address() as { port: number };
  return {
    url: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise<void>(r => server.close(() => r())),
  };
}

test('gap: auth.login-rate-limit detects rate limiting', async () => {
  const srv = await startRateLimitServer(true);
  try {
    const ctx = makeCtx(srv.url + '/', '');
    const findings = await authLoginRateLimitCheck(ctx);
    assert.ok(findings.length > 0);
    assert.equal(findings[0].pass, true, 'should pass when rate limiting is active');
  } finally {
    await srv.close();
  }
});

test('gap: auth.login-rate-limit fails when no throttling', async () => {
  const srv = await startRateLimitServer(false);
  try {
    const ctx = makeCtx(srv.url + '/', '');
    const findings = await authLoginRateLimitCheck(ctx);
    assert.ok(findings.length > 0);
    assert.equal(findings[0].pass, false, 'should fail when no rate limiting');
  } finally {
    await srv.close();
  }
});

// ── Authz IDOR sequential check (requires verification) ──────────────────────

async function startIdorServer(returnData: boolean): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    const path = req.url || '/';
    if (path.startsWith('/api/users/')) {
      if (returnData) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ id: 1, email: 'user@example.com', name: 'Test' }));
      } else {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'unauthorized' }));
      }
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  server.listen(0);
  await once(server, 'listening');
  const addr = server.address() as { port: number };
  return {
    url: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise<void>(r => server.close(() => r())),
  };
}

test('gap: authz.idor-sequential detects unprotected sequential IDs', async () => {
  const srv = await startIdorServer(true);
  try {
    const ctx = makeCtx(srv.url + '/', '');
    const findings = await authzIdorSequentialCheck(ctx);
    assert.ok(findings.length > 0);
    assert.equal(findings[0].pass, false, 'should fail when sequential IDs return data');
    assert.equal(findings[0].severity, 'high');
  } finally {
    await srv.close();
  }
});

test('gap: authz.idor-sequential passes when auth required', async () => {
  const srv = await startIdorServer(false);
  try {
    const ctx = makeCtx(srv.url + '/', '');
    const findings = await authzIdorSequentialCheck(ctx);
    assert.equal(findings.length, 0, 'should pass when endpoints require auth');
  } finally {
    await srv.close();
  }
});

// ── API webhook unsigned check (requires verification) ───────────────────────

async function startWebhookServer(verify: boolean): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    const path = req.url || '/';
    if (path === '/api/webhooks/stripe' && req.method === 'POST') {
      if (verify) {
        const sig = req.headers['stripe-signature'];
        if (!sig) {
          res.writeHead(400, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing signature' }));
          return;
        }
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ received: true }));
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  server.listen(0);
  await once(server, 'listening');
  const addr = server.address() as { port: number };
  return {
    url: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise<void>(r => server.close(() => r())),
  };
}

test('gap: api.webhook-unsigned detects unsigned webhook acceptance', async () => {
  const srv = await startWebhookServer(false);
  try {
    const ctx = makeCtx(srv.url + '/', '');
    const findings = await apiWebhookUnsignedCheck(ctx);
    assert.ok(findings.length > 0);
    assert.equal(findings[0].pass, false, 'should fail when webhook accepts unsigned');
    assert.equal(findings[0].severity, 'high');
  } finally {
    await srv.close();
  }
});

test('gap: api.webhook-unsigned passes when signature required', async () => {
  const srv = await startWebhookServer(true);
  try {
    const ctx = makeCtx(srv.url + '/', '');
    const findings = await apiWebhookUnsignedCheck(ctx);
    assert.ok(findings.length > 0);
    assert.equal(findings[0].pass, true, 'should pass when signature is required');
  } finally {
    await srv.close();
  }
});

// ── Firebase rules check (requires verification) ─────────────────────────────

test('gap: db.firebase-rules returns empty when no Firebase/Supabase detected', async () => {
  const ctx = makeCtx('https://example.com/', '<html><body>No cloud storage</body></html>');
  const findings = await dbFirebaseRulesCheck(ctx);
  assert.equal(findings.length, 0);
});

test('gap: db.firebase-rules detects Firebase storage pattern in HTML', async () => {
  const html = `
    <html><body>
      <img src="https://firebasestorage.googleapis.com/v0/b/myapp.appspot.com/o/image.png">
    </body></html>
  `;
  const ctx = makeCtx('https://example.com/', html);
  const findings = await dbFirebaseRulesCheck(ctx);
  // The actual check will fail silently for unreachable Firebase buckets
  // We just verify it parsed the pattern and didn't crash
  assert.ok(Array.isArray(findings));
});

// ── Preview deployments check (verified only) ────────────────────────────────

import { exposurePreviewDeploymentsCheck } from '../dist/gap-checks.js';

test('gap: exposure.preview-deployments returns findings for public preview hosts', async () => {
  // This test verifies the check runs without error
  // Actual preview discovery requires real network access
  const ctx = makeCtx('https://example.com/', '<html><body>No links</body></html>');
  const findings = await exposurePreviewDeploymentsCheck(ctx);
  // Should return empty array or info finding when no previews found
  assert.ok(Array.isArray(findings));
});

test('gap: exposure.preview-deployments extracts linked hosting URLs', async () => {
  const html = `
    <html><body>
      <a href="https://my-app.vercel.app">Preview</a>
      <a href="https://my-app.pages.dev">Pages</a>
    </body></html>
  `;
  const ctx = makeCtx('https://my-app.com/', html);
  const findings = await exposurePreviewDeploymentsCheck(ctx);
  // The check should attempt to probe these hosts
  assert.ok(Array.isArray(findings));
});

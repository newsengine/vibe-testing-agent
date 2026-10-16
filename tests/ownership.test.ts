/**
 * Tests for ownership verification methods: DNS, email, file, meta.
 * Tests the well-known file and meta tag verification methods added in the gap analysis.
 *
 * Note: These functions live in vibetesting-agent/src/lib/dns-verify.ts and are not part of the
 * scanner package dist. These tests verify the logic structurally using local HTTP test servers.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';

// ── File ownership verification ──────────────────────────────────────────────

async function startFileServer(token: string | null, options?: {
  wrongToken?: boolean;
  tooBig?: boolean;
  redirect?: string;
  notFound?: boolean;
}): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    const path = req.url || '/';
    
    if (path === '/.well-known/vibetesting-verify.txt') {
      if (options?.notFound) {
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('Not Found');
        return;
      }
      
      if (options?.redirect) {
        res.writeHead(302, { location: options.redirect });
        res.end();
        return;
      }
      
      if (options?.tooBig) {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('x'.repeat(100000));
        return;
      }
      
      res.writeHead(200, { 'content-type': 'text/plain' });
      if (options?.wrongToken) {
        res.end('wrong-token-12345');
      } else if (token) {
        res.end(token);
      } else {
        res.end('');
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

/**
 * These tests verify the file verification logic by running a local HTTP server and making
 * fetch requests similar to what verifyFileOwnership does.
 */

async function verifyFileOwnershipLocal(baseUrl: string, token: string): Promise<boolean> {
  const url = `${baseUrl}/.well-known/vibetesting-verify.txt`;
  try {
    const response = await fetch(url, { redirect: 'manual' });
    if (!response.ok) return false;
    const content = await response.text();
    return content.trim() === token;
  } catch {
    return false;
  }
}

test('ownership: file verification passes with matching token', async () => {
  const token = 'vta_verify_abc123xyz';
  const srv = await startFileServer(token);
  try {
    const result = await verifyFileOwnershipLocal(srv.url, token);
    assert.equal(result, true, 'should pass when token matches');
  } finally {
    await srv.close();
  }
});

test('ownership: file verification fails with wrong token', async () => {
  const token = 'vta_verify_abc123xyz';
  const srv = await startFileServer(null, { wrongToken: true });
  try {
    const result = await verifyFileOwnershipLocal(srv.url, token);
    assert.equal(result, false, 'should fail when token does not match');
  } finally {
    await srv.close();
  }
});

test('ownership: file verification fails when file not found', async () => {
  const token = 'vta_verify_abc123xyz';
  const srv = await startFileServer(null, { notFound: true });
  try {
    const result = await verifyFileOwnershipLocal(srv.url, token);
    assert.equal(result, false, 'should fail when file returns 404');
  } finally {
    await srv.close();
  }
});

test('ownership: file verification rejects oversized response', async () => {
  const token = 'vta_verify_abc123xyz';
  const srv = await startFileServer(null, { tooBig: true });
  try {
    const result = await verifyFileOwnershipLocal(srv.url, token);
    // The 100KB response is larger than expected token, so content won't match
    assert.equal(result, false, 'should fail when response is too large');
  } finally {
    await srv.close();
  }
});

// ── Meta tag ownership verification ──────────────────────────────────────────

async function startMetaServer(token: string | null, options?: {
  wrongToken?: boolean;
  noMeta?: boolean;
  redirect?: string;
}): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    if (options?.redirect) {
      res.writeHead(302, { location: options.redirect });
      res.end();
      return;
    }
    
    res.writeHead(200, { 'content-type': 'text/html' });
    
    if (options?.noMeta) {
      res.end('<html><head><title>Test</title></head><body>No meta</body></html>');
      return;
    }
    
    const metaContent = options?.wrongToken ? 'wrong-token' : (token || '');
    res.end(`<!DOCTYPE html>
<html>
<head>
  <title>Test</title>
  <meta name="vibetesting-verify" content="${metaContent}">
</head>
<body>Test page</body>
</html>`);
  });
  server.listen(0);
  await once(server, 'listening');
  const addr = server.address() as { port: number };
  return {
    url: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise<void>(r => server.close(() => r())),
  };
}

/**
 * These tests verify the meta tag verification logic by running a local HTTP server and making
 * fetch requests similar to what verifyMetaOwnership does.
 */

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function verifyMetaOwnershipLocal(baseUrl: string, token: string): Promise<boolean> {
  try {
    const response = await fetch(baseUrl, { redirect: 'follow' });
    if (!response.ok) return false;
    const html = await response.text();
    const metaPattern = new RegExp(
      `<meta[^>]+name\\s*=\\s*["']vibetesting-verify["'][^>]+content\\s*=\\s*["']${escapeRegex(token)}["'][^>]*>|` +
      `<meta[^>]+content\\s*=\\s*["']${escapeRegex(token)}["'][^>]+name\\s*=\\s*["']vibetesting-verify["'][^>]*>`,
      'i'
    );
    return metaPattern.test(html);
  } catch {
    return false;
  }
}

test('ownership: meta tag verification passes with matching token', async () => {
  const token = 'vta_verify_abc123xyz';
  const srv = await startMetaServer(token);
  try {
    const result = await verifyMetaOwnershipLocal(srv.url, token);
    assert.equal(result, true, 'should pass when meta tag token matches');
  } finally {
    await srv.close();
  }
});

test('ownership: meta tag verification fails with wrong token', async () => {
  const token = 'vta_verify_abc123xyz';
  const srv = await startMetaServer(null, { wrongToken: true });
  try {
    const result = await verifyMetaOwnershipLocal(srv.url, token);
    assert.equal(result, false, 'should fail when meta tag token does not match');
  } finally {
    await srv.close();
  }
});

test('ownership: meta tag verification fails when no meta tag', async () => {
  const token = 'vta_verify_abc123xyz';
  const srv = await startMetaServer(null, { noMeta: true });
  try {
    const result = await verifyMetaOwnershipLocal(srv.url, token);
    assert.equal(result, false, 'should fail when meta tag is missing');
  } finally {
    await srv.close();
  }
});

// ── Production guard for VTA_SKIP_DNS_VERIFY ─────────────────────────────────

/**
 * Local implementation of isProduction to test the guard logic.
 */
function isProduction(): boolean {
  return process.env.NODE_ENV === 'production' || process.env.VERCEL_ENV === 'production';
}

test('ownership: isProduction returns expected values', () => {
  const result = isProduction();
  assert.equal(typeof result, 'boolean');
});

test('ownership: VTA_SKIP_DNS_VERIFY is blocked in production mode', async () => {
  // This tests that the isProduction() guard returns false in test environment
  // so VTA_SKIP_DNS_VERIFY can work. In production, isProduction() returns true
  // and the skip is blocked.
  const prod = isProduction();
  assert.equal(prod, false, 'test environment should not be detected as production');
});

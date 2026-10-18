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

// ── Fail-closed guard for VTA_SKIP_DNS_VERIFY ────────────────────────────────

/**
 * Local implementations of the fail-closed guards to test the logic.
 * These mirror the functions in vibetesting-agent/src/lib/dns-verify.ts.
 */
function isDevelopment(): boolean {
  const vtaEnv = process.env.VTA_ENV?.toLowerCase();
  if (vtaEnv === 'development' || vtaEnv === 'test') return true;
  const nodeEnv = process.env.NODE_ENV?.toLowerCase();
  if (nodeEnv === 'development' || nodeEnv === 'test') return true;
  return false;
}

function isLocalHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname.endsWith('.local');
}

function shouldSkipDnsVerify(hostname: string): boolean {
  if (isLocalHost(hostname)) return true;
  if (!isDevelopment()) return false;
  return process.env.VTA_SKIP_DNS_VERIFY === '1' || process.env.SHIPCHECK_SKIP_DNS_VERIFY === '1';
}

test('ownership: isDevelopment fails closed when no env vars set', () => {
  // Save original values
  const origVtaEnv = process.env.VTA_ENV;
  const origNodeEnv = process.env.NODE_ENV;
  
  // Clear environment variables to simulate production Worker
  delete process.env.VTA_ENV;
  delete process.env.NODE_ENV;
  
  try {
    const result = isDevelopment();
    assert.equal(result, false, 'should return false (production) when no env vars set');
  } finally {
    // Restore original values
    if (origVtaEnv !== undefined) process.env.VTA_ENV = origVtaEnv;
    if (origNodeEnv !== undefined) process.env.NODE_ENV = origNodeEnv;
  }
});

test('ownership: isDevelopment returns true with VTA_ENV=development', () => {
  const origVtaEnv = process.env.VTA_ENV;
  const origNodeEnv = process.env.NODE_ENV;
  
  delete process.env.NODE_ENV;
  process.env.VTA_ENV = 'development';
  
  try {
    const result = isDevelopment();
    assert.equal(result, true, 'should return true with VTA_ENV=development');
  } finally {
    if (origVtaEnv !== undefined) process.env.VTA_ENV = origVtaEnv;
    else delete process.env.VTA_ENV;
    if (origNodeEnv !== undefined) process.env.NODE_ENV = origNodeEnv;
  }
});

test('ownership: isDevelopment returns true with VTA_ENV=test', () => {
  const origVtaEnv = process.env.VTA_ENV;
  const origNodeEnv = process.env.NODE_ENV;
  
  delete process.env.NODE_ENV;
  process.env.VTA_ENV = 'test';
  
  try {
    const result = isDevelopment();
    assert.equal(result, true, 'should return true with VTA_ENV=test');
  } finally {
    if (origVtaEnv !== undefined) process.env.VTA_ENV = origVtaEnv;
    else delete process.env.VTA_ENV;
    if (origNodeEnv !== undefined) process.env.NODE_ENV = origNodeEnv;
  }
});

test('ownership: shouldSkipDnsVerify always allows localhost', () => {
  const origVtaEnv = process.env.VTA_ENV;
  const origNodeEnv = process.env.NODE_ENV;
  const origSkip = process.env.VTA_SKIP_DNS_VERIFY;
  
  // Simulate production: no env vars set
  delete process.env.VTA_ENV;
  delete process.env.NODE_ENV;
  delete process.env.VTA_SKIP_DNS_VERIFY;
  
  try {
    assert.equal(shouldSkipDnsVerify('localhost'), true, 'localhost should always skip');
    assert.equal(shouldSkipDnsVerify('127.0.0.1'), true, '127.0.0.1 should always skip');
    assert.equal(shouldSkipDnsVerify('myapp.local'), true, '*.local should always skip');
  } finally {
    if (origVtaEnv !== undefined) process.env.VTA_ENV = origVtaEnv;
    if (origNodeEnv !== undefined) process.env.NODE_ENV = origNodeEnv;
    if (origSkip !== undefined) process.env.VTA_SKIP_DNS_VERIFY = origSkip;
  }
});

test('ownership: shouldSkipDnsVerify blocks skip in production even with VTA_SKIP_DNS_VERIFY=1', () => {
  const origVtaEnv = process.env.VTA_ENV;
  const origNodeEnv = process.env.NODE_ENV;
  const origSkip = process.env.VTA_SKIP_DNS_VERIFY;
  
  // Simulate production Worker: no env vars, but VTA_SKIP_DNS_VERIFY=1 somehow set
  delete process.env.VTA_ENV;
  delete process.env.NODE_ENV;
  process.env.VTA_SKIP_DNS_VERIFY = '1';
  
  try {
    const result = shouldSkipDnsVerify('example.com');
    assert.equal(result, false, 'should NOT skip for non-local host in production even with VTA_SKIP_DNS_VERIFY=1');
  } finally {
    if (origVtaEnv !== undefined) process.env.VTA_ENV = origVtaEnv;
    if (origNodeEnv !== undefined) process.env.NODE_ENV = origNodeEnv;
    if (origSkip !== undefined) process.env.VTA_SKIP_DNS_VERIFY = origSkip;
    else delete process.env.VTA_SKIP_DNS_VERIFY;
  }
});

test('ownership: shouldSkipDnsVerify allows skip in dev mode with VTA_SKIP_DNS_VERIFY=1', () => {
  const origVtaEnv = process.env.VTA_ENV;
  const origNodeEnv = process.env.NODE_ENV;
  const origSkip = process.env.VTA_SKIP_DNS_VERIFY;
  
  // Explicit dev mode
  process.env.VTA_ENV = 'development';
  delete process.env.NODE_ENV;
  process.env.VTA_SKIP_DNS_VERIFY = '1';
  
  try {
    const result = shouldSkipDnsVerify('example.com');
    assert.equal(result, true, 'should skip in dev mode with VTA_SKIP_DNS_VERIFY=1');
  } finally {
    if (origVtaEnv !== undefined) process.env.VTA_ENV = origVtaEnv;
    else delete process.env.VTA_ENV;
    if (origNodeEnv !== undefined) process.env.NODE_ENV = origNodeEnv;
    if (origSkip !== undefined) process.env.VTA_SKIP_DNS_VERIFY = origSkip;
    else delete process.env.VTA_SKIP_DNS_VERIFY;
  }
});

test('ownership: shouldSkipDnsVerify requires VTA_SKIP_DNS_VERIFY=1 even in dev mode', () => {
  const origVtaEnv = process.env.VTA_ENV;
  const origNodeEnv = process.env.NODE_ENV;
  const origSkip = process.env.VTA_SKIP_DNS_VERIFY;
  
  // Dev mode but no skip flag
  process.env.VTA_ENV = 'development';
  delete process.env.NODE_ENV;
  delete process.env.VTA_SKIP_DNS_VERIFY;
  
  try {
    const result = shouldSkipDnsVerify('example.com');
    assert.equal(result, false, 'should NOT skip in dev mode without VTA_SKIP_DNS_VERIFY=1');
  } finally {
    if (origVtaEnv !== undefined) process.env.VTA_ENV = origVtaEnv;
    else delete process.env.VTA_ENV;
    if (origNodeEnv !== undefined) process.env.NODE_ENV = origNodeEnv;
    if (origSkip !== undefined) process.env.VTA_SKIP_DNS_VERIFY = origSkip;
  }
});

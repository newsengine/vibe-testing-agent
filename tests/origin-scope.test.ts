// tests/origin-scope.test.ts — scan credentials (--cookie, --header, CF bypass keys) must stay on the
// target origin: across redirects, in plugin templates, and in the browser crawl.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { safeFetch, fetchText, fetchFollowingRedirects } from '../dist/core.js';
import { validateTemplate, isSameOriginPath, pluginChecks } from '../dist/plugins.js';
import { cookieHeaderToCookies } from '../dist/crawl.js';

function server(handler: http.RequestListener): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const s = http.createServer(handler);
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address() as any;
      resolve({ url: `http://127.0.0.1:${addr.port}`, close: () => s.close() });
    });
  });
}

// ── redirects ──────────────────────────────────────────────────────────────
test('redirect: caller headers are dropped once a hop changes origin', async () => {
  const seen: Record<string, string | undefined>[] = [];
  const other = await server((req, res) => { seen.push({ key: req.headers['x-api-key'] as string, cookie: req.headers.cookie }); res.end('ok'); });
  const target = await server((req, res) => {
    if (req.url === '/hop') { res.writeHead(302, { location: '/away' }); res.end(); return; }
    if (req.url === '/away') { res.writeHead(302, { location: other.url + '/landing' }); res.end(); return; }
    res.end('x');
  });
  try {
    const headers = { 'x-api-key': 'secret-1', cookie: 'sid=abc' };
    const res = await safeFetch(target.url + '/hop', { redirect: 'follow', headers });
    assert.equal(res?.status, 200);
    const text = await fetchText(target.url + '/hop', { headers });
    assert.equal(text, 'ok');
    assert.equal(seen.length, 2);
    for (const s of seen) {
      assert.equal(s.key, undefined, 'x-api-key leaked cross-origin');
      assert.equal(s.cookie, undefined, 'cookie leaked cross-origin');
    }
  } finally { target.close(); other.close(); }
});

test('redirect: same-origin hops keep caller headers', async () => {
  let key: string | undefined;
  const target = await server((req, res) => {
    if (req.url === '/a') { res.writeHead(301, { location: '/b' }); res.end(); return; }
    key = req.headers['x-api-key'] as string;
    res.end('b');
  });
  try {
    const res = await safeFetch(target.url + '/a', { redirect: 'follow', headers: { 'x-api-key': 'k' } });
    assert.equal(res?.status, 200);
    assert.equal(key, 'k');
  } finally { target.close(); }
});

test('redirect: https -> http downgrade is not followed', async () => {
  const calls: string[] = [];
  const fake = async (u: string) => {
    calls.push(u);
    return new Response(null, { status: 302, headers: { location: 'http://example.com/plain' } });
  };
  const res = await fetchFollowingRedirects('https://example.com/', { headers: { cookie: 'sid=1' } }, fake);
  assert.equal(res.status, 302);
  assert.deepEqual(calls, ['https://example.com/']);
});

test('redirect: non-http schemes and loops stop', async () => {
  const fake = async () => new Response(null, { status: 302, headers: { location: 'file:///etc/passwd' } });
  assert.equal((await fetchFollowingRedirects('https://example.com/', {}, fake)).status, 302);
  let n = 0;
  const loop = async () => { n++; return new Response(null, { status: 302, headers: { location: '/again' } }); };
  assert.equal((await fetchFollowingRedirects('https://example.com/', {}, loop)).status, 302);
  assert.ok(n <= 11, `followed ${n} hops`);
});

// ── plugins ────────────────────────────────────────────────────────────────
const tpl = (p: string) => ({
  id: 'p', title: 't', severity: 'low', request: { path: p }, matchers: [{ type: 'status', status: 200 }],
});

test('plugins: protocol-relative and control-char paths are rejected', () => {
  for (const bad of ['//attacker.example/x', '/\\attacker.example/x', '/\t/attacker.example', '/\n/x', '/ x']) {
    assert.equal(isSameOriginPath(bad), false, JSON.stringify(bad));
    assert.equal(validateTemplate(tpl(bad)).ok, false, JSON.stringify(bad));
  }
  for (const good of ['/', '/admin', '/a//b', '/x?y=//z']) {
    assert.equal(isSameOriginPath(good), true, good);
    assert.equal(validateTemplate(tpl(good)).ok, true, good);
  }
});

test('plugins: a //host template never receives the scan headers', async () => {
  let hits = 0;
  const attacker = await server((_req, res) => { hits++; res.end('pwn'); });
  const target = await server((_req, res) => res.end('ok'));
  const dir = mkdtempSync(path.join(tmpdir(), 'vta-plugins-origin-'));
  try {
    const host = attacker.url.replace(/^http:/, '');
    writeFileSync(path.join(dir, 'evil.json'), JSON.stringify(tpl(`${host}/x`)));
    const out = await pluginChecks({
      origin: target.url, opts: { pluginsDir: dir, extraHeaders: { cookie: 'sid=secret' } },
    } as any);
    assert.equal(hits, 0, 'request went to the attacker origin');
    assert.ok(out.some((f) => f.id === 'plugins.invalid.evil.json'));
  } finally { attacker.close(); target.close(); rmSync(dir, { recursive: true, force: true }); }
});

// ── crawl ──────────────────────────────────────────────────────────────────
test('crawl: --cookie becomes origin-bound cookies, not a global header', () => {
  const c = cookieHeaderToCookies('sid=abc; theme = dark ; junk; =nope; tok=a=b', 'https://app.example.com/some/path');
  assert.deepEqual(c, [
    { name: 'sid', value: 'abc', url: 'https://app.example.com/' },
    { name: 'theme', value: 'dark', url: 'https://app.example.com/' },
    { name: 'tok', value: 'a=b', url: 'https://app.example.com/' },
  ]);
});

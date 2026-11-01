// tests/probe.test.ts — self-tests via node:test against tiny local servers.
// Imports the BUILT artifact (dist) so we test exactly what ships; `npm test` builds first.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { probe, summarize, normalizeUrl, discoverPages } from '../dist/probe.js';
import { loadConfig } from '../dist/config.js';
import { writeFileSync, rmSync } from 'node:fs';
import { scanSecrets, html as H } from '../dist/core.js';
import { checkSecurityHeaders, checkCookieFlags, idorProbe, setTenantParam, classifyTenantAccess, rbacProbe, dataIsolationProbe, massAssignmentProbe, findSensitiveFields } from '../dist/testkit.js';
import { failsAtLevel } from '../dist/audit.js';
import { lintCsp } from '../dist/checks.js';
import { toSarif } from '../dist/sarif.js';
import { buildBaseline, applyBaseline } from '../dist/baseline.js';
import { evaluateDnsHygiene, apexOf } from '../dist/dns.js';
import { evaluateAgentReadiness, visibleText, aiCrawlersBlocked } from '../dist/agent.js';
import { detectStacks } from '../dist/detect.js';
import { gradeTlsProtocol, gradeTlsCipher } from '../dist/core.js';
import { identifyEdge } from '../dist/host.js';
import { scanPort, parsePorts, identifyBanner } from '../dist/active.js';
import { parseNvd } from '../dist/cve.js';
import { refsFor, asvsCoverage, securityGrade, tlsGrade, cwesHit, apiTop10Hit } from '../dist/compliance.js';
import { renderReport } from '../dist/report.js';
import { renderHealthFindings } from '../dist/render-health.js';
import { detectComponents, matchVulnerabilities, versionLt, componentChecks } from '../dist/components.js';
import { analyzeJwt, jwtFindings } from '../dist/jwt.js';
import { hostHeaderChecks } from '../dist/hostheader.js';
import { csrfFindings } from '../dist/csrf.js';
import { domXssFindings, scanDomXssSinks } from '../dist/domxss.js';
import net from 'node:net';

// Build a JWT (header.payload.sig) from objects — base64url, no real signature (black-box test).
function makeJwt(header: object, payload: object, sig = 'sig'): string {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b64(header)}.${b64(payload)}.${sig}`;
}

function server(handler: http.RequestListener): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const s = http.createServer(handler);
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address() as any;
      resolve({ url: `http://127.0.0.1:${addr.port}`, close: () => s.close() });
    });
  });
}

// ── security (back-compat) ─────────────────────────────────────────────────
test('probe flags a wide-open server (missing headers, no security.txt)', async () => {
  const srv = await server((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><body>hi</body></html>'); });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(summarize(findings).failed > 0, 'should have failures');
  assert.ok(findings.find((f) => f.id === 'header.x-content-type-options' && !f.pass), 'flags missing nosniff');
  assert.ok(findings.find((f) => f.id === 'securitytxt' && !f.pass), 'flags missing security.txt');
  assert.ok(findings.find((f) => f.id === 'tls.scheme' && !f.pass), 'flags non-https');
});

test('probe passes a hardened server', async () => {
  const srv = await server((req, res) => {
    if (req.url?.startsWith('/.well-known/security.txt')) {
      res.writeHead(200); res.end('Contact: mailto:s@x.com\nExpires: 2027-01-01T00:00:00Z\n'); return;
    }
    res.writeHead(200, {
      'content-type': 'text/html',
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'x-frame-options': 'SAMEORIGIN',
      'content-security-policy': "default-src 'self'",
    });
    res.end('<html><body>hi</body></html>');
  });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'header.content-security-policy' && f.pass), 'CSP passes');
  assert.ok(findings.find((f) => f.id === 'securitytxt' && f.pass), 'security.txt passes');
});

// ── ported security checks (open-redirect / sri / cookie-prefix / rate-limit) ─
test('open-redirect: flags a server that 3xx-es a redirect param off-domain', async () => {
  const srv = await server((req, res) => {
    const u = new URL(req.url || '/', 'http://x');
    const next = u.searchParams.get('next');
    if (next) { res.writeHead(302, { location: next }); res.end(); return; }
    res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html>ok</html>');
  });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'open-redirect' && !f.pass), 'flags the open redirect');
});

test('sri: flags a cross-origin script with no integrity, passes when pinned', async () => {
  const unpinned = await server((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><script src="https://cdn.example.com/x.js"></script></html>'); });
  const a = await probe(unpinned.url, { only: ['security'] }); unpinned.close();
  assert.ok(a.find((f) => f.id === 'sri' && !f.pass), 'flags un-pinned cross-origin script');

  const pinned = await server((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><script src="https://cdn.example.com/x.js" integrity="sha384-abc" crossorigin></script></html>'); });
  const b = await probe(pinned.url, { only: ['security'] }); pinned.close();
  assert.ok(b.find((f) => f.id === 'sri' && f.pass), 'passes when integrity is present');
});

test('cookie-prefix: info-fails on an un-prefixed cookie', async () => {
  const srv = await server((_req, res) => { res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': 'sid=abc; Secure; HttpOnly; SameSite=Lax' }); res.end('<html>ok</html>'); });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'cookie.sid' && f.pass), 'cookie flags pass');
  assert.ok(findings.find((f) => f.id === 'cookie-prefix.sid' && !f.pass), 'recommends a __Host-/__Secure- prefix');
});

test('rate-limit (opt-in): passes when the path throttles with 429', async () => {
  let n = 0;
  const srv = await server((_req, res) => { n++; if (n > 5) { res.writeHead(429); res.end('slow down'); return; } res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html>ok</html>'); });
  const findings = await probe(srv.url, { only: ['security'], rateLimitPath: '/' });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'rate-limit' && f.pass), 'detects throttling');
});

// ── dependency audit (pure severity gating) ──────────────────────────────────
test('audit failsAtLevel gates at/above the threshold', () => {
  assert.equal(failsAtLevel({ counts: { high: 1 }, total: 1 }, 'high'), true, 'high vuln fails at high');
  assert.equal(failsAtLevel({ counts: { low: 2 }, total: 2 }, 'high'), false, 'low vuln does not fail at high');
  assert.equal(failsAtLevel({ counts: { low: 2 }, total: 2 }, 'low'), true, 'low vuln fails at low');
  assert.equal(failsAtLevel({ counts: {}, total: 0 }, 'high'), false, 'clean audit passes');
});

// ── CSP linter (#4) ──────────────────────────────────────────────────────────
test('lintCsp flags unsafe-inline / unsafe-eval / wildcard, passes a strong policy', () => {
  const weak = lintCsp("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *");
  const ids = weak.map((i) => i.id);
  assert.ok(ids.includes('csp.unsafe-inline'), 'flags unsafe-inline');
  assert.ok(ids.includes('csp.unsafe-eval'), 'flags unsafe-eval');
  assert.ok(ids.includes('csp.wildcard-script'), 'flags wildcard script source');

  const strong = lintCsp("default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; base-uri 'self'");
  assert.deepEqual(strong, [], 'a strong policy has no issues');
});

test('lintCsp: script-src falls back to default-src', () => {
  const issues = lintCsp("default-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'");
  assert.ok(issues.some((i) => i.id === 'csp.unsafe-inline'), 'inherits weakness from default-src');
});

test('probe emits csp.* findings when a weak CSP is served', async () => {
  const srv = await server((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', 'content-security-policy': "script-src 'self' 'unsafe-inline'" });
    res.end('<html>ok</html>');
  });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'csp.unsafe-inline' && !f.pass), 'surfaces the CSP weakness');
});

// ── SARIF output (#2) ────────────────────────────────────────────────────────
test('toSarif produces valid 2.1.0 with rules + results for failing findings only', () => {
  const findings = [
    { id: 'header.hsts', category: 'security', title: 'Missing HSTS', severity: 'high', pass: false, detail: 'no HSTS', fix: 'Send HSTS' },
    { id: 'seo.title', category: 'seo', title: 'Has title', severity: 'info', pass: true, detail: 'ok' },
  ] as any;
  const sarif = toSarif(findings, { url: 'https://x.example', version: '1.2.3' }) as any;
  assert.equal(sarif.version, '2.1.0');
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, 'vibetesting-agent');
  assert.equal(run.tool.driver.version, '1.2.3');
  assert.equal(run.results.length, 1, 'only the failing finding becomes a result');
  assert.equal(run.results[0].ruleId, 'header.hsts');
  assert.equal(run.results[0].level, 'error', 'high maps to error');
  assert.ok(run.tool.driver.rules.some((r: any) => r.id === 'header.hsts'), 'registers the rule');
});

// ── baseline / diff mode (#3) ────────────────────────────────────────────────
test('baseline: buildBaseline records failing keys; applyBaseline splits new vs accepted', () => {
  const findings = [
    { id: 'header.hsts', category: 'security', title: 't', severity: 'high', pass: false, detail: 'd' },
    { id: 'open-redirect', category: 'security', title: 't', severity: 'high', pass: false, detail: 'd' },
    { id: 'seo.title', category: 'seo', title: 't', severity: 'info', pass: true, detail: 'd' },
  ] as any;
  const baseline = buildBaseline(findings, 'https://x');
  assert.deepEqual(baseline.keys, ['header.hsts', 'open-redirect'], 'only failing keys, sorted');

  // A later scan where hsts is still failing (accepted) but a NEW failure appears.
  const later = [
    { id: 'header.hsts', category: 'security', title: 't', severity: 'high', pass: false, detail: 'd' },
    { id: 'sri', category: 'security', title: 't', severity: 'low', pass: false, detail: 'd' },
  ] as any;
  const diff = applyBaseline(later, baseline);
  assert.deepEqual(diff.newFailures.map((f: any) => f.id), ['sri'], 'sri is new');
  assert.deepEqual(diff.baselined.map((f: any) => f.id), ['header.hsts'], 'hsts is accepted');
});

// ── DNS / email hygiene (#6) ─────────────────────────────────────────────────
test('apexOf reduces subdomains to the registrable apex', () => {
  assert.equal(apexOf('beta.example.com'), 'example.com');
  assert.equal(apexOf('example.com'), 'example.com');
  assert.equal(apexOf('a.b.c.example.com'), 'example.com');
});

test('evaluateDnsHygiene: flags a bare domain, passes a hardened one', () => {
  const bare = evaluateDnsHygiene({ hostname: 'x.com', apex: 'x.com', apexTxt: [], dmarcTxt: [], hasCaa: false, danglingCnameTarget: null });
  const byId = (id: string) => bare.find((f: any) => f.id === id);
  assert.ok(byId('dns.spf') && !byId('dns.spf').pass, 'no SPF fails');
  assert.ok(byId('dns.dmarc') && !byId('dns.dmarc').pass, 'no DMARC fails');
  assert.ok(byId('dns.caa') && !byId('dns.caa').pass, 'no CAA fails');

  const hard = evaluateDnsHygiene({
    hostname: 'x.com', apex: 'x.com',
    apexTxt: ['v=spf1 include:_spf.google.com -all'],
    dmarcTxt: ['v=DMARC1; p=reject; rua=mailto:a@x.com'],
    hasCaa: true, danglingCnameTarget: null,
  });
  assert.ok(hard.every((f: any) => f.pass), 'a fully hardened domain has no failures');
});

test('evaluateDnsHygiene: p=none is a weak (failing) DMARC; dangling CNAME is high', () => {
  const weakDmarc = evaluateDnsHygiene({ hostname: 'x.com', apex: 'x.com', apexTxt: ['v=spf1 -all'], dmarcTxt: ['v=DMARC1; p=none'], hasCaa: true, danglingCnameTarget: null });
  const d = weakDmarc.find((f: any) => f.id === 'dns.dmarc');
  assert.ok(d && !d.pass && d.severity === 'low', 'p=none is a low-severity fail');

  const dangling = evaluateDnsHygiene({ hostname: 'gone.x.com', apex: 'x.com', apexTxt: ['v=spf1 -all'], dmarcTxt: ['v=DMARC1; p=reject'], hasCaa: true, danglingCnameTarget: 'old-app.herokudns.com' });
  const c = dangling.find((f: any) => f.id === 'dns.dangling-cname');
  assert.ok(c && !c.pass && c.severity === 'high', 'dangling CNAME is a high-severity takeover risk');
});

// ── secrets ────────────────────────────────────────────────────────────────
test('scanSecrets catches real keys, ignores publishable/anon, redacts', () => {
  const hits = scanSecrets(`
    const stripe = "sk_live_51HxYzAbCdEfGhIjKlMnOpQrStUvWx";
    const aws = "AKIAIOSFODNN7EXAMPLE";
    const pk = "-----BEGIN RSA PRIVATE KEY-----";
    const publishable = "pk_live_thisIsPublishableAndFine";
  `);
  assert.ok(hits.some((h) => h.ruleId === 'stripe.sk_live'), 'catches sk_live');
  assert.ok(hits.some((h) => h.ruleId === 'aws.akid'), 'catches AWS key');
  assert.ok(hits.some((h) => h.ruleId === 'privatekey'), 'catches private key block');
  assert.ok(!hits.some((h) => h.sample.includes('pk_live')), 'ignores publishable pk_live');
  assert.ok(hits.every((h) => !h.sample.includes('UvWx') || h.sample.includes('…')), 'redacts the secret body');
  assert.equal(scanSecrets('const x = 1; fetch("/api");').length, 0, 'clean code => no hits');
});

test('Supabase service_role JWT fires only on role=service_role', () => {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head = 'eyJhbGciOiJIUzI1NiJ9';
  const svc = `${head}.${b64({ role: 'service_role' })}.sigaaaaaaaaaa`;
  const anon = `${head}.${b64({ role: 'anon' })}.sigaaaaaaaaaa`;
  assert.ok(scanSecrets(svc).some((h) => h.ruleId === 'supabase.service_role'), 'flags service_role');
  assert.ok(!scanSecrets(anon).some((h) => h.ruleId === 'supabase.service_role'), 'ignores anon');
});

test('probe surfaces a secret leaked in a same-origin script bundle', async () => {
  const srv = await server((req, res) => {
    if (req.url === '/app.js') { res.writeHead(200, { 'content-type': 'application/javascript' }); res.end('var k="sk_live_AbCdEfGhIjKlMnOpQrStUvWx";'); return; }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html><body><script src="/app.js"></script></body></html>');
  });
  const findings = await probe(srv.url, { only: ['secrets'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'secret.stripe.sk_live' && !f.pass), 'flags the leaked key from the bundle');
});

// ── exposure (SPA false-positive guard) ──────────────────────────────────────
test('exposure does NOT false-positive when a SPA returns index.html for /.env', async () => {
  const srv = await server((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<!DOCTYPE html><html><body>app</body></html>'); });
  const findings = await probe(srv.url, { only: ['exposure'] });
  srv.close();
  assert.ok(!findings.some((f) => f.id.startsWith('exposed/') && !f.pass), 'no exposed-file findings for an SPA catch-all');
});

test('exposure flags a genuinely served .env', async () => {
  const srv = await server((req, res) => {
    if (req.url === '/.env') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('DATABASE_URL=postgres://u:p@h/db\nSTRIPE_KEY=sk_test_x\n'); return; }
    res.writeHead(404); res.end('nope');
  });
  const findings = await probe(srv.url, { only: ['exposure'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'exposed/.env' && !f.pass), 'flags a real .env');
});

// ── seo + a11y (HTML parsing) ────────────────────────────────────────────────
test('seo + a11y findings reflect the served HTML', async () => {
  const srv = await server((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<!DOCTYPE html><html lang="en"><head><title>My App</title><meta name="viewport" content="width=device-width"></head><body><h1>Hi</h1><img src="/a.png"></body></html>');
  });
  const findings = await probe(srv.url, { only: ['seo', 'a11y'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'seo.title' && f.pass), 'detects title');
  assert.ok(findings.find((f) => f.id === 'seo.description' && !f.pass), 'flags missing description');
  assert.ok(findings.find((f) => f.id === 'a11y.lang' && f.pass), 'detects lang');
  assert.ok(findings.find((f) => f.id === 'a11y.alt' && !f.pass), 'flags img missing alt');
});

test('html helpers parse tags correctly', () => {
  const doc = '<html lang="en"><title>T</title><img src="/x.png" alt="x"><img src="/y.png"><a href="/p">p</a><script src="/b.js"></script>';
  assert.equal(H.title(doc), 'T');
  assert.equal(H.hasLang(doc), true);
  assert.equal(H.images(doc).filter((i) => !i.hasAlt).length, 1);
  assert.deepEqual(H.scripts(doc), ['/b.js']);
  assert.deepEqual(H.links(doc), ['/p']);
});

// ── white-box helpers (unchanged) ────────────────────────────────────────────
test('checkSecurityHeaders + checkCookieFlags', () => {
  assert.deepEqual(checkSecurityHeaders({ 'strict-transport-security': 'max-age=99999', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'content-security-policy': "default-src 'self'" }), []);
  assert.ok(checkSecurityHeaders({}).length >= 3);
  assert.deepEqual(checkCookieFlags('s=1; Secure; HttpOnly; SameSite=Lax'), []);
  assert.ok(checkCookieFlags('s=1').length === 3);
});

test('idorProbe reports a cross-tenant leak', async () => {
  const leaky = await server((_req, res) => { res.writeHead(200); res.end('secret'); });
  const res = await idorProbe(
    { label: 'attacker', headers: {} },
    [{ name: 'GET /orgA/secret', request: () => ({ url: leaky.url + '/orgA/secret' }) }],
  );
  leaky.close();
  assert.equal(res[0].ok, false, 'a 200 to the attacker is a leak');
});

// ═══════════════════════ audit fixes (2026-07-02) ═══════════════════════════

// [DNS apex] multi-label public suffixes — a .com.au multi-label public-suffix case.
test('apexOf handles multi-label public suffixes (.com.au / .co.uk / .co.nz)', () => {
  assert.equal(apexOf('example.com.au'), 'example.com.au', 'AU domain apex is the registrable name, not com.au');
  assert.equal(apexOf('www.example.com.au'), 'example.com.au');
  assert.equal(apexOf('shop.example.co.uk'), 'example.co.uk');
  assert.equal(apexOf('foo.bar.example.co.nz'), 'example.co.nz');
  assert.equal(apexOf('plain.example.com'), 'example.com', 'ordinary TLDs still use last two labels');
});

// [correctness #1] open redirect via an UPPERCASE protocol-relative location.
test('open-redirect: catches a protocol-relative redirect regardless of case', async () => {
  const srv = await server((req, res) => {
    const u = new URL(req.url || '/', 'http://x');
    const p = u.searchParams.get('next');
    if (p) { res.writeHead(302, { location: '//EVIL.EXAMPLE/' }); res.end(); return; }
    res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html>ok</html>');
  });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'open-redirect' && !f.pass), 'flags //EVIL.EXAMPLE despite uppercase');
});

// [correctness #2] .env with lowercase variable names (Flask/Django style).
test('exposure flags a .env that uses lowercase variable names', async () => {
  const srv = await server((req, res) => {
    if (req.url === '/.env') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('debug_mode=true\ndatabase_url=postgres://u:p@h/db\n'); return; }
    res.writeHead(404); res.end('nope');
  });
  const findings = await probe(srv.url, { only: ['exposure'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'exposed/.env' && !f.pass), 'lowercase-keyed .env is still detected');
});

// [correctness #15] object-src falls back to default-src 'none'.
test('lintCsp: object-src inherits default-src \'none\' (no false object-src warning)', () => {
  const issues = lintCsp("default-src 'none'; script-src 'self' 'nonce-x'; base-uri 'self'");
  assert.ok(!issues.some((i) => i.id === 'csp.object-src'), "default-src 'none' covers object-src");
  const missing = lintCsp("default-src 'self'; script-src 'self' 'nonce-x'; base-uri 'self'");
  assert.ok(missing.some((i) => i.id === 'csp.object-src'), "default-src 'self' does NOT cover object-src");
});

// [coverage #16/#20/#22] modern hardening headers.
test('security: flags missing Permissions-Policy, COOP, and non-preloadable HSTS', async () => {
  const srv = await server((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', 'strict-transport-security': 'max-age=600' });
    res.end('<html>ok</html>');
  });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'header.permissions-policy' && !f.pass), 'flags missing Permissions-Policy');
  assert.ok(findings.find((f) => f.id === 'header.cross-origin-opener-policy' && !f.pass), 'flags missing COOP');
  assert.ok(findings.find((f) => f.id === 'tls.hsts-preload' && !f.pass), 'short HSTS is not preload-eligible');
});

test('security: flags TRACE (XST) via OPTIONS and missing CORP', async () => {
  const srv = await server((req, res) => {
    if (req.method === 'OPTIONS') { res.writeHead(204, { allow: 'GET, POST, OPTIONS, TRACE' }); res.end(); return; }
    res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html>ok</html>');
  });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'http.methods' && !f.pass && /TRACE/.test(f.title)), 'flags TRACE/TRACK (XST)');
  assert.ok(findings.find((f) => f.id === 'header.cross-origin-resource-policy' && !f.pass), 'flags missing CORP');
});

test('security: HSTS preload-eligible header passes', async () => {
  const srv = await server((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', 'strict-transport-security': 'max-age=31536000; includeSubDomains; preload' });
    res.end('<html>ok</html>');
  });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'tls.hsts-preload' && f.pass), 'full HSTS is preload-eligible');
});

// [coverage #3] framework debug/admin endpoint exposure.
test('exposure flags a Spring Boot actuator health endpoint', async () => {
  const srv = await server((req, res) => {
    if (req.url === '/actuator/health') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"status":"UP","components":{"db":{"status":"UP"}}}'); return; }
    res.writeHead(404); res.end('nope');
  });
  const findings = await probe(srv.url, { only: ['exposure'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'exposed/actuator/health' && !f.pass), 'detects exposed actuator');
});

// [coverage #4] directory listing detection + SPA guard.
test('exposure flags a real directory listing but not an SPA catch-all', async () => {
  const listing = await server((req, res) => {
    if (req.url?.startsWith('/uploads/')) { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><head><title>Index of /uploads</title></head><body><pre><a href="../">Parent Directory</a>\n<a href="a.jpg">a.jpg</a></pre></body></html>'); return; }
    res.writeHead(404); res.end('nope');
  });
  const a = await probe(listing.url, { only: ['exposure'] }); listing.close();
  assert.ok(a.find((f) => f.id === 'dir-listing/uploads/' && !f.pass), 'flags an autoindex page');

  const spa = await server((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<!DOCTYPE html><html><body><div id="root"></div><script src="/app.js"></script></body></html>'); });
  const b = await probe(spa.url, { only: ['exposure'] }); spa.close();
  assert.ok(!b.some((f) => f.id.startsWith('dir-listing') && !f.pass), 'SPA index is not a directory listing');
});

// [coverage #11/#21] robots.txt disclosing sensitive paths.
test('exposure flags robots.txt that Disallows sensitive paths', async () => {
  const srv = await server((req, res) => {
    if (req.url === '/robots.txt') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('User-agent: *\nDisallow: /admin/\nDisallow: /internal-backup/\nDisallow: /public/\n'); return; }
    res.writeHead(404); res.end('nope');
  });
  const findings = await probe(srv.url, { only: ['exposure'] });
  srv.close();
  const finding = findings.find((f) => f.id === 'robots.sensitive');
  assert.ok(finding && !finding.pass, 'flags admin/backup Disallow entries');
});

// [robustness #7/#14] bare-domain normalization.
test('normalizeUrl adds https:// to a bare domain and leaves full URLs alone', () => {
  assert.equal(normalizeUrl('example.com'), 'https://example.com');
  assert.equal(normalizeUrl('example.com/path'), 'https://example.com/path');
  assert.equal(normalizeUrl('http://example.com'), 'http://example.com');
  assert.equal(normalizeUrl('https://example.com'), 'https://example.com');
});

// [robustness #5/#6] a site that accepts the connection but never responds must not hang the scan.
test('probe returns (does not hang) against a non-responsive server within the timeout', async () => {
  const hanging = await server(() => { /* never write a response */ });
  const start = Date.now();
  const findings = await probe(hanging.url, { only: ['security'], timeoutMs: 400, retries: 0 });
  const elapsed = Date.now() - start;
  hanging.close();
  assert.ok(elapsed < 8000, `scan should abort quickly, took ${elapsed}ms`);
  const reach = findings.find((f) => f.id === 'reachability');
  assert.ok(reach, 'reports reachability');
  assert.equal(reach?.inconclusive, true, 'unreachable after retries is error/inconclusive, not a finding');
  assert.equal(reach?.pass, true);
});

// ═══════════════════════ agent-readiness category (#11) ═════════════════════

test('visibleText strips scripts/styles/tags and leaves readable content', () => {
  const html = '<html><head><style>.x{color:red}</style><script>var a=1</script></head><body><h1>Hello</h1><p>Real content here.</p></body></html>';
  const t = visibleText(html);
  assert.ok(t.includes('Hello') && t.includes('Real content here.'), 'keeps body text');
  assert.ok(!t.includes('var a') && !t.includes('color:red'), 'drops script/style bodies');
});

test('aiCrawlersBlocked parses robots.txt groups correctly', () => {
  const robots = [
    'User-agent: GPTBot', 'Disallow: /',
    '', 'User-agent: *', 'Disallow: /admin/',
    '', 'User-agent: CCBot', 'Allow: /',
  ].join('\n');
  const blocked = aiCrawlersBlocked(robots);
  assert.ok(blocked.includes('gptbot'), 'GPTBot Disallow: / is blocked');
  assert.ok(!blocked.includes('ccbot'), 'CCBot is not blocked');
  assert.ok(!blocked.includes('claudebot'), 'ClaudeBot falls back to * (which only blocks /admin), not blocked at root');

  const blockAll = aiCrawlersBlocked('User-agent: *\nDisallow: /');
  assert.ok(blockAll.includes('gptbot') && blockAll.includes('claudebot'), 'a wildcard Disallow: / blocks every AI crawler');
});

test('evaluateAgentReadiness: flags a JS-only shell, missing llms.txt, blocked crawlers', () => {
  const out = evaluateAgentReadiness({
    html: '<html><body><div id="root"></div><script src="/app.js"></script></body></html>',
    hasLlmsTxt: false,
    robotsTxt: 'User-agent: GPTBot\nDisallow: /',
    robotsPresent: true,
    hasAgentManifest: false,
  });
  const byId = (id: string) => out.find((f: any) => f.id === id);
  assert.ok(byId('agent.ssr-content') && !byId('agent.ssr-content').pass, 'JS-only shell fails SSR check');
  assert.ok(byId('agent.llms-txt') && !byId('agent.llms-txt').pass, 'no llms.txt fails');
  assert.ok(byId('agent.ai-crawlers') && !byId('agent.ai-crawlers').pass, 'blocked GPTBot fails');
  assert.ok(byId('agent.structured-data') && !byId('agent.structured-data').pass, 'no JSON-LD fails');
});

test('evaluateAgentReadiness: an agent-ready page passes', () => {
  const out = evaluateAgentReadiness({
    html: '<html><body><h1>My Product</h1><p>' + 'Lots of real server-rendered content. '.repeat(20) + '</p><script type="application/ld+json">{"@type":"Product"}</script></body></html>',
    hasLlmsTxt: true,
    robotsTxt: 'User-agent: *\nAllow: /',
    robotsPresent: true,
    hasAgentManifest: true,
  });
  assert.ok(out.every((f: any) => f.pass), 'a fully agent-ready page has no failures');
});

test('probe runs the agent category end-to-end', async () => {
  const srv = await server((req, res) => {
    if (req.url === '/llms.txt') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('# My Site\n\n> A helpful site.\n'); return; }
    if (req.url === '/robots.txt') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('User-agent: *\nAllow: /\n'); return; }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html><body><h1>Welcome</h1><p>' + 'Server-rendered words. '.repeat(20) + '</p></body></html>');
  });
  const findings = await probe(srv.url, { only: ['agent'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'agent.llms-txt' && f.pass), 'detects llms.txt');
  assert.ok(findings.find((f) => f.id === 'agent.ssr-content' && f.pass), 'detects server-rendered content');
  assert.ok(findings.find((f) => f.id === 'agent.ai-crawlers' && f.pass), 'detects open crawler policy');
});

// ═══════════════════════ authenticated scan (#7) ════════════════════════════

test('extraHeaders are sent on same-origin requests (scan behind login)', async () => {
  let sawAuthOnHome = false;
  let sawAuthOnEnv = false;
  const srv = await server((req, res) => {
    const authed = req.headers['cookie'] === 'session=secret';
    if (req.url === '/') { sawAuthOnHome ||= authed; res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><body>home</body></html>'); return; }
    if (req.url === '/.env') {
      sawAuthOnEnv ||= authed;
      // Only serve the secret file to an authenticated request (simulating a page behind login).
      if (authed) { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('SECRET_KEY=abc123\n'); return; }
      res.writeHead(401); res.end('unauthorized'); return;
    }
    res.writeHead(404); res.end('nope');
  });
  const findings = await probe(srv.url, { only: ['exposure'], extraHeaders: { cookie: 'session=secret' } });
  srv.close();
  assert.ok(sawAuthOnEnv, 'auth cookie reached the same-origin /.env probe');
  assert.ok(findings.find((f) => f.id === 'exposed/.env' && !f.pass), 'finds the .env only reachable while authenticated');
});

test('auth-debug leak: fires on a real secret value, NOT on a field-name mention', async () => {
  const leaky = await server((req, res) => {
    if (req.url === '/api/auth/debug') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"user":"x","password_hash":"$2b$10$abcdefghijklmnopqrstuv"}'); return; }
    res.writeHead(404); res.end('no');
  });
  const a = await probe(leaky.url, { only: ['exposure'] }); leaky.close();
  assert.ok(a.find((f) => f.id === 'debug-leak/api/auth/debug' && !f.pass), 'flags an actual leaked hash value');

  const docs = await server((req, res) => {
    if (req.url === '/api/auth/debug') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"schema":["password_hash","access_token"],"note":"fields we never return"}'); return; }
    res.writeHead(404); res.end('no');
  });
  const b = await probe(docs.url, { only: ['exposure'] }); docs.close();
  assert.ok(!b.some((f) => f.id.startsWith('debug-leak') && !f.pass), 'does NOT false-positive on field-name mentions');
});

// ═══════════════════════ multi-tenant / separation-of-accounts ══════════════

test('setTenantParam replaces or adds the tenant id, keeping relative URLs relative', () => {
  assert.equal(setTenantParam('/api/x?tenant_uuid=AAA&page=1', 'BBB'), '/api/x?tenant_uuid=BBB&page=1');
  assert.equal(setTenantParam('/api/x?page=1', 'BBB'), '/api/x?page=1&tenant_uuid=BBB');
  assert.equal(setTenantParam('https://h.example/api/x', 'BBB'), 'https://h.example/api/x?tenant_uuid=BBB');
  assert.equal(setTenantParam('/api/x?org=AAA', 'BBB', 'org'), '/api/x?org=BBB');
});

test('classifyTenantAccess: leak vs isolated vs inconclusive', () => {
  const ownerData = { status: 200, body: '{"records":[{"id":1,"secret":"A-private"}]}' };
  const attackerOwn = { status: 200, body: '{"records":[]}' };

  // Attacker got the owner's exact data -> LEAK.
  assert.equal(classifyTenantAccess({ baseline: ownerData, attack: ownerData, control: attackerOwn }).verdict, 'leak');

  // Attacker denied outright -> isolated.
  assert.equal(classifyTenantAccess({ baseline: ownerData, attack: { status: 403, body: 'no' }, control: attackerOwn }).verdict, 'isolated');

  // Attacker got 200 but empty / their own scope -> isolated (no owner data disclosed).
  assert.equal(classifyTenantAccess({ baseline: ownerData, attack: { status: 200, body: '{"data":null}' }, control: attackerOwn }).verdict, 'isolated');
  assert.equal(classifyTenantAccess({ baseline: ownerData, attack: attackerOwn, control: attackerOwn }).verdict, 'isolated');

  // Baseline itself failed (stale token) -> inconclusive, NOT a pass.
  assert.equal(classifyTenantAccess({ baseline: { status: 401, body: 'x' }, attack: { status: 401, body: 'x' } }).verdict, 'inconclusive');

  // 200 with foreign-but-non-owner data -> needs a human.
  assert.equal(classifyTenantAccess({ baseline: ownerData, attack: { status: 200, body: '{"records":[{"id":99}]}' }, control: attackerOwn }).verdict, 'inspect');
});

// ═══════════════════ RBAC / access-control testkit (generalized from db-nextjs-fresh) ═══════════

test('rbacProbe: passes a properly-gated endpoint, flags an open one', async () => {
  // Stub: admin token -> 200, any other token -> 403, no token -> 401.
  const gated = async (_url, init) => {
    const role = new Headers(init?.headers).get('x-role');
    return new Response('ok', { status: role === 'admin' ? 200 : role ? 403 : 401 });
  };
  const actors = [
    { label: 'anonymous', expect: 'deny' },
    { label: 'plain user', headers: { 'x-role': 'user' }, expect: 'deny' },
    { label: 'admin', headers: { 'x-role': 'admin' }, expect: 'allow' },
  ];
  const good = await rbacProbe(() => ({ url: 'https://x/api/admin/users' }), actors, gated);
  assert.ok(good.every((r) => r.ok), 'a correctly-gated endpoint passes every actor');

  const wideOpen = async () => new Response('ok', { status: 200 });
  const bad = await rbacProbe(() => ({ url: 'https://x/api/admin/users' }), actors, wideOpen);
  assert.ok(bad.find((r) => r.actor === 'anonymous' && !r.ok), 'flags anon NOT being denied on an open endpoint');
  assert.ok(bad.find((r) => r.actor === 'plain user' && !r.ok), 'flags a plain user reaching an admin endpoint');
});

test('dataIsolationProbe: disjoint id sets pass, shared ids fail', async () => {
  const idsByUser = { A: '{"items":[{"id":"a1"},{"id":"a2"}]}', B: '{"items":[{"id":"b1"}]}' };
  const scoped = async (_url, init) => new Response(idsByUser[new Headers(init?.headers).get('x-user')], { status: 200 });
  const extract = (body) => [...body.matchAll(/"id":"([^"]+)"/g)].map((m) => m[1]);
  const ok = await dataIsolationProbe(() => ({ url: 'https://x/api/items' }), { label: 'A', headers: { 'x-user': 'A' } }, { label: 'B', headers: { 'x-user': 'B' } }, extract, scoped);
  assert.ok(ok.ok && ok.shared.length === 0, 'owner-scoped lists are disjoint');

  const global = async () => new Response('{"items":[{"id":"a1"},{"id":"b1"}]}', { status: 200 });
  const leak = await dataIsolationProbe(() => ({ url: 'https://x/api/items' }), { label: 'A', headers: {} }, { label: 'B', headers: {} }, extract, global);
  assert.ok(!leak.ok && leak.shared.length === 2, 'a global list (both users see all) is flagged');
});

test('massAssignmentProbe: flags a server that reflects a forged field', async () => {
  const echo = async (_url, init) => new Response(init?.body ?? '', { status: 200 });
  const bad = await massAssignmentProbe(() => ({ url: 'https://x/api/stories', init: { method: 'POST', body: '{"title":"t","author_id":"attacker-forged"}' } }), 'attacker-forged', echo);
  assert.ok(!bad.ok, 'server that echoes the forged author_id is flagged');

  const strips = async () => new Response('{"title":"t","author_id":"real-server-id"}', { status: 200 });
  const good = await massAssignmentProbe(() => ({ url: 'https://x/api/stories', init: { method: 'POST', body: '{"author_id":"attacker-forged"}' } }), 'attacker-forged', strips);
  assert.ok(good.ok, 'server that ignores the forged field passes');
});

test('findSensitiveFields spots secret keys in a response body', () => {
  assert.deepEqual(findSensitiveFields('{"user":"x","access_token":"ey..."}').sort(), ['access_token']);
  assert.ok(findSensitiveFields('{"password_hash":"$2b$10$...","role":"admin"}').includes('password_hash'));
  assert.deepEqual(findSensitiveFields('{"id":1,"name":"ok"}'), [], 'clean body has none');
});

// ═══════════════════════ multi-page crawl (#12) + config (#13) ══════════════

test('discoverPages returns capped same-origin pages, ignoring off-origin + fragments', async () => {
  const srv = await server((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html><body><a href="/a">a</a><a href="/b">b</a><a href="/c">c</a><a href="https://evil.example/x">ext</a><a href="/a#frag">dup</a></body></html>');
  });
  const pages = await discoverPages(srv.url, 2);
  srv.close();
  assert.equal(pages.length, 2, 'respects the cap');
  assert.ok(pages.every((p) => p.startsWith(srv.url)), 'same-origin only');
  assert.ok(!pages.some((p) => p.includes('evil.example')), 'excludes off-origin links');
});

test('loadConfig reads a file, tolerates a missing default', () => {
  const path = '/tmp/vibetesting-agent-test-config.json';
  writeFileSync(path, JSON.stringify({ failOn: 'medium', skip: ['a11y'], quiet: true }));
  const { config, error } = loadConfig(path);
  rmSync(path, { force: true });
  assert.equal(error, undefined);
  assert.equal(config.failOn, 'medium');
  assert.deepEqual(config.skip, ['a11y']);

  const missing = loadConfig('/tmp/vibetesting-agent-does-not-exist.json');
  assert.ok(missing.error, 'an explicit missing path is an error');
  assert.deepEqual(loadConfig(undefined).config, {}, 'a missing default file is fine (empty config)');
});

// ═══════════════════════ deeper TLS grading (#5) ════════════════════════════

test('gradeTlsProtocol flags deprecated protocols, passes modern ones', () => {
  assert.equal(gradeTlsProtocol('TLSv1').ok, false);
  assert.equal(gradeTlsProtocol('TLSv1').severity, 'high');
  assert.equal(gradeTlsProtocol('TLSv1.1').ok, false);
  assert.equal(gradeTlsProtocol('TLSv1.2').ok, true);
  assert.equal(gradeTlsProtocol('TLSv1.3').ok, true);
  assert.equal(gradeTlsProtocol(null).ok, true, 'undeterminable is not a failure');
});

test('gradeTlsCipher flags weak/legacy ciphers, passes AEAD', () => {
  assert.equal(gradeTlsCipher('ECDHE-RSA-RC4-SHA').ok, false);
  assert.equal(gradeTlsCipher('ECDHE-RSA-DES-CBC3-SHA').ok, false);
  assert.equal(gradeTlsCipher('TLS_AES_256_GCM_SHA384').ok, true);
  assert.equal(gradeTlsCipher('ECDHE-RSA-CHACHA20-POLY1305').ok, true);
});

// ═══════════════════════ OWASP / ASVS compliance mapping ═══════════════════

test('refsFor maps findings to standards by longest prefix', () => {
  assert.equal(refsFor('tls.protocol').asvs?.[0], 'V9.1.3');
  assert.equal(refsFor('header.content-security-policy').asvs?.[0], 'V14.4.3');
  assert.equal(refsFor('cookie-prefix.sid').asvs?.[0], 'V3.4.4', 'cookie-prefix beats cookie');
  assert.equal(refsFor('cookie.sid').owasp, 'A05');
  assert.equal(refsFor('exposed/backup.zip').asvs?.includes('V12.5.1'), true);
  assert.deepEqual(refsFor('totally.unknown.id'), {}, 'unknown id → no refs');
});

test('renderReport builds a self-contained HTML report with findings, fixes and grades', () => {
  const findings = [
    { id: 'header.content-security-policy', category: 'security', title: 'Missing content-security-policy', severity: 'high', pass: false, detail: 'expected a CSP', fix: 'Add a CSP header' },
    { id: 'tls.scheme', category: 'security', title: 'Served over HTTPS', severity: 'high', pass: true, detail: 'https://x' },
  ];
  const html = renderReport('https://acme.example', findings, { generatedAt: '2026-07-02 00:00 UTC' });
  assert.ok(html.startsWith('<!DOCTYPE html>'), 'is a full HTML doc');
  assert.ok(html.includes('https://acme.example'), 'includes the target');
  assert.ok(html.includes('Missing content-security-policy') && html.includes('Add a CSP header'), 'includes finding + fix');
  assert.ok(html.includes('CWE-693'), 'includes standards badge');
  assert.ok(/Security · \d+\/100/.test(html), 'includes the security grade');
  assert.ok(!html.includes('<script'), 'no scripts — safe to open/print');
});

test('refsFor carries CWE + API-Top-10 for relevant findings', () => {
  assert.deepEqual(refsFor('tls.scheme').cwe, ['CWE-319']);
  assert.equal(refsFor('idor.x').apiTop10, 'API1:2023', 'IDOR → BOLA');
  assert.equal(refsFor('rate-limit').apiTop10, 'API4:2023');
  assert.ok(refsFor('header.x-frame-options').cwe?.includes('CWE-1021'));
});

test('securityGrade + tlsGrade + cwesHit + apiTop10Hit', () => {
  const clean = [{ id: 'header.content-security-policy', category: 'security', title: 't', severity: 'high', pass: true, detail: '' }];
  assert.equal(securityGrade(clean).grade, 'A+', 'no failures → A+');

  const bad = [
    { id: 'header.content-security-policy', category: 'security', title: 't', severity: 'high', pass: false, detail: '' },
    { id: 'idor.orders', category: 'security', title: 't', severity: 'high', pass: false, detail: '' },
  ];
  assert.ok(securityGrade(bad).score < 70, 'two highs drop the grade');
  assert.ok(cwesHit(bad).includes('CWE-693'), 'collects CWE from failing findings');
  assert.equal(apiTop10Hit(bad)['API1:2023'], 1, 'IDOR failure → BOLA count');

  assert.equal(tlsGrade([{ id: 'tls.scheme', category: 'security', title: 't', severity: 'high', pass: false, detail: '' }]), 'F', 'no HTTPS → F');
  assert.equal(tlsGrade([
    { id: 'tls.scheme', category: 'security', title: 't', severity: 'high', pass: true, detail: '' },
    { id: 'tls.protocol', category: 'security', title: 't', severity: 'low', pass: true, detail: '' },
    { id: 'tls.hsts-preload', category: 'security', title: 't', severity: 'low', pass: true, detail: '' },
  ]), 'A+', 'modern TLS + preload HSTS → A+');
});

test('asvsCoverage: pass/fail/cleanSignal/not-observed', () => {
  const findings = [
    { id: 'tls.protocol', category: 'security', title: 't', severity: 'info', pass: true, detail: '' },
    { id: 'header.content-security-policy', category: 'security', title: 't', severity: 'high', pass: false, detail: '' },
    { id: 'exposure.none', category: 'exposure', title: 't', severity: 'info', pass: true, detail: '' },
  ];
  const cov = asvsCoverage(findings);
  const by = (id) => cov.find((r) => r.id === id);
  assert.equal(by('V9.1.3').status, 'pass', 'passing tls.protocol → pass');
  assert.equal(by('V14.4.3').status, 'fail', 'failing CSP → fail');
  assert.equal(by('V12.5.1').status, 'pass', 'clean exposure.none satisfies the backup-files req');
  assert.equal(by('V14.4.4').status, 'not-observed', 'nosniff never observed here');
  assert.equal(by('V3.4.5').status, 'not-covered', 'cookie-path is an honest gap');
});

// ═══════════════════════ active recon (identify-only) ══════════════════════

test('parsePorts handles common/all/list/garbage', () => {
  assert.ok(parsePorts('common').length > 20);
  assert.equal(parsePorts('all').length, 65535);
  assert.deepEqual(parsePorts('22,80,443'), [22, 80, 443]);
  assert.deepEqual(parsePorts('bad,99999,-1,0'), [], 'invalid ports are dropped');
});

test('parseNvd extracts id/severity/summary from an NVD 2.0 response', () => {
  const sample = { vulnerabilities: [
    { cve: { id: 'CVE-2016-10009', descriptions: [{ lang: 'en', value: 'Untrusted search path in ssh-agent in OpenSSH before 7.4.' }], metrics: { cvssMetricV31: [{ cvssData: { baseSeverity: 'HIGH' } }] } } },
    { cve: { id: 'CVE-2016-10010', descriptions: [{ lang: 'es', value: 'spanish' }, { lang: 'en', value: 'sshd privsep flaw.' }], metrics: {} } },
    { cve: {} },
  ] };
  const hits = parseNvd(sample);
  assert.equal(hits.length, 2, 'skips entries with no id');
  assert.deepEqual(hits[0], { id: 'CVE-2016-10009', summary: 'Untrusted search path in ssh-agent in OpenSSH before 7.4.', severity: 'HIGH' });
  assert.equal(hits[1].summary, 'sshd privsep flaw.', 'prefers the English description');
  assert.deepEqual(parseNvd({}), [], 'empty response → no hits');
});

test('identifyBanner extracts product + version for CVE lookup', () => {
  assert.deepEqual(identifyBanner('SSH-2.0-OpenSSH_8.9p1 Ubuntu'), { product: 'OpenSSH', version: '8.9p1' });
  assert.deepEqual(identifyBanner('Server: nginx/1.18.0'), { product: 'nginx', version: '1.18.0' });
  assert.equal(identifyBanner('Server: cloudflare').product, 'cloudflare');
  assert.equal(identifyBanner('220 ProFTPD 1.3.5 Server').product, 'ProFTPD');
  assert.deepEqual(identifyBanner(''), {}, 'no banner → nothing');
});

test('scanPort detects an open port (with banner) and a closed one', async () => {
  const srv = net.createServer((s) => s.end('SSH-2.0-OpenSSH_9.0\r\n'));
  await new Promise((r) => srv.listen(0, '127.0.0.1', () => r(null)));
  const port = (srv.address()).port;
  const open = await scanPort('127.0.0.1', port, 1500);
  srv.close();
  assert.equal(open.open, true, 'listening port reports open');
  assert.match(open.banner || '', /OpenSSH_9\.0/, 'grabs the service banner');

  const closed = await scanPort('127.0.0.1', 1, 800);
  assert.equal(closed.open, false, 'a port with nothing listening reports closed');
});

// ═══════════════════════ host / infrastructure intel ═══════════════════════

test('identifyEdge fingerprints CDN/hosting providers from headers', () => {
  assert.deepEqual(identifyEdge({ 'cf-ray': '123', server: 'cloudflare' }), { providers: ['Cloudflare'], behindCdn: true });
  assert.equal(identifyEdge({ 'x-vercel-id': 'abc' }).providers[0], 'Vercel');
  assert.equal(identifyEdge({ server: 'nginx/1.25' }).behindCdn, false, 'a bare nginx origin is not a CDN');
  assert.deepEqual(identifyEdge({}), { providers: [], behindCdn: false });
});

// ═══════════════════════ framework fingerprinting (#14) ═════════════════════

const hdr = (o) => new Headers(o);

test('detectStacks fingerprints Next.js, WordPress, Laravel, Spring with high confidence', () => {
  const next = detectStacks({ html: '<script id="__NEXT_DATA__" type="application/json">{}</script>', headers: hdr({}), setCookie: [] });
  assert.equal(next.find((s) => s.name === 'Next.js')?.confidence, 'high');

  const wp = detectStacks({ html: '<link href="/wp-content/themes/x/style.css"><meta name="generator" content="WordPress 6.4">', headers: hdr({}), setCookie: [] });
  assert.equal(wp.find((s) => s.name === 'WordPress')?.confidence, 'high');

  const laravel = detectStacks({ html: '<html></html>', headers: hdr({}), setCookie: ['laravel_session=abc; path=/'] });
  assert.equal(laravel.find((s) => s.name === 'Laravel')?.confidence, 'high');

  const spring = detectStacks({ html: '', headers: hdr({ 'x-application-context': 'application:prod' }), setCookie: ['JSESSIONID=x'] });
  assert.equal(spring.find((s) => s.name === 'Spring Boot')?.confidence, 'high');
});

test('detectStacks does not fingerprint a plain static site', () => {
  const s = detectStacks({ html: '<html><body><h1>hello</h1></body></html>', headers: hdr({}), setCookie: [] });
  assert.equal(s.filter((x) => x.confidence === 'high').length, 0, 'no false-positive stack on a plain page');
});

test('detectStacks: a lone spoofable x-powered-by is only MEDIUM (not high) — no framework probing', () => {
  const s = detectStacks({ html: '<html></html>', headers: hdr({ 'x-powered-by': 'Express' }), setCookie: [] });
  const express = s.find((x) => x.name === 'Express');
  assert.equal(express?.confidence, 'medium', 'a single spoofable header must not reach high confidence');
});

test('classifyTenantAccess: 200 with data but no control is INCONCLUSIVE, not a false pass', () => {
  const owner = { status: 200, body: '{"records":[{"id":1,"secret":"A"}]}' };
  const attackNonEmpty = { status: 200, body: '{"records":[{"id":2}]}' };
  assert.equal(classifyTenantAccess({ baseline: owner, attack: attackNonEmpty }).verdict, 'inconclusive');
  // still correctly isolated when the body is genuinely empty
  assert.equal(classifyTenantAccess({ baseline: owner, attack: { status: 200, body: '{"data":null}' } }).verdict, 'isolated');
});

test('framework category: probes WordPress user-enum only when WP is detected', async () => {
  // A "WordPress" server that leaks the REST user list.
  const wp = await server((req, res) => {
    if (req.url === '/wp-json/wp/v2/users') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('[{"id":1,"slug":"admin","name":"Admin"}]'); return; }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html><head><meta name="generator" content="WordPress 6.4"></head><body><img src="/wp-content/x.png"></body></html>');
  });
  const findings = await probe(wp.url, { only: ['framework'] });
  wp.close();
  assert.ok(findings.find((f) => f.id === 'framework.detected' && /WordPress/.test(f.detail)), 'reports WordPress detected');
  assert.ok(findings.find((f) => f.id === 'framework.wp.user-enum' && !f.pass), 'flags REST user enumeration');

  // A plain site: framework category should NOT probe wp-json and should report nothing fingerprinted.
  const plain = await server((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><body>plain</body></html>'); });
  const pf = await probe(plain.url, { only: ['framework'] });
  plain.close();
  assert.ok(pf.find((f) => f.id === 'framework.none' && f.pass), 'no framework fingerprinted on a plain site');
  assert.ok(!pf.some((f) => f.id === 'framework.wp.user-enum'), 'does not run WP checks on a non-WP site');
});

test('framework category: flags secrets serialized into Next.js __NEXT_DATA__', async () => {
  const srv = await server((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html><body><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"access_token":"ey-leaked"}}}</script></body></html>');
  });
  const findings = await probe(srv.url, { only: ['framework'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'framework.next.data-secrets' && !f.pass), 'flags a secret in __NEXT_DATA__');
});

test('render-health: flags a rendered error boundary (the Sparkle #119 class — 200, no pageerror)', () => {
  // Short page whose whole content is the fallback → HIGH, this is the exact miss browse/crawl had.
  const eb = renderHealthFindings('/forms/123', { visibleTextLen: 90, errorSignature: 'something went wrong', overlay: null, blankRoot: null, rootTextLen: 90 });
  assert.equal(eb.length, 1);
  assert.equal(eb[0].id, 'render.errorboundary/forms/123');
  assert.equal(eb[0].severity, 'high');
  assert.equal(eb[0].pass, false);
  assert.equal(eb[0].category, 'reliability');
});

test('render-health: does NOT flag a long page that merely mentions the phrase', () => {
  const ok = renderHealthFindings('/blog/post', { visibleTextLen: 4200, errorSignature: 'something went wrong', overlay: null, blankRoot: null, rootTextLen: 4200 });
  assert.equal(ok.length, 1);
  assert.equal(ok[0].pass, true, 'a 4200-char article that says "something went wrong" is not a crash');
  assert.equal(ok[0].id, 'render.ok/blog/post');
});

test('render-health: flags a framework crash overlay and a blank app root', () => {
  const ov = renderHealthFindings('/x', { visibleTextLen: 1200, errorSignature: null, overlay: 'nextjs-portal', blankRoot: null, rootTextLen: 1200 });
  assert.equal(ov[0].id, 'render.overlay/x');
  assert.equal(ov[0].severity, 'high');

  const blank = renderHealthFindings('/dashboard', { visibleTextLen: 0, errorSignature: null, overlay: null, blankRoot: '#root', rootTextLen: 0 });
  assert.equal(blank[0].id, 'render.blank/dashboard');
  assert.equal(blank[0].severity, 'medium');
});

test('render-health: healthy page yields an info PASS (so the report records the check ran)', () => {
  const ok = renderHealthFindings('/', { visibleTextLen: 2000, errorSignature: null, overlay: null, blankRoot: null, rootTextLen: 2000 });
  assert.equal(ok[0].pass, true);
  assert.equal(ok[0].severity, 'info');
  assert.equal(ok[0].id, 'render.ok/');
});

test('render-health: category is overridable (e.g. security scans)', () => {
  const s = renderHealthFindings('/p', { visibleTextLen: 50, errorSignature: 'unhandled runtime error', overlay: null, blankRoot: null, rootTextLen: 50 }, 'security');
  assert.equal(s[0].category, 'security');
  assert.equal(s[0].severity, 'high');
});

// ---- OWASP A06: vulnerable client-side components (retire.js-style) ----
test('components: versionLt compares dotted versions', () => {
  assert.equal(versionLt('3.4.1', '3.5.0'), true);
  assert.equal(versionLt('3.5.0', '3.5.0'), false);
  assert.equal(versionLt('4.17.21', '4.17.21'), false);
  assert.equal(versionLt('1.9.0', '1.13.0'), true);
});

test('components: detects a library + version from a CDN URL and flags the known CVE', () => {
  const html = `<html><head><script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script></head></html>`;
  const detected = detectComponents(html, 'https://example.com/');
  const jq = detected.find((d) => d.name === 'jquery');
  assert.ok(jq, 'detected jquery');
  assert.equal(jq.version, '3.4.1');
  const v = matchVulnerabilities(jq);
  assert.ok(v && /CVE-2020-11022/.test(v.ref), 'matched the jQuery XSS CVE');
  assert.equal(v.severity, 'medium');
});

test('components: a current library is detected but NOT flagged', () => {
  const html = `<script src="/vendor/jquery-3.7.1.min.js"></script>`;
  const jq = detectComponents(html, 'https://example.com/').find((d) => d.name === 'jquery');
  assert.ok(jq && jq.version === '3.7.1');
  assert.equal(matchVulnerabilities(jq), null, 'jquery 3.7.1 is not vulnerable');
});

test('components: detects lodash from npm-CDN @version + flags high-sev RCE range', () => {
  const html = `<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.11/lodash.min.js"></script>`;
  const c = detectComponents(html, 'https://x.com/').find((d) => d.name === 'lodash');
  assert.ok(c && c.version === '4.17.11');
  const v = matchVulnerabilities(c);
  assert.equal(v && v.severity, 'high');
});

test('components: componentChecks emits a HIGH failing finding for the whole scan', async () => {
  const html = `<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.11/lodash.min.js"></script>`;
  const findings = await componentChecks({ html, baseUrl: 'https://x.com/', origin: 'https://x.com', url: new URL('https://x.com/'), res: null, headers: new Headers(), opts: {} } as any);
  const bad = findings.find((f) => f.id === 'components.lodash' && !f.pass);
  assert.ok(bad, 'flags vulnerable lodash');
  assert.equal(bad.category, 'components');
  assert.equal(bad.severity, 'high');
});

test('components: no libraries → a single info pass, never a false positive', async () => {
  const findings = await componentChecks({ html: '<html><body>hi</body></html>', baseUrl: 'https://x.com/', origin: 'https://x.com', url: new URL('https://x.com/'), res: null, headers: new Headers(), opts: {} } as any);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'components.none');
  assert.equal(findings[0].pass, true);
});

// ---- JWT hygiene ----
test('jwt: b64urlDecode round-trips and analyzeJwt reads the header alg', () => {
  const t = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'u1', exp: 9999999999, iat: 9999900000 });
  const a = analyzeJwt(t);
  assert.equal(a.valid, true);
  assert.equal(a.alg, 'HS256');
  assert.equal(a.hasExp, true);
});

test('jwt: alg:none is flagged HIGH', () => {
  const t = makeJwt({ alg: 'none', typ: 'JWT' }, { sub: 'admin' }, '');
  const findings = jwtFindings({ html: `token=${t}`, headers: new Headers(), origin: 'https://x.com' } as any);
  const none = findings.find((f) => f.id === 'jwt.alg-none');
  assert.ok(none && !none.pass && none.severity === 'high');
});

test('jwt: missing exp is flagged MEDIUM; sensitive claims are surfaced', () => {
  const t = makeJwt({ alg: 'HS256' }, { sub: 'u1', email: 'a@b.com', role: 'admin' });
  const findings = jwtFindings({ html: t, headers: new Headers(), origin: 'https://x.com' } as any);
  assert.ok(findings.find((f) => f.id === 'jwt.no-exp' && f.severity === 'medium'));
  assert.ok(findings.find((f) => f.id === 'jwt.sensitive-claims'));
});

test('jwt: JWT in a non-HttpOnly cookie is flagged; clean token → no noise', () => {
  const t = makeJwt({ alg: 'RS256' }, { sub: 'u1', exp: 2000000000, iat: 1999999000 });
  const h = new Headers(); h.append('set-cookie', `session=${t}; Path=/; Secure`); // no HttpOnly
  const findings = jwtFindings({ html: '', headers: h, origin: 'https://x.com' } as any);
  assert.ok(findings.find((f) => f.id === 'jwt.cookie-not-httponly' && f.severity === 'medium'));
});

test('jwt: no JWT present → stays silent (no findings)', () => {
  assert.equal(jwtFindings({ html: '<html>nothing here</html>', headers: new Headers(), origin: 'https://x.com' } as any).length, 0);
});

// ---- Host-header injection ----
test('host-header: flags reflection of a spoofed X-Forwarded-Host', async () => {
  const srv = await server((req, res) => {
    const xfh = req.headers['x-forwarded-host'] || 'localhost';
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<html><head><link rel="canonical" href="https://${xfh}/home"></head><body>hi</body></html>`);
  });
  const findings = await hostHeaderChecks({ origin: srv.url, opts: {} } as any);
  srv.close();
  const hit = findings.find((f) => f.id === 'host-header.injection');
  assert.ok(hit && !hit.pass, 'reflected host is flagged');
  assert.equal(hit.severity, 'medium');
});

test('host-header: a well-behaved app (fixed canonical host) passes', async () => {
  const srv = await server((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<html><head><link rel="canonical" href="https://fixed.example/home"></head><body>hi</body></html>`);
  });
  const findings = await hostHeaderChecks({ origin: srv.url, opts: {} } as any);
  srv.close();
  const hit = findings.find((f) => f.id === 'host-header.injection');
  assert.ok(hit && hit.pass, 'no reflection → pass');
});

// ---- CSRF protection heuristic ----
test('csrf: POST form with no token + no SameSite → MEDIUM', () => {
  const h = new Headers(); h.append('set-cookie', 'sessionid=abc; Path=/; HttpOnly');
  const ctx = { html: `<form method="post" action="/transfer"><input name="amount"></form>`, headers: h } as any;
  const hit = csrfFindings(ctx).find((f) => f.id === 'csrf');
  assert.ok(hit && !hit.pass && hit.severity === 'medium', 'unprotected POST form flagged medium');
});

test('csrf: a CSRF token field clears it (pass)', () => {
  const ctx = { html: `<form method="post"><input type="hidden" name="_csrf" value="x"><input name="q"></form>`, headers: new Headers() } as any;
  const hit = csrfFindings(ctx).find((f) => f.id === 'csrf');
  assert.ok(hit && hit.pass, 'token present → pass');
});

test('csrf: SameSite=Strict cookie downgrades a token-less form to LOW', () => {
  const h = new Headers(); h.append('set-cookie', 'session=abc; Path=/; HttpOnly; SameSite=Strict');
  const ctx = { html: `<form method="post"><input name="q"></form>`, headers: h } as any;
  const hit = csrfFindings(ctx).find((f) => f.id === 'csrf');
  assert.ok(hit && !hit.pass && hit.severity === 'low', 'SameSite mitigates → low');
});

test('csrf: no POST forms (SPA) → not applicable, no finding', () => {
  const ctx = { html: `<form><input name="q"></form><div id="app"></div>`, headers: new Headers() } as any;
  assert.equal(csrfFindings(ctx).length, 0);
});

// ---- DOM-XSS sink heuristic ----
test('dom-xss: direct location→innerHTML flow is flagged', () => {
  const hits = scanDomXssSinks(`function r(){ document.getElementById('o').innerHTML = location.hash.slice(1); }`);
  assert.ok(hits.some((h) => /innerHTML/.test(h.sink)), 'innerHTML ← location.hash detected');
});

test('dom-xss: document.write(location) and eval(location) flagged', () => {
  assert.ok(scanDomXssSinks(`document.write(location.search)`).length, 'document.write');
  assert.ok(scanDomXssSinks(`eval(location.hash)`).length, 'eval');
});

test('dom-xss: a lone innerHTML with no source is NOT flagged (low false positive)', () => {
  assert.equal(scanDomXssSinks(`el.innerHTML = "<b>static</b>"; render(data);`).length, 0);
});

test('dom-xss: domXssFindings scans only inline scripts and emits a MEDIUM finding', () => {
  const ctx = { html: `<script>document.body.innerHTML = document.referrer;</script>` } as any;
  const hit = domXssFindings(ctx).find((f) => f.id === 'dom-xss');
  assert.ok(hit && !hit.pass && hit.severity === 'medium');
});

test('dom-xss: clean inline script → no findings', () => {
  const ctx = { html: `<script>console.log('hi'); const x = 1;</script>` } as any;
  assert.equal(domXssFindings(ctx).length, 0);
});

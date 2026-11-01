// src/checks.ts
// Every check takes the shared ScanContext (homepage fetched once) and returns Finding[]. They are
// grouped by Category. All are black-box: a URL is the only input, so the same kit works against any
// vibe-coded app — Vite, Next, Astro, Rails, whatever — without touching the source.

import type { Finding, ScanContext, Severity } from './types.js';
import {
  safeFetch, fetchText, resolveUrl, sameOrigin, html as H, scanSecrets,
  tlsProbe, gradeTlsProtocol, gradeTlsCipher,
} from './core.js';
import { jwtFindings } from './jwt.js';
import { hostHeaderChecks } from './hostheader.js';
import { csrfFindings } from './csrf.js';
import { domXssFindings } from './domxss.js';
import { jsonLdFindings } from './jsonld.js';
import { apiExposureFindings, apiSecurityFindings } from './api.js';

const f = (
  category: Finding['category'],
  id: string,
  title: string,
  severity: Severity,
  pass: boolean,
  detail: string,
  fix?: string,
): Finding => ({ category, id, title, severity, pass, detail, fix });

// Set-Cookie headers, preferring the structured getSetCookie() API and falling back to the raw folded
// header on older runtimes. The fallback splits on the comma that precedes a new "name=" pair, so an
// Expires date's own comma doesn't split a cookie in two.
function getSetCookieHeaders(h: Headers): string[] {
  const structured = (h as { getSetCookie?: () => string[] }).getSetCookie?.();
  if (structured?.length) return structured;
  const raw = h.get('set-cookie');
  if (!raw) return [];
  return raw.split(/,(?=\s*[A-Za-z0-9!#$%&'*+.^_`|~-]+=)/).map((c) => c.trim()).filter(Boolean);
}

// Parse a CSP header into a directive→sources map (lowercased directive names).
function parseCsp(policy: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const part of policy.split(';')) {
    const [name, ...sources] = part.trim().split(/\s+/);
    if (name) map.set(name.toLowerCase(), sources);
  }
  return map;
}

export interface CspIssue { id: string; title: string; severity: Severity; detail: string; fix: string }

/** Grade a CSP beyond mere presence: the weaknesses that actually let XSS through. Regex-free, zero-dep. */
export function lintCsp(policy: string): CspIssue[] {
  const d = parseCsp(policy);
  const issues: CspIssue[] = [];
  // script-src falls back to default-src when absent (CSP semantics).
  const scriptSrc = d.get('script-src') ?? d.get('default-src') ?? [];
  const has = (list: string[], token: string) => list.some((s) => s.toLowerCase() === token);

  if (has(scriptSrc, "'unsafe-inline'")) {
    issues.push({ id: 'csp.unsafe-inline', title: "CSP allows 'unsafe-inline' scripts", severity: 'high', detail: "script-src includes 'unsafe-inline' — injected <script> and inline handlers still run, defeating most of the CSP", fix: "Drop 'unsafe-inline'; use nonces ('nonce-…') or hashes for the scripts you do need." });
  }
  if (has(scriptSrc, "'unsafe-eval'")) {
    issues.push({ id: 'csp.unsafe-eval', title: "CSP allows 'unsafe-eval'", severity: 'medium', detail: "script-src includes 'unsafe-eval' — eval()/new Function() are allowed, widening the XSS surface", fix: "Remove 'unsafe-eval' and refactor any eval()/Function() usage." });
  }
  if (scriptSrc.some((s) => s === '*' || /^https?:$/i.test(s) || s === 'data:')) {
    issues.push({ id: 'csp.wildcard-script', title: 'CSP script source is a wildcard', severity: 'high', detail: `script-src allows a wildcard source (${scriptSrc.find((s) => s === '*' || /^https?:$/i.test(s) || s === 'data:')}) — any host can supply scripts`, fix: 'Pin script-src to specific trusted origins (or self + nonces), not * / https: / data:.' });
  }
  // object-src falls back to default-src (CSP semantics): default-src 'none' already locks plugins down.
  const objectSrc = d.get('object-src') ?? d.get('default-src') ?? [];
  if (!has(objectSrc, "'none'")) {
    issues.push({ id: 'csp.object-src', title: "CSP missing object-src 'none'", severity: 'low', detail: 'without object-src \'none\' (or a default-src \'none\' fallback), legacy plugin vectors (<object>/<embed>) remain open', fix: "Add object-src 'none' (or default-src 'none')." });
  }
  if (!d.has('base-uri')) {
    issues.push({ id: 'csp.base-uri', title: 'CSP missing base-uri', severity: 'low', detail: 'without base-uri, an injected <base> tag can hijack relative URLs', fix: "Add base-uri 'self' (or 'none')." });
  }
  return issues;
}

// ───────────────────────────── security (headers / TLS / CORS / cookies) ─────────────────────────

const REQUIRED_HEADERS: { name: string; severity: Severity; validate?: (v: string) => boolean; hint: string; fix: string }[] = [
  { name: 'strict-transport-security', severity: 'high', validate: (v) => /max-age=\d{5,}/.test(v), hint: 'HSTS with a long max-age', fix: 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains' },
  { name: 'x-content-type-options', severity: 'medium', validate: (v) => v.toLowerCase().includes('nosniff'), hint: 'nosniff', fix: 'Send X-Content-Type-Options: nosniff' },
  { name: 'referrer-policy', severity: 'low', hint: 'e.g. strict-origin-when-cross-origin', fix: 'Send Referrer-Policy: strict-origin-when-cross-origin' },
  { name: 'x-frame-options', severity: 'medium', hint: 'SAMEORIGIN/DENY or CSP frame-ancestors', fix: 'Send X-Frame-Options: SAMEORIGIN (or a CSP frame-ancestors directive)' },
  { name: 'content-security-policy', severity: 'high', hint: 'a Content-Security-Policy (enforced)', fix: 'Add a Content-Security-Policy header to stop injected scripts' },
  { name: 'permissions-policy', severity: 'low', hint: 'a Permissions-Policy locking down camera/mic/geolocation', fix: 'Send a Permissions-Policy header (e.g. camera=(), microphone=(), geolocation=()) to disable powerful APIs you don\'t use' },
];

export async function securityChecks(ctx: ScanContext): Promise<Finding[]> {
  const out: Finding[] = [];
  const { origin, url } = ctx;

  // TLS + redirect
  if (url.protocol !== 'https:') {
    out.push(f('security', 'tls.scheme', 'Site is not served over HTTPS', 'high', false, `URL uses ${url.protocol}`, 'Serve the app over https:// — most hosts (Cloudflare/Vercel/Netlify) do this automatically.'));
  } else {
    out.push(f('security', 'tls.scheme', 'Served over HTTPS', 'high', true, origin));
    const httpRes = await safeFetch(origin.replace('https:', 'http:'));
    if (httpRes) {
      const loc = httpRes.headers.get('location') || '';
      const redirects = httpRes.status >= 300 && httpRes.status < 400 && loc.startsWith('https:');
      out.push(f('security', 'tls.redirect', 'HTTP redirects to HTTPS', 'medium', redirects, redirects ? `HTTP ${httpRes.status} -> ${loc}` : `http:// did not 3xx->https (status ${httpRes.status})`, 'Redirect all http:// traffic to https://.'));
    }
  }

  if (!ctx.res) {
    out.push({
      category: 'security',
      id: 'reachability',
      title: 'Site unreachable after retries (error/inconclusive)',
      severity: 'info',
      pass: true,
      inconclusive: true,
      retries: ctx.opts.retries ?? 0,
      detail: `fetch ${origin} failed`,
      fix: 'Confirm the deploy is live and retry. This is not a security finding.',
    });
    return out;
  }
  const h = ctx.headers;

  for (const req of REQUIRED_HEADERS) {
    const val = h.get(req.name);
    if (req.name === 'content-security-policy' && !val) {
      const ro = h.get('content-security-policy-report-only');
      if (ro && ctx.opts.allowReportOnlyCsp) {
        out.push(f('security', 'header.content-security-policy', 'CSP present (Report-Only)', 'info', true, 'Only Report-Only is set — enforce once tuned.'));
        continue;
      }
    }
    const present = !!val;
    const valid = present && (!req.validate || req.validate(val!));
    out.push(f('security', `header.${req.name}`, present ? `Header ${req.name}${valid ? '' : ' (weak)'}` : `Missing ${req.name}`, req.severity, valid, present ? `${req.name}: ${val}`.slice(0, 200) : `expected ${req.hint}`, req.fix));
  }

  // HSTS preload eligibility: present-but-not-preloadable is a common near-miss. Only nudge if HSTS is set.
  const hsts = h.get('strict-transport-security') || '';
  if (hsts) {
    const maxAge = Number(hsts.match(/max-age=(\d+)/i)?.[1] || 0);
    const eligible = maxAge >= 31_536_000 && /includesubdomains/i.test(hsts) && /preload/i.test(hsts);
    out.push(f('security', 'tls.hsts-preload', eligible ? 'HSTS is preload-eligible' : 'HSTS not preload-eligible', 'low', eligible, eligible ? 'max-age≥1y + includeSubDomains + preload' : `has HSTS but ${maxAge < 31_536_000 ? 'max-age<1y' : ''}${!/includesubdomains/i.test(hsts) ? ' no includeSubDomains' : ''}${!/preload/i.test(hsts) ? ' no preload token' : ''}`.trim(), eligible ? undefined : 'For hstspreload.org eligibility send: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'));
  }

  // Cross-Origin-Opener-Policy: cheap isolation win against cross-window attacks (Spectre/XS-Leaks).
  const coop = h.get('cross-origin-opener-policy');
  out.push(f('security', 'header.cross-origin-opener-policy', coop ? 'Has Cross-Origin-Opener-Policy' : 'No Cross-Origin-Opener-Policy', 'low', !!coop, coop ? `cross-origin-opener-policy: ${coop}` : 'no COOP header', coop ? undefined : 'Send Cross-Origin-Opener-Policy: same-origin to isolate your window from cross-origin popups.'));

  // Cross-Origin-Resource-Policy: the third of the isolation trio (with COOP/COEP) — limits who can embed
  // your resources. Low, informational.
  const corp = h.get('cross-origin-resource-policy');
  out.push(f('security', 'header.cross-origin-resource-policy', corp ? 'Has Cross-Origin-Resource-Policy' : 'No Cross-Origin-Resource-Policy', 'low', !!corp, corp ? `cross-origin-resource-policy: ${corp}` : 'no CORP header', corp ? undefined : 'Send Cross-Origin-Resource-Policy: same-origin (or same-site) so other origins can\'t embed your resources.'));

  // Content-Type + charset on the document (ASVS V14.4.1) — a missing charset on text/html invites
  // sniffing/UTF-7-style issues.
  const docCt = h.get('content-type') || '';
  const isText = /text\/html|application\/xhtml/i.test(docCt);
  const ctOk = !!docCt && (!isText || /charset=/i.test(docCt));
  out.push(f('security', 'header.content-type', docCt ? (ctOk ? `Content-Type set (${docCt})` : 'Content-Type missing charset') : 'No Content-Type header', ctOk ? 'info' : 'low', ctOk, docCt || 'response had no Content-Type', ctOk ? undefined : 'Send a Content-Type with an explicit charset (e.g. text/html; charset=utf-8).'));

  // Anti-caching on authenticated responses (ASVS V8.2.1) — only meaningful when we're scanning behind
  // login; a shared cache/browser must not retain private pages.
  if (ctx.opts.extraHeaders) {
    const cc = h.get('cache-control') || '';
    const safe = /no-store|no-cache|private/i.test(cc);
    out.push(f('security', 'cache.sensitive', safe ? 'Authenticated response is non-cacheable' : 'Authenticated response lacks anti-caching headers', 'medium', safe, `cache-control: ${cc || '(none)'}`, safe ? undefined : 'On authenticated/sensitive pages send Cache-Control: no-store so private data isn\'t cached by browsers or shared proxies.'));
  }

  // HTTP methods (WSTG-CONF-06): enumerate via OPTIONS; flag TRACE (Cross-Site Tracing) + risky verbs.
  const optRes = await safeFetch(origin, { method: 'OPTIONS', headers: ctx.opts.extraHeaders });
  if (optRes) {
    const allow = (optRes.headers.get('allow') || optRes.headers.get('access-control-allow-methods') || '').toUpperCase();
    if (allow) {
      const risky = ['TRACE', 'TRACK', 'CONNECT', 'PUT', 'DELETE', 'PATCH'].filter((m) => allow.includes(m));
      const hasTrace = allow.includes('TRACE') || allow.includes('TRACK');
      out.push(f('security', 'http.methods', hasTrace ? 'TRACE/TRACK method enabled (XST)' : risky.length ? `Extra HTTP methods allowed: ${risky.join(', ')}` : 'HTTP methods look restrained', hasTrace ? 'medium' : 'low', !hasTrace && risky.length === 0, `Allow: ${allow}`, hasTrace ? 'Disable TRACE/TRACK at the server — they enable Cross-Site Tracing (XST) and echo request headers.' : risky.length ? 'Ensure write verbs (PUT/DELETE/PATCH) are auth-gated and only exposed where intended.' : undefined));
    }
  }

  // CSP linting: grade the policy that IS set (enforced, or Report-Only when the caller accepts it).
  const cspToLint = h.get('content-security-policy') || (ctx.opts.allowReportOnlyCsp ? h.get('content-security-policy-report-only') : null);
  if (cspToLint) {
    for (const issue of lintCsp(cspToLint)) {
      out.push(f('security', issue.id, issue.title, issue.severity, false, issue.detail, issue.fix));
    }
  }

  // Version-banner disclosure
  let disclosed = false;
  for (const banner of ['server', 'x-powered-by']) {
    const v = h.get(banner);
    if (v && /\d/.test(v)) {
      disclosed = true;
      out.push(f('security', `disclosure.${banner}`, `Version banner in ${banner}`, 'low', false, `${banner}: ${v}`, `Strip the ${banner} header so you don't advertise exact versions to attackers.`));
    }
  }
  if (!disclosed) out.push(f('security', 'disclosure.none', 'No version banners disclosed', 'info', true, 'no numeric Server/X-Powered-By version'));

  // Cookie flags. Prefer getSetCookie() (Node 20+); fall back to the raw header so the check never
  // silently no-ops on an older undici that only folds set-cookie into one value.
  const setCookie = getSetCookieHeaders(h);
  if (setCookie.length) {
    for (const c of setCookie) {
      const name = c.split('=')[0];
      const secure = /;\s*secure/i.test(c);
      const httpOnly = /;\s*httponly/i.test(c);
      const sameSite = /;\s*samesite=/i.test(c);
      const ok = secure && httpOnly && sameSite;
      out.push(f('security', `cookie.${name}`, `Cookie ${name} flags`, 'medium', ok, `Secure=${secure} HttpOnly=${httpOnly} SameSite=${sameSite}`, 'Set Secure + HttpOnly + SameSite on session cookies so they can\'t be stolen by scripts or sent cross-site.'));
      // Split-out (#24): a missing Secure flag is its own always-on finding — without it the cookie can
      // ride any downgraded/mixed request regardless of HttpOnly/SameSite.
      out.push(f('security', `cookie-secure.${name}`, `Cookie ${name} Secure flag`, 'medium', secure, secure ? 'Secure is set' : 'no Secure attribute — the cookie can be sent over a downgraded/mixed request', secure ? undefined : `Add the Secure attribute to the ${name} cookie so it is only ever sent over https.`));
      // Defense-in-depth: a session-ish cookie ideally carries a __Host-/__Secure- prefix.
      const prefixed = name.startsWith('__Host-') || name.startsWith('__Secure-');
      out.push(f('security', `cookie-prefix.${name}`, `Cookie ${name} prefix`, 'info', prefixed, prefixed ? 'uses __Host-/__Secure- prefix' : 'consider a __Host- prefix for session cookies', prefixed ? undefined : 'Rename session cookies to __Host-<name> so the browser pins them to your origin + https.'));
    }
  }

  // security.txt
  const stPath = ctx.opts.securityTxtPath || '/.well-known/security.txt';
  const st = await safeFetch(origin + stPath, { redirect: 'follow', headers: ctx.opts.extraHeaders });
  if (st && st.ok) {
    const body = await st.text();
    const ok = /^contact:/im.test(body) && /^expires:/im.test(body);
    out.push(f('security', 'securitytxt', 'security.txt present', 'low', ok, ok ? 'has Contact + Expires' : 'present but missing Contact/Expires (RFC 9116)'));
  } else {
    out.push(f('security', 'securitytxt', 'No security.txt', 'low', false, `expected at ${stPath}`, 'Add /.well-known/security.txt so researchers know how to report bugs to you.'));
  }

  // Dangerous CORS reflection
  if (ctx.opts.corsTestPath) {
    const evil = 'https://evil.example';
    const cors = await safeFetch(origin + ctx.opts.corsTestPath, { headers: { Origin: evil } });
    if (cors) {
      const acao = cors.headers.get('access-control-allow-origin') || '';
      const acac = (cors.headers.get('access-control-allow-credentials') || '').toLowerCase() === 'true';
      const dangerous = acao === evil && acac;
      out.push(f('security', 'cors.reflection', 'CORS origin reflection', dangerous ? 'high' : 'info', !dangerous, `ACAO=${acao || '(none)'} ACAC=${acac}`, dangerous ? 'Never reflect an arbitrary Origin while also allowing credentials — that lets any site read authenticated responses.' : undefined));
    }
  }

  // TLS: cert expiry + protocol/cipher grading (https only) — reads the served cert via a raw TLS socket.
  if (url.protocol === 'https:') {
    const tlsInfo = await tlsProbe(url.hostname, Number(url.port) || 443);
    const days = tlsInfo.daysRemaining;
    if (days === null) {
      out.push(f('security', 'tls.expiry', 'TLS cert expiry not determinable', 'info', true, 'could not read the peer certificate'));
    } else {
      const sev: Severity = days < 14 ? 'high' : days < 30 ? 'medium' : 'low';
      out.push(f('security', 'tls.expiry', `TLS cert expires in ${days} day(s)`, sev, days >= 14, days < 14 ? 'certificate expires very soon — renew now' : `${days} days remaining`, days >= 30 ? undefined : 'Renew the TLS certificate (or enable auto-renewal — Let\'s Encrypt/most hosts do this for you).'));
    }
    // Deprecated protocol (TLS 1.0/1.1/SSLv3) — the modern high-value TLS finding.
    const proto = gradeTlsProtocol(tlsInfo.protocol);
    out.push(f('security', 'tls.protocol', proto.ok ? `TLS protocol ${tlsInfo.protocol ?? '(unknown)'}` : `Deprecated TLS protocol ${tlsInfo.protocol}`, proto.severity, proto.ok, proto.detail, proto.ok ? undefined : 'Disable TLS 1.0/1.1 (and SSLv3) at the host/load-balancer — require TLS 1.2+ (ideally 1.3).'));
    // Weak cipher suite.
    const cipher = gradeTlsCipher(tlsInfo.cipher);
    if (tlsInfo.cipher) {
      out.push(f('security', 'tls.cipher', cipher.ok ? `TLS cipher ${tlsInfo.cipher}` : `Weak TLS cipher ${tlsInfo.cipher}`, 'medium', cipher.ok, cipher.detail, cipher.ok ? undefined : 'Disable weak/legacy ciphers (RC4/3DES/CBC/MD5/EXPORT) — prefer AEAD suites (AES-GCM / ChaCha20-Poly1305).'));
    }
  }

  // Subresource Integrity: cross-origin <script>/<link rel=stylesheet> should carry an integrity attr.
  const sriTags = [...ctx.html.matchAll(/<(?:script|link)\b[^>]*>/gi)].map((m) => m[0]);
  const crossOriginNoSri = sriTags.filter((t) => {
    const m = t.match(/(?:src|href)\s*=\s*["'](https?:\/\/[^"']+)["']/i);
    if (!m) return false;
    const isCross = !sameOrigin(m[1], ctx.baseUrl);
    const isScriptish = /<script/i.test(t) || /rel\s*=\s*["']stylesheet["']/i.test(t);
    return isCross && isScriptish && !/\bintegrity\s*=/.test(t);
  });
  if (sriTags.length) {
    out.push(f('security', 'sri', crossOriginNoSri.length ? `${crossOriginNoSri.length} cross-origin asset(s) without SRI` : 'Cross-origin assets use SRI (or none present)', 'low', crossOriginNoSri.length === 0, crossOriginNoSri.length ? 'a compromised third-party CDN could inject code' : 'no un-pinned cross-origin scripts/styles', crossOriginNoSri.length ? 'Add integrity="sha384-…" + crossorigin to third-party <script>/<link> so a hacked CDN can\'t swap the file.' : undefined));
  }

  // Open redirect: try common redirect params pointed off-domain; fail if the server 3xx's there.
  const evilRedirect = 'https://evil.example/';
  const redirectParams = ['next', 'redirect', 'redirect_uri', 'url', 'return', 'returnTo', 'dest', 'continue'];
  let openRedirectParam: string | null = null;
  for (const p of redirectParams) {
    const r = await safeFetch(`${origin}/?${p}=${encodeURIComponent(evilRedirect)}`, { redirect: 'manual' });
    if (r && r.status >= 300 && r.status < 400) {
      const loc = r.headers.get('location') || '';
      if (/^(?:https?:)?\/\/evil\.example/i.test(loc)) { openRedirectParam = p; break; }
    }
  }
  out.push(f('security', 'open-redirect', openRedirectParam ? `Open redirect via ?${openRedirectParam}` : 'No open redirect on common params', 'high', !openRedirectParam, openRedirectParam ? `?${openRedirectParam}= redirects off-domain to an attacker URL` : 'common redirect params do not redirect off-domain', openRedirectParam ? 'Validate redirect targets against an allow-list of your own paths — never redirect to an arbitrary user-supplied URL.' : undefined));

  // Rate limiting (opt-in): burst a path and expect a 429.
  if (ctx.opts.rateLimitPath) {
    const target = origin + ctx.opts.rateLimitPath;
    const burst = await Promise.all(Array.from({ length: 25 }, () => safeFetch(target, undefined, undefined, { retries: 0 })));
    const got429 = burst.some((r) => r && r.status === 429);
    out.push(f('security', 'rate-limit', got429 ? 'Rate limiting active' : 'No rate limiting observed', 'medium', got429, got429 ? '25-request burst was throttled (429)' : `25 rapid requests to ${ctx.opts.rateLimitPath} were not throttled`, got429 ? undefined : 'Add rate limiting on auth/public endpoints so they can\'t be brute-forced or hammered.'));
  }

  // JWT hygiene on any token exposed to the browser (alg:none / no-exp / long-lived / non-HttpOnly cookie).
  out.push(...jwtFindings(ctx));
  // Host-header injection (password-reset / cache poisoning) — one extra request with a spoofed host.
  out.push(...await hostHeaderChecks(ctx));
  // CSRF protection heuristic on state-changing HTML forms (conservative — SameSite/token aware).
  out.push(...csrfFindings(ctx));
  // DOM-XSS: user-controllable source flowing directly into an HTML/JS sink in inline scripts.
  out.push(...domXssFindings(ctx));
  // JSON-LD script-breakout: structured-data blocks that don't escape </script> (stored XSS).
  out.push(...jsonLdFindings(ctx));
  // API-surface security nuances (#24): CORS-on-discovered-routes (on), rate-limit scan + reflected-XSS (opt-in).
  out.push(...await apiSecurityFindings(ctx));

  return out;
}

// ───────────────────────────── secrets (keys leaked to the browser) ──────────────────────────────

export async function secretChecks(ctx: ScanContext): Promise<Finding[]> {
  const out: Finding[] = [];
  if (!ctx.res) return out;

  // Scan the HTML itself + every same-origin script bundle (capped) — this is where vibe coders most
  // often leak a key by hardcoding it into client code.
  const blobs: { where: string; text: string }[] = [{ where: 'HTML', text: ctx.html }];
  const scripts = H.scripts(ctx.html)
    .map((s) => resolveUrl(ctx.baseUrl, s))
    .filter((u): u is string => !!u && sameOrigin(u, ctx.baseUrl))
    .slice(0, ctx.opts.maxCrawl ?? 25);

  let mapExposed = 0;
  for (const src of scripts) {
    const text = await fetchText(src, { headers: ctx.opts.extraHeaders });
    if (!text) continue;
    blobs.push({ where: src.replace(ctx.origin, ''), text });
    // Source map exposure → the app's original (unminified) source is downloadable.
    const mapRef = text.match(/[#@]\s*sourceMappingURL=([^\s'"]+)/)?.[1];
    if (mapRef && !mapRef.startsWith('data:')) {
      const mapUrl = resolveUrl(src, mapRef);
      if (mapUrl) {
        const map = await fetchText(mapUrl, undefined, 200_000);
        if (map.includes('"sources"')) mapExposed++;
      }
    }
  }

  let total = 0;
  for (const { where, text } of blobs) {
    for (const hit of scanSecrets(text)) {
      total++;
      out.push(f('secrets', `secret.${hit.ruleId}`, `${hit.name} exposed in client code`, hit.severity, false, `${hit.name} (${hit.sample}) found in ${where}`, 'Remove the key from client code and rotate it immediately. Secret keys belong in server-side env vars only.'));
    }
  }
  if (total === 0) out.push(f('secrets', 'secret.none', 'No hardcoded secrets in client code', 'info', true, `scanned ${blobs.length} file(s)`));

  if (mapExposed > 0) {
    out.push(f('secrets', 'sourcemap.exposed', 'Source maps are publicly downloadable', 'medium', false, `${mapExposed} reachable .map file(s) expose your original source`, 'Disable source-map upload to production (or restrict access) so your unminified code isn\'t downloadable.'));
  }

  return out;
}

// ───────────────────────────── exposure (.env / .git / config / debug) ───────────────────────────

// Each probe validates the BODY, not just a 200 — SPAs return 200 + index.html for unknown paths, so
// a naive status check would false-positive on every single one.
const EXPOSED_PATHS: { path: string; severity: Severity; looksReal: (body: string, ct: string) => boolean; label: string }[] = [
  // Match KEY= at line start for any case (Flask/Django use lowercase like `debug_mode=true`), but still
  // reject an SPA's index.html catch-all.
  { path: '/.env', severity: 'high', label: '.env file', looksReal: (b) => /^[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(b) && !/<html/i.test(b) },
  { path: '/.env.local', severity: 'high', label: '.env.local', looksReal: (b) => /^[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(b) && !/<html/i.test(b) },
  { path: '/.env.production', severity: 'high', label: '.env.production', looksReal: (b) => /^[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(b) && !/<html/i.test(b) },
  { path: '/.git/config', severity: 'high', label: '.git/config', looksReal: (b) => /\[core\]|\[remote/i.test(b) },
  { path: '/.git/HEAD', severity: 'high', label: '.git/HEAD', looksReal: (b) => /^ref:\s/m.test(b) },
  { path: '/wrangler.toml', severity: 'high', label: 'wrangler.toml', looksReal: (b) => /compatibility_date|^name\s*=/m.test(b) },
  { path: '/package.json', severity: 'low', label: 'package.json', looksReal: (b, ct) => ct.includes('json') && /"(?:dependencies|name)"\s*:/.test(b) },
  { path: '/.npmrc', severity: 'high', label: '.npmrc', looksReal: (b) => /_authToken|registry=/.test(b) && !/<html/i.test(b) },
  { path: '/docker-compose.yml', severity: 'medium', label: 'docker-compose.yml', looksReal: (b) => /^services:/m.test(b) },
  { path: '/.DS_Store', severity: 'low', label: '.DS_Store', looksReal: (b) => b.startsWith('\x00\x00\x00\x01Bud1') || /Bud1/.test(b.slice(0, 8)) },
  { path: '/backup.sql', severity: 'high', label: 'backup.sql', looksReal: (b) => /(CREATE TABLE|INSERT INTO)/i.test(b) },
  // Framework debug/admin surfaces that ship on by accident. Each body-validates so a generic 200/SPA
  // index doesn't false-positive.
  { path: '/actuator/health', severity: 'high', label: 'Spring Boot actuator', looksReal: (b, ct) => ct.includes('json') && /"status"\s*:\s*"(?:UP|DOWN|OUT_OF_SERVICE)"/i.test(b) },
  { path: '/server-status', severity: 'medium', label: 'Apache server-status', looksReal: (b) => /Apache Server Status/i.test(b) },
  { path: '/debug/vars', severity: 'high', label: 'Go expvar debug endpoint', looksReal: (b, ct) => ct.includes('json') && /"cmdline"|"memstats"/.test(b) },
  { path: '/metrics', severity: 'medium', label: 'Prometheus metrics', looksReal: (b, ct) => /^#\s*(HELP|TYPE)\s/m.test(b) && !/<html/i.test(b) && (ct.includes('text') || ct === '') },
  { path: '/swagger.json', severity: 'medium', label: 'Swagger/OpenAPI spec', looksReal: (b, ct) => ct.includes('json') && /"(?:swagger|openapi)"\s*:/.test(b) },
  { path: '/api-docs', severity: 'medium', label: 'Swagger/OpenAPI docs', looksReal: (b) => /swagger-ui|"(?:swagger|openapi)"\s*:/i.test(b) },
  { path: '/.aws/credentials', severity: 'high', label: 'AWS credentials file', looksReal: (b) => /aws_access_key_id/i.test(b) && !/<html/i.test(b) },
  { path: '/config.json', severity: 'medium', label: 'config.json', looksReal: (b, ct) => ct.includes('json') && /"(?:apiKey|secret|password|token|database|db)"/i.test(b) },
  // Backup / temp / archive files left in the webroot (ASVS V12.5.1). Validated by content-type / magic
  // bytes / source markers so an SPA/404 fallback doesn't false-positive.
  { path: '/.env.bak', severity: 'high', label: '.env backup', looksReal: (b) => /^[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(b) && !/<html/i.test(b) },
  { path: '/backup.zip', severity: 'high', label: 'backup.zip', looksReal: (b, ct) => ct.includes('zip') || b.startsWith('PK\x03\x04') },
  { path: '/backup.tar.gz', severity: 'high', label: 'backup.tar.gz', looksReal: (b, ct) => ct.includes('gzip') || ct.includes('tar') || b.startsWith('\x1f\x8b') },
  { path: '/backup.sql.gz', severity: 'high', label: 'backup.sql.gz', looksReal: (b, ct) => ct.includes('gzip') || b.startsWith('\x1f\x8b') },
  { path: '/.git.zip', severity: 'high', label: '.git archive', looksReal: (b, ct) => ct.includes('zip') || b.startsWith('PK\x03\x04') },
  { path: '/config.php.bak', severity: 'high', label: 'config.php backup', looksReal: (b) => /<\?php/.test(b) },
  { path: '/index.php.bak', severity: 'medium', label: 'index.php backup', looksReal: (b) => /<\?php/.test(b) },
  { path: '/web.config.bak', severity: 'high', label: 'web.config backup', looksReal: (b) => /<configuration|<connectionStrings/i.test(b) },
];

// Directories that are commonly mis-served with autoindex on, leaking internal file structure.
const LISTABLE_DIRS = ['/uploads/', '/files/', '/backup/', '/backups/', '/.git/', '/static/', '/assets/', '/data/'];
// A real Apache/nginx/generic autoindex page — NOT an SPA index (which has a root mount div + script bundle).
function looksLikeDirListing(body: string): boolean {
  if (/<div[^>]*\bid=["'](?:root|app|__next)["']/i.test(body)) return false;
  return /<title>Index of \//i.test(body)
    || /Directory listing for \//i.test(body)
    || (/<a[^>]+href=["'][^"']*\/["']/i.test(body) && /Parent Directory|<pre>/i.test(body));
}

export async function exposureChecks(ctx: ScanContext): Promise<Finding[]> {
  const out: Finding[] = [];
  let any = false;
  for (const p of EXPOSED_PATHS) {
    const res = await safeFetch(ctx.origin + p.path, { redirect: 'follow', headers: ctx.opts.extraHeaders });
    if (!res || !res.ok) continue;
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    const body = (await res.text()).slice(0, 4000);
    if (p.looksReal(body, ct)) {
      any = true;
      out.push(f('exposure', `exposed${p.path}`, `${p.label} is publicly reachable`, p.severity, false, `GET ${p.path} -> 200 and the body looks like a real ${p.label}`, `Block ${p.path} at the host/router — config and dotfiles must never be web-served.`));
    }
  }

  // Directory listing (autoindex) on common dirs — leaks internal structure / stray files.
  for (const dir of LISTABLE_DIRS) {
    const res = await safeFetch(ctx.origin + dir, { redirect: 'follow', headers: ctx.opts.extraHeaders });
    if (!res || !res.ok) continue;
    const body = (await res.text()).slice(0, 6000);
    if (looksLikeDirListing(body)) {
      any = true;
      out.push(f('exposure', `dir-listing${dir}`, `Directory listing enabled at ${dir}`, 'medium', false, `GET ${dir} returns an auto-generated index of files`, `Turn off directory autoindex for ${dir} (nginx: autoindex off; Apache: Options -Indexes) so your file structure isn't browsable.`));
    }
  }

  // robots.txt that Disallows sensitive-looking paths advertises exactly where the interesting stuff is.
  const robots = await safeFetch(ctx.origin + '/robots.txt', { redirect: 'follow', headers: ctx.opts.extraHeaders });
  if (robots && robots.ok) {
    const body = (await robots.text()).slice(0, 8000);
    const sensitive = [...body.matchAll(/^\s*Disallow:\s*(\S+)/gim)]
      .map((m) => m[1])
      .filter((p) => /admin|internal|private|secret|backup|config|\.git|staging|test|debug|api\/|dashboard|wp-admin/i.test(p));
    if (sensitive.length) {
      out.push(f('exposure', 'robots.sensitive', 'robots.txt discloses sensitive paths', 'low', false, `Disallow entries point at ${sensitive.slice(0, 5).join(', ')}`, 'Don\'t list secret paths in robots.txt — it\'s public and tells attackers where to look. Protect those paths with auth instead.'));
      any = true;
    }
  }

  // Debug/introspection endpoints that echo server secrets (service-role keys, tokens, password hashes).
  // Safe GETs; body-validated so an SPA/HTML fallback or a normal JSON response doesn't false-positive.
  // Require a real JSON key→value (or a full key/hash), so docs that merely mention "password_hash" or a
  // schema field name don't false-positive; only actual leaked VALUES trigger it.
  const SECRET_IN_BODY = /"(?:service_role|SUPABASE_SERVICE_ROLE_KEY|CRON_SECRET|STRIPE_SECRET(?:_KEY)?|password_hash|encrypted_password|access_token|refresh_token|client_secret)"\s*:\s*"?[^"\s,}]{6,}|\$2[aby]\$[./A-Za-z0-9]{20,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\brole"\s*:\s*"service_role"/i;
  for (const dbg of ['/api/auth/debug', '/api/debug', '/api/_debug', '/api/auth/check', '/api/config', '/api/env']) {
    const res = await safeFetch(ctx.origin + dbg, { redirect: 'follow', headers: ctx.opts.extraHeaders });
    if (!res || !res.ok) continue;
    const body = (await res.text()).slice(0, 8000);
    if (/<html/i.test(body)) continue; // SPA catch-all, not a real debug endpoint
    if (SECRET_IN_BODY.test(body)) {
      any = true;
      out.push(f('exposure', `debug-leak${dbg}`, 'Debug endpoint leaks secrets/credentials', 'high', false, `${dbg} returns a body containing service-role keys, tokens, or password hashes`, 'Remove or lock down debug/introspection endpoints — never return service-role keys, session tokens, or password hashes to a client.'));
      break;
    }
  }

  // Verbose error / stack-trace leak on an unknown path.
  const probe404 = await safeFetch(ctx.origin + '/__vibetesting_agent_does_not_exist__', { redirect: 'follow', headers: ctx.opts.extraHeaders });
  if (probe404) {
    const body = (await probe404.text()).slice(0, 8000);
    const leak = /\bat\s+[\w$.]+\s+\(.*:\d+:\d+\)|Traceback \(most recent call last\)|node_modules\/|\/var\/task\/|ECONNREFUSED|Sequelize\w+Error|PG::|psql:/.test(body);
    if (leak) {
      any = true;
      out.push(f('exposure', 'error.stacktrace', 'Error pages leak stack traces / internal paths', 'medium', false, 'an unknown URL returned a server stack trace or internal file paths', 'Return a generic error page in production; never echo stack traces or file paths to users.'));
    }
  }

  // GraphQL introspection enabled (leaks the whole API schema). Sent as a GET introspection query so the
  // scan stays purely GET (the query is read-only; GET introspection is supported by most GraphQL servers).
  const gqlQuery = '?query=' + encodeURIComponent('{__schema{queryType{name}}}');
  for (const gqlPath of ['/graphql', '/api/graphql']) {
    const res = await safeFetch(ctx.origin + gqlPath + gqlQuery, { redirect: 'follow', headers: { accept: 'application/json', ...ctx.opts.extraHeaders } });
    if (res && res.ok) {
      const body = await res.text();
      if (/"__schema"|"queryType"/.test(body)) {
        any = true;
        out.push(f('exposure', `graphql.introspection${gqlPath}`, 'GraphQL introspection is enabled', 'medium', false, `${gqlPath} answers __schema queries`, 'Disable introspection in production so attackers can\'t map your entire API.'));
        break;
      }
    }
  }

  // API-surface exposure (#24): unauthenticated data probe (on) + unauthenticated write probe (opt-in).
  const apiFindings = await apiExposureFindings(ctx);
  out.push(...apiFindings);
  if (apiFindings.some((fnd) => !fnd.pass)) any = true;

  if (!any) out.push(f('exposure', 'exposure.none', 'No exposed config/debug surfaces found', 'info', true, 'checked dotfiles, configs, error pages, GraphQL introspection, unauthenticated API routes'));
  return out;
}

// ───────────────────────────── reliability (broken links/images, mixed content) ──────────────────

export async function reliabilityChecks(ctx: ScanContext): Promise<Finding[]> {
  const out: Finding[] = [];
  if (!ctx.res) return out;

  // Main document status / content-type sanity.
  const ct = (ctx.headers.get('content-type') || '').toLowerCase();
  out.push(f('reliability', 'home.status', `Homepage returns ${ctx.res.status}`, ctx.res.status < 400 ? 'info' : 'high', ctx.res.status < 400, `${ctx.res.status} ${ct}`));

  // Mixed content: http:// resources on an https page.
  if (ctx.url.protocol === 'https:') {
    const insecure = [...new Set(H.insecureRefs(ctx.html))];
    if (insecure.length) {
      out.push(f('reliability', 'mixed-content', 'Page loads resources over http:// (mixed content)', 'medium', false, `${insecure.length} insecure ref(s), e.g. ${insecure[0]}`, 'Load every script/image/style over https:// or browsers will block them.'));
    }
  }

  // Broken same-origin links + images (sampled).
  const cap = ctx.opts.maxCrawl ?? 25;
  const targets = [...new Set([
    ...H.links(ctx.html).map((u) => resolveUrl(ctx.baseUrl, u)),
    ...H.images(ctx.html).map((i) => resolveUrl(ctx.baseUrl, i.src)),
  ].filter((u): u is string => !!u && sameOrigin(u, ctx.baseUrl)))].slice(0, cap);

  const broken: string[] = [];
  for (const t of targets) {
    let res = await safeFetch(t, { method: 'HEAD', redirect: 'follow', headers: ctx.opts.extraHeaders });
    if (res && (res.status === 405 || res.status === 501)) res = await safeFetch(t, { method: 'GET', redirect: 'follow', headers: ctx.opts.extraHeaders });
    if (res && res.status >= 400) broken.push(`${res.status} ${t.replace(ctx.origin, '')}`);
  }
  if (broken.length) {
    out.push(f('reliability', 'broken-links', `${broken.length} broken link(s)/image(s)`, 'medium', false, broken.slice(0, 8).join(', '), 'Fix or remove dead links and missing images — they break navigation and look unfinished.'));
  } else if (targets.length) {
    out.push(f('reliability', 'broken-links', 'No broken same-origin links/images', 'info', true, `checked ${targets.length} URL(s)`));
  }

  return out;
}

// ───────────────────────────── seo ───────────────────────────────────────────────────────────────

export async function seoChecks(ctx: ScanContext): Promise<Finding[]> {
  const out: Finding[] = [];
  if (!ctx.res) return out;
  const h = ctx.html;

  const title = H.title(h);
  out.push(f('seo', 'seo.title', title ? 'Has a <title>' : 'Missing <title>', title ? 'info' : 'medium', !!title && title.length >= 3, title ? `"${title.slice(0, 70)}" (${title.length} chars)` : 'no <title> tag', 'Add a descriptive <title> — it\'s the headline in Google results and browser tabs.'));

  const desc = H.metaContent(h, 'description');
  out.push(f('seo', 'seo.description', desc ? 'Has a meta description' : 'Missing meta description', desc ? 'info' : 'low', !!desc, desc ? `${desc.length} chars` : 'no <meta name="description">', 'Add <meta name="description"> — Google shows it as the snippet under your title.'));

  const og = H.metaContent(h, 'og:title') || H.metaContent(h, 'og:image');
  out.push(f('seo', 'seo.opengraph', og ? 'Has Open Graph tags' : 'Missing Open Graph tags', og ? 'info' : 'low', !!og, og ? 'og:* present' : 'no og:title/og:image', 'Add Open Graph tags so links unfurl with a title + image when shared on social/chat.'));

  out.push(f('seo', 'seo.canonical', H.canonical(h) ? 'Has a canonical URL' : 'No canonical URL', 'low', !!H.canonical(h), H.canonical(h) || 'no <link rel="canonical">', 'Add <link rel="canonical"> to avoid duplicate-content penalties.'));

  const h1 = H.h1Count(h);
  out.push(f('seo', 'seo.h1', h1 === 1 ? 'Exactly one <h1>' : `${h1} <h1> tags`, h1 === 1 ? 'info' : 'low', h1 === 1, `${h1} <h1>`, 'Use exactly one <h1> per page describing what the page is about.'));

  for (const [name, path] of [['robots.txt', '/robots.txt'], ['sitemap.xml', '/sitemap.xml']] as const) {
    const res = await safeFetch(ctx.origin + path, { redirect: 'follow' });
    const ok = !!res && res.ok;
    out.push(f('seo', `seo.${name}`, ok ? `${name} present` : `No ${name}`, 'low', ok, ok ? `200 at ${path}` : `missing ${path}`, `Add ${path} so search engines can crawl/index your site correctly.`));
  }

  return out;
}

// ───────────────────────────── a11y ──────────────────────────────────────────────────────────────

export async function a11yChecks(ctx: ScanContext): Promise<Finding[]> {
  const out: Finding[] = [];
  if (!ctx.res) return out;
  const h = ctx.html;

  out.push(f('a11y', 'a11y.lang', H.hasLang(h) ? '<html lang> set' : 'Missing <html lang>', H.hasLang(h) ? 'info' : 'medium', H.hasLang(h), H.hasLang(h) ? 'lang attribute present' : 'no lang on <html>', 'Add lang="en" (or your language) to <html> so screen readers pronounce content correctly.'));

  out.push(f('a11y', 'a11y.viewport', H.hasViewport(h) ? 'Has viewport meta' : 'Missing viewport meta', H.hasViewport(h) ? 'info' : 'medium', H.hasViewport(h), H.hasViewport(h) ? 'viewport set' : 'no <meta name="viewport">', 'Add <meta name="viewport" content="width=device-width, initial-scale=1"> or the site breaks on mobile.'));

  const imgs = H.images(h);
  const noAlt = imgs.filter((i) => !i.hasAlt).length;
  if (imgs.length) {
    out.push(f('a11y', 'a11y.alt', noAlt ? `${noAlt}/${imgs.length} images missing alt` : 'All images have alt text', noAlt ? 'low' : 'info', noAlt === 0, `${noAlt} of ${imgs.length} <img> lack alt`, 'Give every <img> an alt="" describing it (empty alt for decorative images) for screen readers + SEO.'));
  }

  const inputs = H.inputsNeedingLabel(h);
  const labels = H.labelCount(h);
  if (inputs > 0) {
    const ok = labels >= inputs;
    out.push(f('a11y', 'a11y.labels', ok ? 'Form inputs appear labelled' : 'Form inputs may lack labels', ok ? 'info' : 'low', ok, `${inputs} labelable input(s), ${labels} <label>(s)`, 'Pair every form input with a <label> so it\'s usable with a screen reader.'));
  }

  return out;
}

// ───────────────────────────── performance ───────────────────────────────────────────────────────

export async function performanceChecks(ctx: ScanContext): Promise<Finding[]> {
  const out: Finding[] = [];
  if (!ctx.res) return out;

  // Compression on the HTML document.
  const probe = await safeFetch(ctx.origin, { redirect: 'follow', headers: { 'accept-encoding': 'br, gzip' } });
  const enc = probe?.headers.get('content-encoding') || '';
  out.push(f('performance', 'perf.compression', enc ? `Compression: ${enc}` : 'No compression detected', enc ? 'info' : 'low', !!enc, enc ? `content-encoding: ${enc}` : 'document served uncompressed', 'Enable gzip/brotli compression — it shrinks pages ~70% and most hosts toggle it on.'));

  // Page weight (HTML only — a proxy; huge HTML usually means an un-split bundle dumped inline).
  const bytes = Buffer.byteLength(ctx.html, 'utf8');
  out.push(f('performance', 'perf.html-weight', bytes > 1_000_000 ? 'Very large HTML document' : 'HTML size OK', bytes > 1_000_000 ? 'low' : 'info', bytes <= 1_000_000, `${(bytes / 1024).toFixed(0)} KB of HTML`, 'Trim inline content / code-split — a 1MB+ HTML doc is slow on mobile.'));

  // Script count.
  const scripts = H.scripts(ctx.html).length;
  out.push(f('performance', 'perf.scripts', scripts > 30 ? `${scripts} script files` : 'Reasonable script count', scripts > 30 ? 'low' : 'info', scripts <= 30, `${scripts} <script src>`, 'Bundle/code-split your JS — dozens of separate script requests slow first load.'));

  // Cache headers on the first static asset.
  const firstScript = H.scripts(ctx.html).map((s) => resolveUrl(ctx.baseUrl, s)).find((u): u is string => !!u && sameOrigin(u, ctx.baseUrl));
  if (firstScript) {
    const a = await safeFetch(firstScript, { redirect: 'follow' });
    const cc = a?.headers.get('cache-control') || '';
    const cached = /max-age=\d{4,}|immutable/.test(cc);
    out.push(f('performance', 'perf.caching', cached ? 'Static assets are cacheable' : 'Static assets lack long cache headers', cached ? 'info' : 'low', cached, cc ? `cache-control: ${cc}` : 'no long-lived cache-control on JS', 'Serve hashed assets with Cache-Control: max-age=31536000, immutable so repeat visits are instant.'));
  }

  return out;
}

// src/api.ts
// Issue #24 — API-surface checks that a homepage-only scan misses. Real audits keep turning up API
// routes that answer data (or accept writes) with no auth challenge, expensive endpoints with no rate
// limit, and public inputs that reflect unencoded. These are all reachable black-box from a URL, so
// they belong in the scanner — but the louder ones (writes, bursts, reflected-XSS payloads) are opt-in
// so the default scan stays polite and non-destructive (white-hat posture: identify, never damage).
//
//   apiExposureFindings  → exposure: api.unauth-data (default on, GET-only) · api.unauth-write (opt-in)
//   apiSecurityFindings  → security: api.cors (default on) · api.rate-limit (opt-in) · xss.reflected (opt-in)

import type { Finding, ScanContext, Severity } from './types.js';
import { safeFetch, resolveUrl, sameOrigin, html as H } from './core.js';

const f = (
  category: Finding['category'], id: string, title: string, severity: Severity,
  pass: boolean, detail: string, fix?: string,
): Finding => ({ category, id, title, severity, pass, detail, fix });

// Common API routes worth an unauthenticated GET. Body-validated before flagging (JSON data only) so an
// SPA's index.html catch-all never false-positives.
const API_WORDLIST = [
  '/api/config', '/api/users', '/api/user', '/api/me', '/api/admin', '/api/export',
  '/api/settings', '/api/internal', '/api/status', '/api/accounts', '/api/orders',
  '/api/customers', '/api/data', '/api/list', '/api/profile', '/api/session',
  '/api/homepage/config', '/api/jobs/alerts/public', '/api/v1/users',
];

// Write-suggestive routes for the OPT-IN unauthenticated-write probe. Only benign no-op bodies are sent,
// and destructive-sounding verbs are never touched.
const WRITE_WORDLIST = ['/api/sync', '/api/subscribe', '/api/claim', '/api/create', '/api/import', '/api/contact'];
const DESTRUCTIVE = /(delete|remove|drop|destroy|reset|purge|wipe|truncate|revoke)/i;

// Names that signal a compute/LLM-heavy endpoint where missing rate limiting is a budget-DoS (higher sev).
const EXPENSIVE = /(ai|checklist|search|generate|chat|complet|llm|embed|report|summar|render|pdf)/i;

const ASSET_EXT = /\.(?:js|mjs|css|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot)(?:$|\?)/i;

/** Pull same-origin /api/* (and /rest//v1/) paths referenced anywhere in the homepage HTML. */
export function discoverApiRoutes(ctx: ScanContext): string[] {
  const found = new Set<string>();
  for (const m of ctx.html.matchAll(/["'`(]((?:https?:\/\/[^"'`)\s]+)?\/(?:api|rest)\/[A-Za-z0-9._/-]+)/g)) {
    const abs = resolveUrl(ctx.baseUrl, m[1]);
    if (!abs || !sameOrigin(abs, ctx.baseUrl)) continue;
    const path = new URL(abs).pathname.replace(/[),.;'"]+$/, '');
    if (ASSET_EXT.test(path)) continue;
    if (path.length > 1) found.add(path);
  }
  return [...found].slice(0, 20);
}

/** Does this response challenge for auth (so answering is correct, not a leak)? */
function authChallenged(res: Response): boolean {
  return res.status === 401 || res.status === 403 || res.headers.has('www-authenticate');
}

/** Classify a GET response: is it a non-trivial JSON DATA body (not an error/empty/HTML shell)? */
function classifyData(ct: string, body: string): { data: boolean; sensitive: boolean } {
  const looksJson = ct.includes('json') || /^\s*[[{]/.test(body);
  if (!looksJson) return { data: false, sensitive: false };
  let parsed: unknown;
  try { parsed = JSON.parse(body); } catch { return { data: false, sensitive: false }; }
  const sensitiveRe = /"(?:email|password|passwd|token|secret|api[_-]?key|apikey|ssn|phone|address|user_?id|customer|credit|card|first_?name|last_?name|role|balance|salary)"\s*:/i;
  if (Array.isArray(parsed)) {
    if (parsed.length === 0) return { data: false, sensitive: false };
    const recordy = typeof parsed[0] === 'object' && parsed[0] !== null;
    return { data: true, sensitive: recordy || sensitiveRe.test(body) };
  }
  if (parsed && typeof parsed === 'object') {
    const keys = Object.keys(parsed as Record<string, unknown>);
    if (keys.length === 0) return { data: false, sensitive: false };
    // An error/status envelope isn't a data leak.
    if ('error' in (parsed as any)) return { data: false, sensitive: false };
    const envelope = new Set(['message', 'code', 'status', 'ok', 'success', 'detail']);
    if (keys.every((k) => envelope.has(k.toLowerCase()))) return { data: false, sensitive: false };
    return { data: true, sensitive: sensitiveRe.test(body) };
  }
  return { data: false, sensitive: false };
}

/**
 * exposure category: unauthenticated API-route probe.
 * - GET every candidate route WITHOUT auth headers → flag 200 + JSON data + no auth challenge.
 * - (opt-in `apiWrite`) POST a benign body to write-suggestive routes → flag any 2xx.
 * All GET-only by default; writes require the flag and skip destructive verbs.
 */
export async function apiExposureFindings(ctx: ScanContext): Promise<Finding[]> {
  const out: Finding[] = [];
  const candidates = [...new Set([...API_WORDLIST, ...discoverApiRoutes(ctx)])].slice(0, 30);

  for (const path of candidates) {
    // Deliberately unauthenticated: no extraHeaders — we're testing the anonymous case even mid-auth-scan.
    const res = await safeFetch(ctx.origin + path, { redirect: 'manual' }, ctx.opts.timeoutMs);
    if (!res || res.status !== 200 || authChallenged(res)) continue;
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    const body = (await res.text().catch(() => '')).slice(0, 8000);
    if (/<html/i.test(body)) continue; // SPA catch-all
    const { data, sensitive } = classifyData(ct, body);
    if (!data) continue;
    out.push(f('exposure', `api.unauth-data${path}`,
      `API route ${path} returns data without authentication`,
      sensitive ? 'high' : 'medium', false,
      `GET ${path} → 200 ${ct || '(no content-type)'} with a JSON ${sensitive ? 'record/PII-shaped ' : ''}body and no auth challenge`,
      'Require authentication/authorization on API routes that return data — an anonymous GET should get 401/403, not a JSON payload.'));
  }

  // OPT-IN: unauthenticated write probe (benign no-op POST). Off unless --api-write.
  if (ctx.opts.apiWrite) {
    const writeRoutes = [...new Set([
      ...WRITE_WORDLIST,
      ...discoverApiRoutes(ctx).filter((p) => /(sync|subscribe|claim|create|import|contact|update|save)/i.test(p)),
    ])].filter((p) => !DESTRUCTIVE.test(p)).slice(0, 12);
    for (const path of writeRoutes) {
      const res = await safeFetch(ctx.origin + path, {
        method: 'POST', redirect: 'manual',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ vibetesting_agent: 'noop-probe' }),
      }, ctx.opts.timeoutMs);
      if (!res) continue;
      // 401/403 = auth-gated (good); 404/405 = not there / method not allowed (good). A 2xx = accepted.
      if (res.status < 200 || res.status >= 300) continue;
      // An SPA that returns its index.html (200) for every POST hasn't accepted a write — skip the shell.
      const ct = (res.headers.get('content-type') || '').toLowerCase();
      const body = (await res.text().catch(() => '')).slice(0, 2000);
      if (ct.includes('html') || /<html/i.test(body)) continue;
      out.push(f('exposure', `api.unauth-write${path}`,
        `API route ${path} accepts an unauthenticated write`,
        'high', false,
        `POST ${path} (benign body) → ${res.status} ${ct || '(no content-type)'} with no auth challenge`,
        'Require auth on state-changing endpoints — an anonymous POST should be rejected with 401/403.'));
    }
  }

  return out;
}

/**
 * security category: API-response nuances.
 * - api.cors    (default on): a discovered route reflects an arbitrary Origin with credentials.
 * - api.rate-limit (opt-in `rateLimitScan`): burst expensive routes; expect a 429.
 * - xss.reflected  (opt-in `reflectedXss`): a benign marker on a public query param reflects unencoded.
 */
export async function apiSecurityFindings(ctx: ScanContext): Promise<Finding[]> {
  const out: Finding[] = [];
  const routes = [...new Set([...discoverApiRoutes(ctx), '/api/config', '/api/me', '/api/users'])].slice(0, 15);

  // Dangerous CORS reflection on discovered/likely API routes (one extra GET each, benign header).
  const EVIL = 'https://evil.example';
  for (const path of routes) {
    const res = await safeFetch(ctx.origin + path, { headers: { Origin: EVIL }, redirect: 'manual' }, ctx.opts.timeoutMs);
    if (!res) continue;
    const acao = res.headers.get('access-control-allow-origin') || '';
    const acac = (res.headers.get('access-control-allow-credentials') || '').toLowerCase() === 'true';
    if (acao === EVIL && acac) {
      out.push(f('security', `api.cors${path}`, `CORS reflects any origin with credentials on ${path}`,
        'high', false,
        `${path} echoes Origin: ${EVIL} in Access-Control-Allow-Origin while allowing credentials — any site can read authenticated responses`,
        'Never reflect an arbitrary Origin together with Access-Control-Allow-Credentials: true. Allow-list specific trusted origins instead.'));
    }
  }

  // OPT-IN autonomous rate-limit detection on expensive endpoints.
  if (ctx.opts.rateLimitScan) {
    const expensive = [...new Set([...discoverApiRoutes(ctx), ...API_WORDLIST])]
      .filter((p) => EXPENSIVE.test(p)).slice(0, 3);
    for (const path of expensive) {
      // Pre-check: only burst something that behaves like a real API. An app that returns its SPA
      // index.html (or a 404) for every unknown path isn't an endpoint — bursting it would false-positive.
      const pre = await safeFetch(ctx.origin + path, { redirect: 'manual' }, ctx.opts.timeoutMs);
      if (!pre || pre.status >= 400) continue;
      if ((pre.headers.get('content-type') || '').toLowerCase().includes('html')) continue;
      const burst = await Promise.all(Array.from({ length: 15 }, () => safeFetch(ctx.origin + path, { redirect: 'manual' }, ctx.opts.timeoutMs, { retries: 0 })));
      const reachable = burst.filter((r) => r && r.status < 400).length;
      if (reachable < 8) continue; // not consistently reachable — don't guess
      const throttled = burst.some((r) => r && (r.status === 429 || r.headers.has('retry-after')));
      if (!throttled) {
        const heavy = EXPENSIVE.test(path);
        out.push(f('security', `api.rate-limit${path}`, `No rate limiting on ${path}`,
          heavy ? 'high' : 'medium', false,
          `15 rapid unauthenticated requests to ${path} were not throttled (no 429 / Retry-After)`,
          'Add rate limiting on public/compute-heavy endpoints so they can\'t be hammered (budget-DoS on LLM/AI routes especially).'));
      }
    }
  }

  // OPT-IN reflected-XSS / HTML-injection probe on PUBLIC inputs only (non-executing marker).
  if (ctx.opts.reflectedXss) {
    out.push(...await reflectedXssFindings(ctx));
  }

  return out;
}

/** Inert, structurally-detectable marker: a harmless custom element. If it reflects unencoded, HTML
 *  injection (and thus reflected XSS) is possible — without ever sending an executing payload. */
const XSS_MARKER = 'vta7probe"><x-vta-xss>';
const XSS_TAG = '<x-vta-xss>';
const COMMON_PARAMS = ['q', 's', 'search', 'query', 'term', 'name', 'message', 'redirect_note'];

export async function reflectedXssFindings(ctx: ScanContext): Promise<Finding[]> {
  const out: Finding[] = [];
  const flagged = new Set<string>();

  // Targets: common params on the homepage + any existing query params on same-origin links.
  const targets: { url: string; param: string }[] = [];
  for (const p of COMMON_PARAMS) targets.push({ url: ctx.origin + '/', param: p });
  for (const href of H.links(ctx.html)) {
    const abs = resolveUrl(ctx.baseUrl, href);
    if (!abs || !sameOrigin(abs, ctx.baseUrl)) continue;
    let u: URL;
    try { u = new URL(abs); } catch { continue; }
    for (const key of u.searchParams.keys()) {
      targets.push({ url: u.origin + u.pathname, param: key });
      if (targets.length > 16) break;
    }
    if (targets.length > 16) break;
  }

  for (const { url, param } of targets.slice(0, 16)) {
    if (flagged.has(param)) continue;
    const probe = new URL(url);
    probe.searchParams.set(param, XSS_MARKER);
    const res = await safeFetch(probe.toString(), { redirect: 'manual' }, ctx.opts.timeoutMs);
    if (!res || !res.ok) continue;
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    if (!ct.includes('html')) continue;
    const body = (await res.text().catch(() => '')).slice(0, 200_000);
    if (body.includes(XSS_TAG)) {
      flagged.add(param);
      out.push(f('security', `xss.reflected.${param}`, `Reflected input not HTML-encoded on ?${param}`,
        'high', false,
        `?${param}= is reflected into the HTML response with < > unencoded (an injected tag survives) — reflected XSS is possible`,
        'HTML-encode all user input before reflecting it into a page (or use a framework escaping layer). Never write raw request values into HTML.'));
    }
  }

  return out;
}

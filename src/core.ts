// src/core.ts
// Zero-dependency HTTP + HTML + secret-scanning helpers. Kept regex-based on purpose: the whole kit
// must run via `npx` with no install and no headless browser, so a vibe coder can point it at a
// deploy in one command. Regex HTML parsing is "good enough" for black-box posture checks.

import tls from 'node:tls';
import { AsyncLocalStorage } from 'node:async_hooks';
import {
  DEFAULT_RETRIES,
  decideRetry,
  withRetries,
  type TransientKind,
} from './retry.js';

export interface TlsInfo {
  /** Days until the served certificate expires (null if undeterminable). */
  daysRemaining: number | null;
  /** Negotiated protocol, e.g. "TLSv1.3" / "TLSv1.2" / "TLSv1" (null if undeterminable). */
  protocol: string | null;
  /** Negotiated cipher suite name (null if undeterminable). */
  cipher: string | null;
}

/**
 * Probe the served TLS: cert expiry + negotiated protocol + cipher. Uses a raw TLS connection because
 * fetch() exposes none of this. Fails soft to nulls.
 */
export function tlsProbe(host: string, port = 443): Promise<TlsInfo> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v: TlsInfo) => { if (!done) { done = true; resolve(v); } };
    try {
      const socket = tls.connect({ host, port, servername: host, timeout: 8000 }, () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher()?.name ?? null;
        socket.end();
        const daysRemaining = cert && cert.valid_to
          ? Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000)
          : null;
        finish({ daysRemaining, protocol, cipher });
      });
      socket.on('error', () => finish({ daysRemaining: null, protocol: null, cipher: null }));
      socket.on('timeout', () => { socket.destroy(); finish({ daysRemaining: null, protocol: null, cipher: null }); });
    } catch {
      finish({ daysRemaining: null, protocol: null, cipher: null });
    }
  });
}

/** Back-compat wrapper — days until the served cert expires. */
export async function tlsCertDaysRemaining(host: string, port = 443): Promise<number | null> {
  return (await tlsProbe(host, port)).daysRemaining;
}

/** Grade a negotiated TLS protocol. Pure/testable. */
export function gradeTlsProtocol(protocol: string | null): { ok: boolean; severity: 'high' | 'medium' | 'low' | 'info'; detail: string } {
  if (!protocol) return { ok: true, severity: 'info', detail: 'protocol not determinable' };
  const deprecated: Record<string, 'high' | 'medium'> = { TLSv1: 'high', 'TLSv1.1': 'high', SSLv3: 'high', SSLv2: 'high' };
  if (protocol in deprecated) return { ok: false, severity: deprecated[protocol], detail: `${protocol} is deprecated and known-insecure` };
  if (protocol === 'TLSv1.2') return { ok: true, severity: 'low', detail: 'TLSv1.2 (fine; TLSv1.3 preferred)' };
  return { ok: true, severity: 'info', detail: protocol };
}

/** Flag known-weak cipher suites. Pure/testable. */
export function gradeTlsCipher(cipher: string | null): { ok: boolean; detail: string } {
  if (!cipher) return { ok: true, detail: 'cipher not determinable' };
  // Explicitly-broken primitives, OR CBC-mode suites (named "…-SHA"/"…CBC…" without an AEAD marker).
  const explicit = /RC4|3DES|(^|[-_])DES([-_]|$)|MD5|NULL|EXPORT|ANON/i.test(cipher);
  const cbcMode = (/CBC/i.test(cipher) || /-SHA\d*$/i.test(cipher)) && !/GCM|CCM|CHACHA|POLY1305/i.test(cipher);
  const weak = explicit || cbcMode;
  return { ok: !weak, detail: weak ? `${cipher} is a weak/legacy cipher` : cipher };
}

// Every network call gets a hard deadline so a dead/slow/hostile site can't hang the scan forever.
export const DEFAULT_TIMEOUT_MS = 10_000;

/** Per-scan retry budget. `probe()` installs this so every safeFetch honours `--retries`. */
const retryBudget = new AsyncLocalStorage<number>();

export function runWithRetryBudget<T>(retries: number, fn: () => Promise<T>): Promise<T> {
  return retryBudget.run(Math.max(0, Math.floor(retries)), fn);
}

export function currentRetryBudget(): number {
  const stored = retryBudget.getStore();
  return stored === undefined ? DEFAULT_RETRIES : stored;
}

export interface FetchRetryMeta {
  retries: number;
  exhausted: boolean;
  lastKind?: TransientKind;
}

export interface FetchResult {
  response: Response | null;
  retries: number;
  exhausted: boolean;
  lastKind?: TransientKind;
  error?: unknown;
}

export interface SafeFetchOptions {
  /** Override the scan retry budget. `0` disables retries (rate-limit bursts, attack probes). */
  retries?: number;
}

/** fetch() with an AbortController timeout. Merges any caller-supplied signal-less init. */
async function fetchWithTimeout(url: string, init: RequestInit | undefined, timeoutMs: number): Promise<Response> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    // signal LAST so a caller-supplied init can't clobber the timeout.
    return await fetch(url, { ...init, signal: ac.signal });
  } finally {
    clearTimeout(timer);
  }
}

function retryCount(opts?: SafeFetchOptions): number {
  return opts?.retries !== undefined ? Math.max(0, Math.floor(opts.retries)) : currentRetryBudget();
}

/**
 * Fetch with bounded backoff on network reset / timeout / DNS / 429/502/503/504.
 * Honour Retry-After within the cap. Never retries other 4xx or a successful response.
 */
export async function fetchWithRetry(
  url: string,
  init: RequestInit | undefined,
  timeoutMs: number,
  retries: number,
): Promise<FetchResult> {
  const result = await withRetries(
    async () => fetchWithTimeout(url, init, timeoutMs),
    {
      retries,
      isRetryable: (res) =>
        decideRetry({
          status: res.status,
          retryAfter: res.headers.get('retry-after'),
        }),
    },
  );
  return {
    response: result.value ?? null,
    retries: result.retries,
    exhausted: result.exhausted,
    lastKind: result.lastKind,
    error: result.error,
  };
}

export async function safeFetch(
  url: string,
  init?: RequestInit,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  retryOpts?: SafeFetchOptions,
): Promise<Response | null> {
  const result = await fetchWithRetry(url, { redirect: 'manual', ...init }, timeoutMs, retryCount(retryOpts));
  return result.response;
}

/**
 * Fetch text with a hard timeout AND a streaming byte cap: we stop reading once maxBytes have arrived,
 * so a gzip bomb / endless stream can't OOM the process (arrayBuffer() would buffer the whole body first).
 * Returns '' on any failure. Binary responses are decoded lossily — callers only regex over them.
 */
export async function fetchText(
  url: string,
  init?: RequestInit,
  maxBytes = 3_000_000,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  retryOpts?: SafeFetchOptions,
): Promise<string> {
  try {
    const attempt = await fetchWithRetry(url, { redirect: 'follow', ...init }, timeoutMs, retryCount(retryOpts));
    const res = attempt.response;
    if (!res || !res.ok || !res.body) return '';
    const reader = res.body.getReader();
    const decoder = new TextDecoder('utf-8', { fatal: false });
    let out = '';
    let read = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      read += value.byteLength;
      out += decoder.decode(value, { stream: true });
      if (read >= maxBytes) { await reader.cancel(); break; }
    }
    out += decoder.decode();
    // Memory is already bounded by the byte-counted read loop above; return as-is.
    return out;
  } catch {
    return '';
  }
}

export function headerGet(h: Headers | Record<string, string>, name: string): string | null {
  if (h instanceof Headers) return h.get(name);
  return h[name] ?? h[name.toLowerCase()] ?? null;
}

/** Resolve a possibly-relative href against the page origin; null if it can't be parsed. */
export function resolveUrl(base: string, href: string): string | null {
  try {
    return new URL(href, base).toString();
  } catch {
    return null;
  }
}

export function sameOrigin(a: string, b: string): boolean {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

// ---- tiny HTML extractors (regex, case-insensitive) ----

export function matchAllGroups(html: string, re: RegExp): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(re)) if (m[1] != null) out.push(m[1]);
  return out;
}

export const html = {
  title: (h: string) => (h.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] ?? '').trim(),
  hasLang: (h: string) => /<html[^>]*\blang\s*=\s*["']?[a-z]/i.test(h),
  metaContent: (h: string, name: string): string | null => {
    // matches <meta name="x" content="y"> or property="x" in either attribute order
    const re = new RegExp(
      `<meta[^>]+(?:name|property)\\s*=\\s*["']${name.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')}["'][^>]*>`,
      'i',
    );
    const tag = h.match(re)?.[0];
    if (!tag) return null;
    return tag.match(/content\s*=\s*["']([^"']*)["']/i)?.[1] ?? '';
  },
  hasViewport: (h: string) => /<meta[^>]+name\s*=\s*["']viewport["']/i.test(h),
  canonical: (h: string): string | null =>
    h.match(/<link[^>]+rel\s*=\s*["']canonical["'][^>]*>/i)?.[0]?.match(/href\s*=\s*["']([^"']+)["']/i)?.[1] ?? null,
  scripts: (h: string) => matchAllGroups(h, /<script[^>]+src\s*=\s*["']([^"']+)["']/gi),
  links: (h: string) => matchAllGroups(h, /<a\s[^>]*href\s*=\s*["']([^"'#]+)["']/gi),
  images: (h: string): { src: string; hasAlt: boolean }[] => {
    const out: { src: string; hasAlt: boolean }[] = [];
    for (const m of h.matchAll(/<img\s[^>]*>/gi)) {
      const tag = m[0];
      const src = tag.match(/\bsrc\s*=\s*["']([^"']+)["']/i)?.[1];
      if (src) out.push({ src, hasAlt: /\balt\s*=/i.test(tag) });
    }
    return out;
  },
  h1Count: (h: string) => (h.match(/<h1[\s>]/gi) || []).length,
  // Inputs that should be labelled (excludes hidden/submit/button) vs total <label> count.
  // An aria-label / aria-labelledby / title attribute IS a valid accessible name
  // (WCAG 4.1.2), so inputs carrying one don't need a <label> — counting them
  // produced false positives on pages whose only input was aria-labelled.
  inputsNeedingLabel: (h: string) =>
    (h.match(/<input\b(?![^>]*\btype\s*=\s*["'](?:hidden|submit|button|image|reset)["'])(?![^>]*\baria-label(?:ledby)?\s*=)(?![^>]*\btitle\s*=)[^>]*>/gi) || []).length,
  labelCount: (h: string) => (h.match(/<label[\s>]/gi) || []).length,
  // http:// resources referenced from the page (mixed content when the page is https).
  insecureRefs: (h: string) =>
    matchAllGroups(h, /(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi).filter((u) => !/^http:\/\/(localhost|127\.)/i.test(u)),
};

// ---- secret scanning ----

export interface SecretRule {
  id: string;
  name: string;
  severity: 'high' | 'medium' | 'low';
  re: RegExp;
  /** Optional extra confirmation to cut false positives. */
  confirm?: (match: string, blob: string) => boolean;
}

// High-confidence, low-false-positive patterns. Anything that's *meant* to be public (e.g. Stripe
// pk_live, Supabase anon key) is intentionally NOT here — only things that should never reach a browser.
export const SECRET_RULES: SecretRule[] = [
  { id: 'aws.akid', name: 'AWS access key id', severity: 'high', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'stripe.sk_live', name: 'Stripe live secret key', severity: 'high', re: /\bsk_live_[0-9a-zA-Z]{20,}\b/ },
  { id: 'stripe.rk_live', name: 'Stripe live restricted key', severity: 'high', re: /\brk_live_[0-9a-zA-Z]{20,}\b/ },
  { id: 'privatekey', name: 'Private key block', severity: 'high', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { id: 'github.pat', name: 'GitHub personal access token', severity: 'high', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b/ },
  { id: 'github.pat_fine', name: 'GitHub fine-grained token', severity: 'high', re: /\bgithub_pat_[0-9A-Za-z_]{60,}\b/ },
  { id: 'slack.token', name: 'Slack token', severity: 'high', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { id: 'anthropic.key', name: 'Anthropic API key', severity: 'high', re: /\bsk-ant-[0-9A-Za-z_-]{20,}\b/ },
  { id: 'openai.key', name: 'OpenAI API key', severity: 'high', re: /\bsk-(?:proj-)?[0-9A-Za-z]{20}[0-9A-Za-z_-]{10,}\b/ },
  { id: 'google.apikey', name: 'Google API key', severity: 'medium', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: 'sendgrid.key', name: 'SendGrid API key', severity: 'high', re: /\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b/ },
  { id: 'twilio.sk', name: 'Twilio API key', severity: 'high', re: /\bSK[0-9a-fA-F]{32}\b/ },
  {
    // A JWT whose payload decodes to role=service_role (Supabase) — full DB bypass if shipped to the client.
    id: 'supabase.service_role',
    name: 'Supabase service_role key',
    severity: 'high',
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
    confirm: (m) => {
      try {
        const payload = JSON.parse(Buffer.from(m.split('.')[1], 'base64').toString('utf8'));
        return payload?.role === 'service_role';
      } catch {
        return false;
      }
    },
  },
];

export interface SecretHit {
  ruleId: string;
  name: string;
  severity: 'high' | 'medium' | 'low';
  sample: string;
}

export function scanSecrets(blob: string): SecretHit[] {
  const hits: SecretHit[] = [];
  const seen = new Set<string>();
  for (const rule of SECRET_RULES) {
    for (const m of blob.matchAll(new RegExp(rule.re, rule.re.flags.includes('g') ? rule.re.flags : rule.re.flags + 'g'))) {
      const match = m[0];
      if (rule.confirm && !rule.confirm(match, blob)) continue;
      const key = `${rule.id}:${match.slice(0, 12)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      // Redact: keep enough to identify, hide the secret body.
      const sample = match.length > 14 ? `${match.slice(0, 8)}…${match.slice(-4)}` : match;
      hits.push({ ruleId: rule.id, name: rule.name, severity: rule.severity, sample });
    }
  }
  return hits;
}

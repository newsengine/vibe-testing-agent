// src/probe.ts
// Orchestrates the full black-box scan: fetch the homepage ONCE, then run every enabled category
// against that shared context. `probe()` runs all categories by default (it used to be security-only);
// pass `only`/`skip` to scope it. The result is a flat Finding[] the CLI groups + gates on.

import type { Category, Finding, ScanContext, ScanOptions, Severity } from './types.js';
import {
  securityChecks, secretChecks, exposureChecks, reliabilityChecks, seoChecks, a11yChecks, performanceChecks,
} from './checks.js';
import { dnsChecks } from './dns.js';
import { agentChecks } from './agent.js';
import { frameworkChecks } from './framework.js';
import { componentChecks } from './components.js';
import { detectStacks } from './detect.js';
import { hostChecks } from './host.js';
import { pluginChecks } from './plugins.js';
import { appStyleChecks } from './appstyle.js';
import { atlasChecks } from './atlas.js';
import { DEFAULT_RETRIES, decideRetry, inconclusiveFinding } from './retry.js';
import { fetchWithRetry, runWithRetryBudget } from './core.js';

export type { Category, Finding, ScanContext, ScanOptions, Severity };
// Back-compat alias: ProbeOptions was the old name.
export type ProbeOptions = ScanOptions;

const RUNNERS: Record<Category, (ctx: ScanContext) => Promise<Finding[]>> = {
  security: securityChecks,
  secrets: secretChecks,
  exposure: exposureChecks,
  dns: dnsChecks,
  reliability: reliabilityChecks,
  seo: seoChecks,
  a11y: a11yChecks,
  performance: performanceChecks,
  agent: agentChecks,
  framework: frameworkChecks,
  components: componentChecks,
  host: hostChecks,
  appstyle: appStyleChecks,
  atlas: atlasChecks,
  plugins: pluginChecks,
};

export const ALL_CATEGORIES = Object.keys(RUNNERS) as Category[];

/** Add https:// when the user typed a bare domain, so `vibetesting-agent example.com` just works. */
export function normalizeUrl(input: string): string {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`;
}

async function buildContext(baseUrl: string, opts: ScanOptions): Promise<ScanContext & { homepageRetries: number; homepageTransient: boolean }> {
  const url = new URL(baseUrl);
  let res: Response | null = null;
  let html = '';
  let headers = new Headers();
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const retries = opts.retries ?? DEFAULT_RETRIES;
  const attempt = await fetchWithRetry(
    url.origin,
    { redirect: 'follow', headers: opts.extraHeaders },
    timeoutMs,
    retries,
  );
  res = attempt.response;
  if (res) {
    headers = res.headers;
    if ((res.headers.get('content-type') || '').includes('html')) {
      html = (await res.text()).slice(0, 5_000_000);
    }
  }
  const homepageTransient = !res
    || decideRetry({ status: res.status, retryAfter: res.headers.get('retry-after') }).retry;
  const stacks = detectStacks({ html, headers, setCookie: (headers as any).getSetCookie?.() ?? [] });
  return {
    baseUrl,
    origin: url.origin,
    url,
    res,
    html,
    headers,
    opts,
    stacks,
    homepageRetries: attempt.retries,
    homepageTransient,
  };
}

function stampRetries(findings: Finding[]): Finding[] {
  return findings.map((f) => (f.retries == null ? { ...f, retries: 0 } : f));
}

/** Run the comprehensive scan. Returns every finding across the selected categories. */
export async function probe(baseUrl: string, opts: ScanOptions = {}): Promise<Finding[]> {
  const retries = opts.retries ?? DEFAULT_RETRIES;
  return runWithRetryBudget(retries, async () => {
    const ctx = await buildContext(baseUrl, opts);
    if (ctx.homepageTransient) {
      const kind = ctx.res
        ? `HTTP ${ctx.res.status}`
        : 'network/timeout/DNS failure';
      return [
        inconclusiveFinding({
          id: 'reachability',
          category: 'security',
          title: 'Site unreachable after retries (error/inconclusive)',
          detail: `fetch ${ctx.origin} failed (${kind}) after ${ctx.homepageRetries} retr${ctx.homepageRetries === 1 ? 'y' : 'ies'}`,
          retries: ctx.homepageRetries,
          fix: 'Confirm the deploy is live and retry. This is not a security finding.',
        }),
      ];
    }
    const selected = (opts.only ?? ALL_CATEGORIES).filter((c) => !(opts.skip ?? []).includes(c));
    const results = await Promise.all(selected.map((c) => RUNNERS[c](ctx).catch((e): Finding[] => [
      { category: c, id: `${c}.error`, title: `${c} check crashed`, severity: 'info', pass: true, detail: String(e?.message || e), retries: 0 },
    ])));
    return stampRetries(results.flat());
  });
}

/** Alias — reads better for the full-app use case. */
export const scan = probe;

/**
 * Discover up to `max` additional same-origin pages linked from the homepage — for a bounded multi-page
 * crawl (`--crawl N`). Returns absolute URLs (excluding the homepage itself). Best-effort; [] on failure.
 */
export async function discoverPages(baseUrl: string, max: number, opts: ScanOptions = {}): Promise<string[]> {
  const { safeFetch, html: H, resolveUrl, sameOrigin } = await import('./core.js');
  const url = new URL(baseUrl);
  const res = await safeFetch(url.origin, { redirect: 'follow', headers: opts.extraHeaders }, opts.timeoutMs);
  if (!res || !res.ok) return [];
  const body = (await res.text()).slice(0, 5_000_000);
  const seen = new Set<string>([url.origin, url.origin + '/']);
  const pages: string[] = [];
  for (const href of H.links(body)) {
    const abs = resolveUrl(url.origin, href);
    if (!abs || !sameOrigin(abs, url.origin)) continue;
    const norm = abs.split('#')[0];
    if (seen.has(norm)) continue;
    seen.add(norm);
    pages.push(norm);
    if (pages.length >= max) break;
  }
  return pages;
}

export function summarize(findings: Finding[]): {
  passed: number; failed: number; failHigh: number; failMedium: number; failLow: number;
  byCategory: Record<string, { passed: number; failed: number }>;
} {
  let passed = 0, failed = 0, failHigh = 0, failMedium = 0, failLow = 0;
  const byCategory: Record<string, { passed: number; failed: number }> = {};
  for (const f of findings) {
    (byCategory[f.category] ??= { passed: 0, failed: 0 });
    if (f.pass) { passed++; byCategory[f.category].passed++; continue; }
    failed++; byCategory[f.category].failed++;
    if (f.severity === 'high') failHigh++;
    else if (f.severity === 'medium') failMedium++;
    else if (f.severity === 'low') failLow++;
  }
  return { passed, failed, failHigh, failMedium, failLow, byCategory };
}

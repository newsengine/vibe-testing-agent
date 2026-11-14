// src/crawl.ts
// "Extra batteries" deep browser crawl + SAFE audit. Visits every reachable same-origin page (optionally
// authenticated via a Chrome profile or a cookie) and, per page, reports functional problems a fetch scan
// can't see — JS errors, console errors, failed requests, broken images. Plus SAFE fuzzing on SEARCH/
// FILTER (GET) inputs only: a reflected-input escaping test (HTML-injection/XSS) and a SQL-error probe.
//
// STRICTLY NON-DESTRUCTIVE: only GET navigation and search/filter inputs. It NEVER submits create/edit/
// delete (POST) forms, never clicks destructive buttons, never mutates data. Needs playwright-core + Chrome.

import type { Finding, Severity } from './types.js';
import { RENDER_HEALTH_PROBE, renderHealthFindings } from './render-health.js';

const MARK = 'apxPROBE7391';
const XSS_IN = `"><${MARK}>`;
const SQLI_IN = `apx' OR '1'='1`;
const SQL_ERR = /SQL syntax|sqlite3?|SQLSTATE|PG::|psql:|ORA-\d{3,}|mysqli?_|syntax error at or near|unterminated quoted string|column .* does not exist/i;

export interface CrawlOptions {
  maxPages?: number;
  startPaths?: string[];
  /** Reuse a logged-in Chrome profile (via browser-auth). */
  chromeProfile?: string;
  profilesDir?: string;
  /** Or authenticate with a raw Cookie header. */
  cookie?: string;
  timeoutMs?: number;
}

const f = (id: string, title: string, severity: Severity, detail: string, fix: string, category: Finding['category'] = 'reliability'): Finding =>
  ({ category, id, title, severity, pass: false, detail, fix });

/**
 * Turn a raw `Cookie:` header ("a=1; b=2") into Playwright cookies bound to `origin` via `url`, so the
 * browser only sends them back to that host (host-only, Secure when the origin is https).
 */
export function cookieHeaderToCookies(raw: string, origin: string): { name: string; value: string; url: string }[] {
  const url = new URL(origin).origin + '/';
  const out: { name: string; value: string; url: string }[] = [];
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    if (name) out.push({ name, value: part.slice(eq + 1).trim(), url });
  }
  return out;
}

export async function crawlAudit(startUrl: string, opts: CrawlOptions = {}): Promise<Finding[]> {
  const origin = new URL(startUrl).origin;
  const maxPages = opts.maxPages ?? 30;
  const timeout = opts.timeoutMs ?? 25000;
  const findings: Finding[] = [];
  const sameOrigin = (u: string) => { try { return new URL(u, origin).origin === origin; } catch { return false; } };
  const norm = (u: string) => { try { const x = new URL(u, origin); x.hash = ''; return x.toString(); } catch { return null; } };

  // Acquire an authenticated browser session (profile), or a plain/cookie context.
  let browser: any, closeSession: (() => Promise<void>) | null = null, chromium: any;
  try { ({ chromium } = await import('playwright-core')); }
  catch { return [{ category: 'reliability', id: 'crawl.missing-dep', title: 'crawl mode needs playwright-core', severity: 'info', pass: true, detail: 'run `npm i -D playwright-core` to enable `vibetesting-agent crawl`' }]; }

  if (opts.chromeProfile) {
    const { launchProfile, defaultProfilesDir } = await import('./browser-auth.js');
    const s = await launchProfile({ profilesDir: opts.profilesDir || defaultProfilesDir(), srcProfile: opts.chromeProfile, tag: 'crawl', port: 9251 });
    browser = s.browser; closeSession = s.close;
  } else {
    try { browser = await chromium.launch({ channel: 'chrome', headless: true }); }
    catch { browser = await chromium.launch({ headless: true }); }
    closeSession = async () => { try { await browser.close(); } catch {} };
  }

  const ctx = browser.contexts()[0] || await browser.newContext();
  // Scope --cookie to the target origin. extraHTTPHeaders would send it to every third-party origin
  // the page loads (CDNs, analytics, embeds).
  if (opts.cookie) await ctx.addCookies(cookieHeaderToCookies(opts.cookie, origin));
  const page = await ctx.newPage();

  const seen = new Set<string>();
  const queue: string[] = [];
  for (const p of (opts.startPaths ?? ['/'])) { const n = norm(origin + p); if (n) queue.push(n); }

  while (queue.length && seen.size < maxPages) {
    const url = queue.shift()!;
    if (seen.has(url)) continue;
    seen.add(url);
    const path = new URL(url).pathname;

    const jsErr: string[] = [], conErr: string[] = [], failed: string[] = [];
    const onErr = (e: any) => jsErr.push(String(e?.message || e).slice(0, 140));
    const onCon = (m: any) => { if (m.type() === 'error') conErr.push(m.text().slice(0, 140)); };
    const onResp = (r: any) => { try { const st = r.status(); if (st >= 400 && r.request().resourceType() !== 'document') failed.push(`${st} ${r.url().replace(origin, '').slice(0, 70)}`); } catch {} };
    page.on('pageerror', onErr); page.on('console', onCon); page.on('response', onResp);

    try {
      const resp = await page.goto(url, { waitUntil: 'networkidle', timeout });
      await page.waitForTimeout(1000);
      if (resp && resp.status() >= 400) findings.push(f(`crawl.status${path}`, `Page ${path} returns ${resp.status()}`, 'medium', `authenticated crawl: ${resp.status()} on a navigable route`, 'Fix or remove the broken route/link.'));
    } catch (e: any) {
      findings.push(f(`crawl.load${path}`, `Page failed to load: ${path}`, 'high', String(e?.message || e).slice(0, 100), 'The page errored or timed out in a real browser.'));
      page.off('pageerror', onErr); page.off('console', onCon); page.off('response', onResp);
      continue;
    }

    // Render health (error boundary / crash overlay / blank root) — caught even when no pageerror fires.
    try {
      const health = await page.evaluate(`(${RENDER_HEALTH_PROBE})()`);
      for (const finding of renderHealthFindings(path, health)) if (!finding.pass) findings.push(finding);
    } catch { /* best-effort */ }

    if (jsErr.length) findings.push(f(`crawl.js${path}`, `JavaScript error on ${path}`, 'high', jsErr.slice(0, 2).join(' | '), 'Fix the uncaught exception — it breaks interactivity.'));
    if (failed.length) findings.push(f(`crawl.req${path}`, `Failed request(s) on ${path}`, 'medium', [...new Set(failed)].slice(0, 4).join(', '), 'Fix resources/APIs returning 4xx/5xx on this page.'));
    if (conErr.length) findings.push(f(`crawl.con${path}`, `Console error(s) on ${path}`, 'low', conErr.slice(0, 2).join(' | '), 'Investigate console errors — often failed fetches or feature bugs.'));

    const probe = await page.evaluate(() => {
      const brokenImg = Array.from(document.images).filter((i) => i.complete && i.naturalWidth === 0 && (i.getAttribute('src') || '').trim()).map((i) => i.src);
      const searchInputs = Array.from(document.querySelectorAll('input')).filter((el: any) => {
        const t = (el.type || 'text').toLowerCase();
        const hint = ((el.name || '') + ' ' + (el.placeholder || '') + ' ' + (el.getAttribute('aria-label') || '')).toLowerCase();
        const getForm = !el.form || (el.form.method || 'get').toLowerCase() === 'get';
        return ['text', 'search'].includes(t) && (t === 'search' || /search|query|filter|find|keyword/.test(hint)) && getForm && !el.disabled && !el.readOnly;
      }).length;
      return { brokenImg, searchInputs, links: Array.from(document.querySelectorAll('a[href]')).map((a: any) => a.href) };
    });
    if (probe.brokenImg.length) findings.push(f(`crawl.img${path}`, `Broken image(s) on ${path}`, 'medium', probe.brokenImg.slice(0, 3).join(', '), 'Fix the missing image sources.'));
    for (const href of probe.links) { const n = norm(href); if (n && sameOrigin(n) && !seen.has(n) && !queue.includes(n)) queue.push(n); }

    // SAFE fuzz — search/filter GET inputs only.
    if (probe.searchInputs > 0) {
      for (const payload of [XSS_IN, SQLI_IN]) {
        try {
          const inp = page.locator('input[type=search], input[name*=search i], input[placeholder*=search i], input[name=q]').first();
          if (!(await inp.count())) break;
          await inp.fill(payload, { timeout: 2500 });
          await inp.press('Enter', { timeout: 2500 }).catch(() => {});
          await page.waitForTimeout(1200);
          const html = await page.content();
          if (payload === XSS_IN && html.includes(`<${MARK}>`)) findings.push(f(`crawl.xss${path}`, `Reflected HTML injection on ${path}`, 'high', `search reflected "<${MARK}>" UNESCAPED`, 'Encode user input before rendering it — reflected XSS risk.', 'security'));
          if (payload === SQLI_IN && SQL_ERR.test(html)) findings.push(f(`crawl.sqli${path}`, `SQL error surfaced on ${path}`, 'high', 'a search input produced a SQL error string', 'Use parameterised queries; never build SQL from user input.', 'security'));
          await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 12000 }).catch(() => {});
        } catch {}
      }
    }
    page.off('pageerror', onErr); page.off('console', onCon); page.off('response', onResp);
  }

  if (closeSession) await closeSession();
  (findings as any).pagesVisited = [...seen].map((u) => new URL(u).pathname);
  return findings;
}

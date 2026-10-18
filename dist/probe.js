// src/probe.ts
// Orchestrates the full black-box scan: fetch the homepage ONCE, then run every enabled category
// against that shared context. `probe()` runs all categories by default (it used to be security-only);
// pass `only`/`skip` to scope it. The result is a flat Finding[] the CLI groups + gates on.
import { securityChecks, secretChecks, exposureChecks, reliabilityChecks, seoChecks, a11yChecks, performanceChecks, } from './checks.js';
import { dnsChecks } from './dns.js';
import { agentChecks } from './agent.js';
import { frameworkChecks } from './framework.js';
import { componentChecks } from './components.js';
import { detectStacks } from './detect.js';
import { hostChecks } from './host.js';
import { pluginChecks } from './plugins.js';
import { appStyleChecks } from './appstyle.js';
import { atlasChecks } from './atlas.js';
import { gapChecks } from './gap-checks.js';
import { scanRepo, repoHitsToFindings } from './repo-secrets.js';
const RUNNERS = {
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
export const ALL_CATEGORIES = Object.keys(RUNNERS);
/** Add https:// when the user typed a bare domain, so `vibetesting-agent example.com` just works. */
export function normalizeUrl(input) {
    return /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`;
}
async function buildContext(baseUrl, opts) {
    const url = new URL(baseUrl);
    let res = null;
    let html = '';
    let headers = new Headers();
    // The homepage fetch is the one call not going through safeFetch, so it needs its own hard timeout —
    // otherwise a site that accepts the connection but never responds would hang the entire scan.
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), opts.timeoutMs ?? 10_000);
    try {
        res = await fetch(url.origin, { redirect: 'follow', signal: ac.signal, headers: opts.extraHeaders });
        headers = res.headers;
        if ((res.headers.get('content-type') || '').includes('html')) {
            html = (await res.text()).slice(0, 5_000_000);
        }
    }
    catch {
        res = null;
    }
    finally {
        clearTimeout(timer);
    }
    const stacks = detectStacks({ html, headers, setCookie: headers.getSetCookie?.() ?? [] });
    return { baseUrl, origin: url.origin, url, res, html, headers, opts, stacks };
}
/** Run the comprehensive scan. Returns every finding across the selected categories. */
export async function probe(baseUrl, opts = {}) {
    const ctx = await buildContext(baseUrl, opts);
    const selected = (opts.only ?? ALL_CATEGORIES).filter((c) => !(opts.skip ?? []).includes(c));
    const results = await Promise.all(selected.map((c) => RUNNERS[c](ctx).catch((e) => [
        { category: c, id: `${c}.error`, title: `${c} check crashed`, severity: 'info', pass: true, detail: String(e?.message || e) },
    ])));
    const findings = results.flat();
    try {
        findings.push(...await gapChecks(ctx, {
            authorizedGap: opts.authorizedGap || opts.authorizedActive,
            verified: opts.verified,
            repoPath: opts.repoPath,
            only: selected,
            skip: opts.skip,
        }));
    }
    catch (e) {
        findings.push({
            category: 'security', id: 'gap.error', title: 'gap checks crashed', severity: 'info', pass: true,
            detail: String(e?.message || e),
        });
    }
    if (opts.repoPath && selected.includes('secrets')) {
        try {
            const scan = await scanRepo(opts.repoPath);
            findings.push(...repoHitsToFindings(scan).filter((f) => selected.includes(f.category) && !(opts.skip ?? []).includes(f.category)));
        }
        catch (e) {
            findings.push({
                category: 'secrets', id: 'repo.secrets.error', title: 'repo secret scan crashed', severity: 'info', pass: true,
                detail: String(e?.message || e),
            });
        }
    }
    return findings;
}
/** Alias — reads better for the full-app use case. */
export const scan = probe;
/**
 * Discover up to `max` additional same-origin pages linked from the homepage — for a bounded multi-page
 * crawl (`--crawl N`). Returns absolute URLs (excluding the homepage itself). Best-effort; [] on failure.
 */
export async function discoverPages(baseUrl, max, opts = {}) {
    const { safeFetch, html: H, resolveUrl, sameOrigin } = await import('./core.js');
    const url = new URL(baseUrl);
    const res = await safeFetch(url.origin, { redirect: 'follow', headers: opts.extraHeaders }, opts.timeoutMs);
    if (!res || !res.ok)
        return [];
    const body = (await res.text()).slice(0, 5_000_000);
    const seen = new Set([url.origin, url.origin + '/']);
    const pages = [];
    for (const href of H.links(body)) {
        const abs = resolveUrl(url.origin, href);
        if (!abs || !sameOrigin(abs, url.origin))
            continue;
        const norm = abs.split('#')[0];
        if (seen.has(norm))
            continue;
        seen.add(norm);
        pages.push(norm);
        if (pages.length >= max)
            break;
    }
    return pages;
}
export function summarize(findings) {
    let passed = 0, failed = 0, failHigh = 0, failMedium = 0, failLow = 0;
    const byCategory = {};
    for (const f of findings) {
        (byCategory[f.category] ??= { passed: 0, failed: 0 });
        if (f.pass) {
            passed++;
            byCategory[f.category].passed++;
            continue;
        }
        failed++;
        byCategory[f.category].failed++;
        if (f.severity === 'high')
            failHigh++;
        else if (f.severity === 'medium')
            failMedium++;
        else if (f.severity === 'low')
            failLow++;
    }
    return { passed, failed, failHigh, failMedium, failLow, byCategory };
}

/**
 * Runs security scans and builds VibeTesting Agent artifacts.
 * On Cloudflare Workers: pure fetch-based lite/fast checks (no child_process).
 * Locally: prefers monorepo vibetesting-agent when available.
 */
import type { ScanMode } from './plans';
import {
  buildSecurityReviewMarkdown,
  buildSecurityReviewHtml,
} from './security-review';
import { canRunGapCheck } from './entitlements';

export interface Finding {
  id: string;
  category: string;
  title: string;
  severity: 'high' | 'medium' | 'low' | 'info';
  pass: boolean;
  detail: string;
  fix?: string;
}

export interface ScanResult {
  url: string;
  findings: Finding[];
  summary: {
    total: number;
    passed: number;
    failed: number;
    failHigh: number;
    failMedium: number;
    failLow: number;
  };
  score: number;
  grade: string;
  fixPackMarkdown: string;
  reportHtml: string;
  baselineDiff: {
    newFailures: Finding[];
    resolved: string[];
    stillFailing: string[];
  };
}

function scoreFromFindings(findings: Finding[]): { score: number; grade: string } {
  const failed = findings.filter((f) => !f.pass);
  let score = 100;
  for (const f of failed) {
    if (f.severity === 'high') score -= 12;
    else if (f.severity === 'medium') score -= 6;
    else if (f.severity === 'low') score -= 2;
  }
  score = Math.max(0, Math.min(100, score));
  const grade =
    score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
  return { score, grade };
}

function summarize(findings: Finding[]) {
  const failed = findings.filter((f) => !f.pass);
  return {
    total: findings.length,
    passed: findings.filter((f) => f.pass).length,
    failed: failed.length,
    failHigh: failed.filter((f) => f.severity === 'high').length,
    failMedium: failed.filter((f) => f.severity === 'medium').length,
    failLow: failed.filter((f) => f.severity === 'low').length,
  };
}

export function buildFixPack(
  url: string,
  findings: Finding[],
  score: number,
  grade: string,
  opts: { mode?: string; scanId?: string; projectName?: string } = {},
): string {
  // End-of-run artifact = Claude `/security-review` ranked report
  return buildSecurityReviewMarkdown(url, findings, score, grade, {
    mode: opts.mode,
    scanId: opts.scanId,
    projectName: opts.projectName,
    suite: opts.mode ? `VibeTesting Agent ${opts.mode} suite` : undefined,
  });
}

/**
 * Single paste-ready prompt for Claude / Codex / Cursor to fix every failing finding
 * for one specific deploy URL (ranked P1…Pn).
 */
export function buildAgentFixPrompt(
  url: string,
  findings: Finding[],
  score: number,
  grade: string,
  opts: { suite?: string } = {},
): string {
  const fails = findings
    .filter((f) => !f.pass)
    .sort((a, b) => {
      const o = { high: 0, medium: 1, low: 2, info: 3 } as const;
      return o[a.severity] - o[b.severity];
    });

  const suite = opts.suite || 'VibeTesting Agent black-box scan';
  const lines: string[] = [
    `You are a senior application security engineer working in this repository.`,
    ``,
    `## Mission`,
    `Fix **every** security finding below for the live deploy at:`,
    ``,
    `\`${url}\``,
    ``,
    `Scan score: **${score}/100** (grade **${grade}**). Suite: ${suite}.`,
    `Generated: ${new Date().toISOString()}`,
    ``,
    `## Rules`,
    `1. Work **top-down** (P1 first). Do not skip high severity.`,
    `2. Prefer **least-privilege**, production-safe fixes (config, headers, edge rules, env hygiene).`,
    `3. Do **not** invent issues that are not listed.`,
    `4. For each finding: implement the fix in code/config, then note how to verify.`,
    `5. Keep public keys public; never commit real secrets — rotate if any secret was exposed.`,
    `6. If a fix needs DNS (SPF/DMARC/CAA), document the exact record for the domain owner.`,
    `7. After changes, summarize files touched and residual risk.`,
    ``,
    `## Findings to fix (${fails.length})`,
    ``,
  ];

  if (!fails.length) {
    lines.push(`No failing findings — confirm baseline remains green and improve CSP strength if only warnings exist.`);
    return lines.join('\n');
  }

  fails.forEach((f, i) => {
    lines.push(`### P${i + 1}. [${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`- **id:** \`${f.id}\``);
    lines.push(`- **category:** \`${f.category}\``);
    lines.push(`- **evidence:** ${f.detail}`);
    lines.push(`- **recommended fix:** ${f.fix || 'Investigate and harden this surface.'}`);
    lines.push(`- **acceptance:** Finding \`${f.id}\` should pass a re-scan of ${url}.`);
    lines.push(``);
  });

  lines.push(`## Deliverables`);
  lines.push(`1. Code/config patches for all P1–P${fails.length} items you can fix in-repo.`);
  lines.push(`2. Short checklist of deploy/DNS steps the human must do outside the repo.`);
  lines.push(`3. Suggested re-scan command: \`npx github:newsengine/vibetesting-agent ${url}\``);
  lines.push(``);
  lines.push(`Start with P1 now.`);

  return lines.join('\n');
}

function buildReportHtml(
  url: string,
  findings: Finding[],
  score: number,
  grade: string,
  opts: { mode?: string; scanId?: string } = {},
): string {
  return buildSecurityReviewHtml(url, findings, score, grade, {
    mode: opts.mode,
    scanId: opts.scanId,
    suite: opts.mode ? `VibeTesting Agent ${opts.mode} suite` : undefined,
  });
}

export function diffBaseline(
  findings: Finding[],
  baselineIds: string[] | null,
): ScanResult['baselineDiff'] {
  const failing = findings.filter((f) => !f.pass);
  const failingIds = new Set(failing.map((f) => f.id));
  const base = new Set(baselineIds || []);
  return {
    newFailures: failing.filter((f) => !base.has(f.id)),
    stillFailing: [...failingIds].filter((id) => base.has(id)),
    resolved: [...base].filter((id) => !failingIds.has(id)),
  };
}

const SECRET_PATTERNS: { id: string; name: string; severity: Finding['severity']; re: RegExp }[] = [
  { id: 'secret.stripe.sk_live', name: 'Stripe live secret key', severity: 'high', re: /\bsk_live_[0-9a-zA-Z]{20,}\b/ },
  { id: 'secret.aws.akia', name: 'AWS access key', severity: 'high', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'secret.openai', name: 'OpenAI API key', severity: 'high', re: /\bsk-[a-zA-Z0-9]{20,}\b/ },
  { id: 'secret.github', name: 'GitHub token', severity: 'high', re: /\bghp_[a-zA-Z0-9]{36}\b/ },
  { id: 'secret.anthropic', name: 'Anthropic key', severity: 'high', re: /\bsk-ant-[a-zA-Z0-9\-_]{20,}\b/ },
];

/** Progress events for streaming lite-scan UI (NDJSON). */
export type ScanProgressEvent =
  | { type: 'start'; message: string; url: string }
  | { type: 'phase'; message: string; category?: string }
  | {
      type: 'check';
      id: string;
      category: string;
      title: string;
      severity: Finding['severity'];
      pass: boolean;
      detail: string;
      message: string;
    }
  | { type: 'done'; message: string; total: number; failed: number };

export type ScanProgressHandler = (event: ScanProgressEvent) => void | Promise<void>;

/** Workers-safe black-box scan using fetch only. */
export async function runWorkerScan(
  url: string,
  opts: { onProgress?: ScanProgressHandler; extraHeaders?: Record<string, string>; verified?: boolean } = {},
): Promise<Finding[]> {
  const onProgress = opts.onProgress;
  const extraHeaders = opts.extraHeaders || {};
  const findings: Finding[] = [];
  const emit = async (event: ScanProgressEvent) => {
    await onProgress?.(event);
  };
  const ua = extraHeaders['user-agent'] || 'VibeTestingAgent/1.0 (+https://vibetestingagent.com)';

  const push = async (
    category: string,
    id: string,
    title: string,
    severity: Finding['severity'],
    pass: boolean,
    detail: string,
    fix?: string,
  ): Promise<Finding> => {
    const finding: Finding = { category, id, title, severity, pass, detail, fix };
    findings.push(finding);
    const mark = pass ? 'PASS' : 'FAIL';
    await emit({
      type: 'check',
      id,
      category,
      title,
      severity,
      pass,
      detail: detail.slice(0, 160),
      message: `[${mark}] ${category}/${id} — ${title}`,
    });
    return finding;
  };

  await emit({ type: 'start', url, message: `Starting lite scan of ${url}` });
  if (Object.keys(extraHeaders).length) {
    await emit({
      type: 'phase',
      message: 'Using project authenticated session (same-origin headers only)…',
    });
  }
  await emit({ type: 'phase', category: 'reliability', message: 'Fetching target homepage…' });

  let res: Response | null = null;
  let html = '';
  let headers = new Headers();
  try {
    res = await fetch(url, {
      redirect: 'follow',
      headers: { 'user-agent': ua, ...extraHeaders },
      signal: AbortSignal.timeout(15000),
    });
    headers = res.headers;
    const ct = headers.get('content-type') || '';
    if (ct.includes('text/html') || ct.includes('text/plain') || ct.includes('javascript')) {
      html = (await res.text()).slice(0, 500_000);
    }
  } catch (e) {
    await push(
      'reliability',
      'site.unreachable',
      'Site unreachable',
      'high',
      false,
      String((e as Error).message),
      'Check DNS and that the deploy is live.',
    );
    await emit({
      type: 'done',
      message: 'Scan aborted — target unreachable',
      total: findings.length,
      failed: findings.filter((x) => !x.pass).length,
    });
    return findings;
  }

  await push(
    'reliability',
    'site.status',
    'Homepage responds',
    res.ok ? 'info' : 'medium',
    res.ok,
    `HTTP ${res.status}`,
    res.ok ? undefined : 'Fix server errors / routing.',
  );

  // Security headers
  await emit({ type: 'phase', category: 'security', message: 'Checking security headers…' });
  const hsts = headers.get('strict-transport-security');
  await push(
    'security',
    'header.strict-transport-security',
    hsts ? 'HSTS present' : 'Missing strict-transport-security',
    'high',
    !!hsts,
    hsts || 'expected HSTS with a long max-age',
    'Send Strict-Transport-Security: max-age=31536000; includeSubDomains',
  );
  const csp = headers.get('content-security-policy');
  await push(
    'security',
    'header.content-security-policy',
    csp ? 'CSP present' : 'Missing content-security-policy',
    'high',
    !!csp,
    csp?.slice(0, 200) || 'expected a Content-Security-Policy (enforced)',
    'Add a Content-Security-Policy header to stop injected scripts',
  );
  if (csp && (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'"))) {
    await push(
      'security',
      'csp.weak',
      'CSP allows unsafe-inline or unsafe-eval',
      'high',
      false,
      csp.slice(0, 240),
      'Remove unsafe-inline/unsafe-eval; use nonces or hashes.',
    );
  }
  const nosniff = headers.get('x-content-type-options');
  await push(
    'security',
    'header.x-content-type-options',
    nosniff ? 'nosniff set' : 'Missing x-content-type-options',
    'medium',
    (nosniff || '').toLowerCase().includes('nosniff'),
    nosniff || 'expected nosniff',
    'Send X-Content-Type-Options: nosniff',
  );
  const xfo = headers.get('x-frame-options') || headers.get('content-security-policy')?.includes('frame-ancestors');
  await push(
    'security',
    'header.x-frame-options',
    xfo ? 'Clickjacking protection present' : 'Missing clickjacking protection',
    'medium',
    !!xfo,
    typeof xfo === 'string' ? xfo : xfo ? 'CSP frame-ancestors' : 'expected X-Frame-Options or CSP frame-ancestors',
    'Send X-Frame-Options: DENY or CSP frame-ancestors',
  );
  const refpol = headers.get('referrer-policy');
  await push(
    'security',
    'header.referrer-policy',
    refpol ? 'Referrer-Policy set' : 'Missing referrer-policy',
    'low',
    !!refpol,
    refpol || 'missing',
    'Send Referrer-Policy: strict-origin-when-cross-origin (or tighter)',
  );

  // HTTPS redirect check
  await emit({ type: 'phase', category: 'security', message: 'Checking HTTP → HTTPS redirect…' });
  try {
    const u = new URL(url);
    if (u.protocol === 'https:') {
      const httpUrl = `http://${u.host}${u.pathname}`;
      const r = await fetch(httpUrl, { redirect: 'manual', signal: AbortSignal.timeout(8000) });
      const loc = r.headers.get('location') || '';
      const redirects = r.status >= 300 && r.status < 400 && loc.startsWith('https:');
      await push(
        'security',
        'tls.redirect',
        redirects ? 'HTTP redirects to HTTPS' : 'HTTP does not redirect to HTTPS',
        'medium',
        redirects,
        `status ${r.status}`,
        'Redirect all http:// traffic to https://',
      );
    }
  } catch {
    /* ignore */
  }

  // Exposure probes
  await emit({ type: 'phase', category: 'exposure', message: 'Probing exposed config paths…' });
  const exposurePaths = ['/.env', '/.git/config', '/.git/HEAD', '/wrangler.toml', '/package.json', '/backup.sql'];
  for (const path of exposurePaths) {
    await emit({ type: 'phase', category: 'exposure', message: `GET ${path}` });
    try {
      const er = await fetch(new URL(path, url).toString(), {
        signal: AbortSignal.timeout(6000),
        headers: { 'user-agent': ua, ...extraHeaders },
      });
      if (!er.ok) {
        await push('exposure', `exposed${path}`, `${path} not exposed`, 'info', true, `HTTP ${er.status}`);
        continue;
      }
      const body = (await er.text()).slice(0, 2000);
      const looksReal =
        path.includes('.env')
          ? /=/.test(body) && !/<html/i.test(body)
          : path.includes('git')
            ? /\[core\]|ref: refs\//.test(body)
            : path.includes('package')
              ? /"name"\s*:/.test(body)
              : !/<html/i.test(body) && body.length > 20;
      await push(
        'exposure',
        `exposed${path}`,
        looksReal ? `${path} appears publicly readable` : `${path} returned HTML (likely SPA catch-all)`,
        looksReal ? 'high' : 'info',
        !looksReal,
        body.slice(0, 120).replace(/\s+/g, ' '),
        looksReal ? 'Block this path at the edge/CDN; never ship secrets to static hosting.' : undefined,
      );
    } catch {
      await push('exposure', `exposed${path}`, `${path} not reachable`, 'info', true, 'fetch failed');
    }
  }

  // Secrets in HTML
  await emit({ type: 'phase', category: 'secrets', message: 'Scanning page for leaked secrets…' });
  for (const rule of SECRET_PATTERNS) {
    const m = html.match(rule.re);
    await push(
      'secrets',
      rule.id,
      m ? `${rule.name} found in page` : `No ${rule.name}`,
      rule.severity,
      !m,
      m ? 'redacted hit in HTML/JS payload' : 'no match',
      m ? 'Rotate the key immediately and remove it from client bundles.' : undefined,
    );
  }

  // DNS (Workers supports DNS over HTTPS via cloudflare-dns or skip if unavailable)
  await emit({ type: 'phase', category: 'dns', message: 'Looking up DNS / email hygiene (SPF)…' });
  try {
    const host = new URL(url).hostname;
    const doh = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=TXT`,
      { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(8000) },
    );
    if (doh.ok) {
      const data = (await doh.json()) as { Answer?: { data: string }[] };
      const txt = (data.Answer || []).map((a) => a.data).join(' ');
      const hasSpf = /v=spf1/i.test(txt);
      await push(
        'dns',
        'dns.spf',
        hasSpf ? 'SPF present' : 'No SPF TXT found (or not on apex TXT)',
        'low',
        hasSpf,
        hasSpf ? 'SPF record observed' : 'Add SPF for email domains',
        'Publish SPF TXT on the sending domain',
      );
    }
  } catch {
    /* optional */
  }

  await emit({ type: 'phase', category: 'dns', message: 'Gap checks (DKIM, CSRF, PII, preview hosts)…' });
  try {
    const gap = await runWorkerGapChecks(url, html, extraHeaders, ua, opts.verified === true);
    for (const g of gap) {
      await push(g.category, g.id, g.title, g.severity, g.pass, g.detail, g.fix);
    }
  } catch {
    /* optional */
  }

  const failed = findings.filter((x) => !x.pass).length;
  await emit({
    type: 'done',
    message: `Lite suite complete — ${findings.length} checks, ${failed} failed`,
    total: findings.length,
    failed,
  });
  return findings;
}

async function tryMonorepoProbe(
  url: string,
  mode: ScanMode,
  extraHeaders?: Record<string, string>,
  opts: { verified?: boolean; repoPath?: string } = {},
): Promise<Finding[] | null> {
  try {
    // Only works in Node local monorepo
    const { join } = await import('node:path');
    const { existsSync } = await import('node:fs');
    const { pathToFileURL } = await import('node:url');
    const root = join(process.cwd(), '..');
    const entry = join(root, 'dist', 'index.js');
    if (!existsSync(entry)) return null;
    const mod = await import(pathToFileURL(entry).href);
    const only =
      mode === 'fast' || mode === 'lite'
        ? (['secrets', 'exposure', 'security', 'dns', 'framework', 'host'] as const)
        : undefined;
    return (await mod.probe(url, {
      only: only as never,
      timeoutMs: 15000,
      maxCrawl: mode === 'crawl' ? 40 : 15,
      extraHeaders,
      verified: opts.verified,
      authorizedGap: opts.verified,
      repoPath: opts.verified ? opts.repoPath : undefined,
    })) as Finding[];
  } catch {
    return null;
  }
}

export async function runScan(
  url: string,
  opts: {
    mode?: ScanMode;
    baselineIds?: string[] | null;
    onProgress?: ScanProgressHandler;
    /** Prefer Workers fetch suite so progress events stream (homepage lite). */
    forceWorker?: boolean;
    /** Same-origin Cookie / Authorization for authenticated scans */
    extraHeaders?: Record<string, string>;
    /** Project ownership verified — enables verified-only gap checks. */
    verified?: boolean;
    /** Local repo path for repo.secrets (CLI/monorepo only). */
    repoPath?: string;
  } = {},
): Promise<ScanResult> {
  const mode = opts.mode === 'lite' ? 'fast' : opts.mode || 'fast';
  let findings: Finding[] | null = null;
  if (!opts.forceWorker && !opts.onProgress) {
    findings = await tryMonorepoProbe(url, mode, opts.extraHeaders, { verified: opts.verified, repoPath: opts.repoPath });
  } else if (!opts.forceWorker && opts.onProgress) {
    await opts.onProgress({ type: 'phase', message: 'Trying local monorepo probe…' });
    findings = await tryMonorepoProbe(url, mode, opts.extraHeaders, { verified: opts.verified, repoPath: opts.repoPath });
    if (findings) {
      await opts.onProgress({
        type: 'phase',
        message: `Monorepo probe returned ${findings.length} findings (batch)`,
      });
      for (const finding of findings) {
        await opts.onProgress({
          type: 'check',
          id: finding.id,
          category: finding.category,
          title: finding.title,
          severity: finding.severity,
          pass: finding.pass,
          detail: finding.detail.slice(0, 160),
          message: `[${finding.pass ? 'PASS' : 'FAIL'}] ${finding.category}/${finding.id} — ${finding.title}`,
        });
      }
    }
  }
  if (!findings) {
    findings = await runWorkerScan(url, {
      onProgress: opts.onProgress,
      extraHeaders: opts.extraHeaders,
      verified: opts.verified,
    });
  }

  const summary = summarize(findings);
  const { score, grade } = scoreFromFindings(findings);

  return {
    url,
    findings,
    summary,
    score,
    grade,
    fixPackMarkdown: buildFixPack(url, findings, score, grade, { mode }),
    reportHtml: buildReportHtml(url, findings, score, grade, { mode }),
    baselineDiff: diffBaseline(findings, opts.baselineIds ?? null),
  };
}

const WORKER_DKIM_SELECTORS = ['google', 'selector1', 'selector2', 'k1', 'k2', 'dkim', 'default'];
const WORKER_PREVIEW_SUBS = ['staging', 'dev', 'preview', 'beta', 'test'];

function workerApex(hostname: string): string {
  const parts = hostname.split('.').filter(Boolean);
  if (parts.length <= 2) return hostname;
  const lastTwo = parts.slice(-2).join('.');
  const multi = new Set(['com.au', 'co.uk', 'org.uk', 'co.nz', 'co.jp', 'com.br', 'co.in']);
  return multi.has(lastTwo) ? parts.slice(-3).join('.') : lastTwo;
}

/**
 * Workers-safe subset of gap checks. Default: dns.dkim, csrf.token, disclosure.pii-in-response,
 * exposure.preview-deployments. Verified-only checks run when `verified` is true (canRunGapCheck).
 */
async function runWorkerGapChecks(
  url: string,
  html: string,
  extraHeaders: Record<string, string>,
  ua: string,
  verified: boolean,
): Promise<Finding[]> {
  const out: Finding[] = [];
  const origin = new URL(url).origin;
  const hostname = new URL(url).hostname;
  const apex = workerApex(hostname);
  const hdrs = { 'user-agent': ua, ...extraHeaders };

  const add = (f: Finding) => {
    if (!canRunGapCheck(f.id, verified)) return;
    out.push(f);
  };

  if (canRunGapCheck('dns.dkim', verified)) {
    const found: string[] = [];
    for (const selector of WORKER_DKIM_SELECTORS) {
      try {
        const doh = await fetch(
          `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(`${selector}._domainkey.${apex}`)}&type=TXT`,
          { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) },
        );
        if (!doh.ok) continue;
        const data = (await doh.json()) as { Answer?: { data: string }[] };
        const txt = (data.Answer || []).map((a) => a.data).join(' ');
        if (/v=DKIM1/i.test(txt)) {
          found.push(selector);
          if (found.length >= 2) break;
        }
      } catch {
        /* NXDOMAIN */
      }
    }
    add({
      id: 'dns.dkim',
      category: 'dns',
      title: found.length ? 'DKIM records present' : 'No DKIM records found',
      severity: found.length ? 'info' : 'medium',
      pass: found.length > 0,
      detail: found.length ? `Found DKIM on selector(s): ${found.join(', ')} at ${apex}` : `No DKIM records on common selectors for ${apex}`,
      fix: found.length ? undefined : 'Configure DKIM signing for outbound email. Add a DKIM TXT record provided by your email service.',
    });
  }

  if (canRunGapCheck('csrf.token', verified)) {
    const forms = [...html.matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/gi)];
    const stateful = forms.filter((m) => /method\s*=\s*["']?post["']?/i.test(m[0]));
    if (stateful.length) {
      const withToken = stateful.filter((m) =>
        /name\s*=\s*["']?(?:csrf|_csrf|csrftoken|csrf_token|_token|authenticity_token)["']?/i.test(m[0]),
      );
      const ok = withToken.length === stateful.length;
      add({
        id: 'csrf.token',
        category: 'security',
        title: ok ? 'Forms have CSRF tokens' : 'Forms missing CSRF tokens',
        severity: ok ? 'info' : 'medium',
        pass: ok,
        detail: ok
          ? `${stateful.length} state-changing form(s) carry CSRF tokens`
          : `${stateful.length - withToken.length} of ${stateful.length} state-changing form(s) lack a CSRF token`,
        fix: ok ? undefined : 'Add CSRF tokens to all state-changing forms, or ensure session cookies use SameSite=Strict/Lax.',
      });
    }
  }

  if (canRunGapCheck('disclosure.pii-in-response', verified)) {
    for (const path of ['/api/user', '/api/me', '/api/profile', '/api/config']) {
      try {
        const res = await fetch(origin + path, { headers: hdrs, signal: AbortSignal.timeout(6000) });
        if (!res.ok) continue;
        const ct = (res.headers.get('content-type') || '').toLowerCase();
        if (!ct.includes('json')) continue;
        const body = await res.text();
        if (/<html/i.test(body)) continue;
        if (
          /"(?:email|email_address|emailAddress)"\s*:\s*"[^"]+@/i.test(body) ||
          /\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}/.test(body)
        ) {
          add({
            id: 'disclosure.pii-in-response',
            category: 'security',
            title: 'PII in API response',
            severity: 'medium',
            pass: false,
            detail: `GET ${path} response contains PII pattern`,
            fix: 'Avoid exposing emails, hashes, or tokens in unauthenticated API responses.',
          });
          break;
        }
      } catch {
        /* skip */
      }
    }
  }

  if (canRunGapCheck('exposure.preview-deployments', verified)) {
    const checked = new Set<string>();
    const flagHost = async (host: string, source: string) => {
      if (checked.has(host) || host === hostname) return;
      checked.add(host);
      try {
        const res = await fetch(`https://${host}/`, { headers: hdrs, signal: AbortSignal.timeout(5000), redirect: 'follow' });
        if (!res.ok) return;
        const body = await res.text();
        const issues: string[] = [];
        if (/<title>\s*debug|<pre>.*stack\s*trace/i.test(body)) issues.push('debug mode enabled');
        if (/(?:api_key|secret|password)\s*[:=]\s*["'][^"']+["']/i.test(body)) issues.push('potential secrets in response');
        if (!res.headers.get('www-authenticate') && !/login|sign in/i.test(body)) issues.push('no authentication required');
        if (issues.length) {
          add({
            id: 'exposure.preview-deployments',
            category: 'exposure',
            title: `Public preview deployment at ${host}`,
            severity: 'medium',
            pass: false,
            detail: `Found via ${source}: ${issues.join(', ')}`,
            fix: 'Protect preview deployments with authentication, or ensure they do not expose debug info or secrets.',
          });
        }
      } catch {
        /* unreachable */
      }
    };
    for (const sub of WORKER_PREVIEW_SUBS) {
      await flagHost(`${sub}.${apex}`, 'subdomain enumeration');
    }
    for (const m of html.matchAll(/href\s*=\s*["']https?:\/\/([^"'/]+)/gi)) {
      const host = m[1].toLowerCase();
      if (/\.(pages\.dev|vercel\.app|netlify\.app|workers\.dev)$/.test(host) && host.includes(apex.split('.')[0])) {
        await flagHost(host, 'page reference');
      }
    }
  }

  return out;
}

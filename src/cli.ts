#!/usr/bin/env node
// src/cli.ts
// `npx github:newsengine/vibetesting-agent <url> [options]`
// Point it at any deployed app and it reports everything wrong: leaked secrets, exposed files, broken
// links, missing security headers, SEO/a11y/performance gaps. Exits non-zero so it can gate CI.
//
//   --only security,secrets         only run these categories
//   --skip seo,a11y                 run everything except these
//   --cors-path /api/health         test CORS reflection on this path
//   --rate-limit-path /api/health   burst-test this path for rate limiting (expects 429)
//   --api-write                     (opt-in) benign unauth POST to write-suggestive API routes; flag any 2xx
//   --rate-limit-scan               (opt-in) auto-burst discovered expensive /api/* routes; expect 429
//   --xss                           (opt-in) reflected-XSS probe on public query params (inert marker)
//   --ai-probe                      (opt-in) MITRE ATLAS prompt-injection canary probe on a chat/LLM endpoint
//   --ledger <file.jsonl>           append this run (+ every sub-test, keyed by VTA number) to a ledger database
//   --priority                      print the Priority-Status report (daily-report cover page) first
//   --fix-pack <file.md>            write a PR-ready fix pack (header config + per-finding checklist)
//   --github-issues <owner/repo>    feed findings into the GitHub issue tracker (dry-run; add --apply to write)
//   --coverage <file.json>          authenticated deep-crawl coverage map (endpoints/params/forms/apis)
//   --authorized-active             (opt-in, AUTHORIZED) active injection engine: SQLi/SSTI/cmd/traversal on GET params
//   --authorized-gap                (opt-in, AUTHORIZED) verified-only gap checks (login rate-limit, IDOR, unsigned webhooks, LLM probes)
//   --repo <path>                   (opt-in) scan a local working tree + git history for leaked secrets (repo.secrets)
//   --allow-report-only-csp         accept CSP Report-Only as a pass
//   --max-crawl 25                  how many links/scripts to fetch-check
//   --plugins <dir>                 dir of custom JSON plugin templates (default ./vibetesting-agent-plugins)
//   --fail-on high|medium|any       CI exit threshold (default high)
//   --json                          machine-readable output
//   --sarif                         emit SARIF 2.1.0 (for GitHub code scanning / upload-sarif)
//   --baseline <file>               only fail on findings NOT in this baseline file
//   --write-baseline <file>         write current failing findings as a baseline, then exit 0
//   --agent-report <file.md>        ranked P1/P2 agent fix report (Claude/Cursor-ready)
//   --gherkin <file.feature>        emit Gherkin security scenarios from findings
//
// Subcommands:
//   vibetesting-agent audit [--prod] [--level low|moderate|high|critical] [--json]
//   vibetesting-agent init <url> [--name app] [--force] [--cwd .]   # scaffold Gherkin + CI + review md
//   vibetesting-agent review <url> [...]   # scan + agent-report + gherkin (security-review workflow)
//   vibetesting-agent db-critical <url>      # Dynamic Business CMS critical-path (auth/API; skips if env missing)

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { probe, summarize, normalizeUrl, discoverPages, ALL_CATEGORIES, type Category, type Finding, type Severity, type ScanOptions } from './probe.js';
import { runNpmAudit, failsAtLevel } from './audit.js';
import { toSarif } from './sarif.js';
import { buildBaseline, applyBaseline, type Baseline } from './baseline.js';
import { loadConfig } from './config.js';
import { asvsCoverage, owaspTop10Hit, refsFor, OWASP_TOP10_NAMES, apiTop10Hit, cwesHit, securityGrade, tlsGrade, OWASP_API_TOP10_NAMES } from './compliance.js';
import { recon, parsePorts } from './active.js';
import { identifyEdge } from './host.js';
import { lookupCves } from './cve.js';
import { renderAgentReport } from './agent-report.js';
import { renderGherkinFeature } from './gherkin.js';
import { initRepo } from './init.js';
import { buildRunRecord, appendRun, readRuns, renderPriorityReport, type RunRecord } from './ledger.js';
import { planIssueActions, keyFromBody, summarizeActions, type ExistingIssue } from './issues.js';
import { renderFixPack } from './fixes.js';
import { buildCoverageMap, summarizeCoverage } from './crawl-map.js';
import { activeInjectionScan } from './inject.js';
import { withCfBypassHeaders } from './cf-bypass-headers.js';
import { execFileSync } from 'node:child_process';

const VERSION = (() => {
  try { return JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version as string; }
  catch { return '0.0.0'; }
})();

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
const flag = (name: string) => process.argv.includes(name);
const list = (v?: string) => (v ? (v.split(',').map((s) => s.trim()).filter(Boolean) as Category[]) : undefined);

const SEV_ICON: Record<Severity, string> = { high: '🟥', medium: '🟧', low: '🟨', info: 'ℹ️ ' };
const CAT_TITLE: Record<Category, string> = {
  security: '🔐 Security', secrets: '🔑 Leaked secrets', exposure: '📂 Exposed files & debug',
  dns: '🌐 DNS & email', reliability: '🔗 Reliability', seo: '🔎 SEO', a11y: '♿ Accessibility', performance: '⚡ Performance',
  agent: '🤖 Agent readiness',
  framework: '🧩 Framework-specific',
  components: '📦 Vulnerable components',
  host: '🖥️  Host & infrastructure',
  appstyle: '🏢 App-type rules',
  atlas: '🤖 AI/LLM attack surface (MITRE ATLAS)',
  plugins: '🔌 Custom plugins',
};

async function runAudit() {
  const level = arg('--level') || 'high';
  const result = await runNpmAudit(process.cwd(), flag('--prod'));
  if (flag('--json')) { console.log(JSON.stringify(result, null, 2)); }
  else if (result.error) { console.error('audit error:', result.error); }
  else {
    console.log(`\n🔐 vibetesting-agent audit (npm audit)\n`);
    for (const sev of ['critical', 'high', 'moderate', 'low', 'info']) console.log(`  ${sev}: ${result.counts[sev] ?? 0}`);
    console.log(`\n${result.total} total advisories\n`);
  }
  process.exit(result.error ? 2 : failsAtLevel(result, level) ? 1 : 0);
}

// #34 — sync findings to a GitHub repo's issue tracker via the `gh` CLI. Idempotent: matches existing
// issues by the vta-key marker, opens new ones, refreshes matched ones, and closes ones that now pass.
// Dry-run by default; only writes when apply=true.
function syncGithubIssues(repo: string, findings: Finding[], target: string, apply: boolean): void {
  const gh = (args: string[], input?: string): string => {
    try { return execFileSync('gh', args, { encoding: 'utf8', input, stdio: ['pipe', 'pipe', 'pipe'] }); }
    catch (e: any) { throw new Error(`gh ${args.slice(0, 2).join(' ')} failed: ${String(e?.stderr || e?.message || e)}`); }
  };
  let existing: ExistingIssue[] = [];
  try {
    const raw = gh(['issue', 'list', '--repo', repo, '--label', 'vta', '--state', 'all', '--limit', '500', '--json', 'number,state,body']);
    existing = (JSON.parse(raw) as { number: number; state: string; body: string }[])
      .map((i) => ({ number: i.number, state: i.state.toLowerCase() === 'closed' ? 'closed' as const : 'open' as const, key: keyFromBody(i.body || '') || '' }))
      .filter((i) => i.key);
  } catch (e) { console.error(`⚠️  could not list existing issues (${String((e as Error).message)}); planning against none`); }

  const plan = planIssueActions(findings, { target, existing });
  console.error(`🔖 GitHub issue feed for ${repo}: ${summarizeActions(plan)}${apply ? '' : '  (dry-run — pass --apply to write)'}`);
  if (!apply) {
    for (const s of plan.toOpen) console.error(`   + open   ${s.title}`);
    for (const u of plan.toUpdate) console.error(`   ~ update #${u.number} ${u.spec.title}`);
    for (const c of plan.toClose) console.error(`   - close  #${c.number} (${c.key})`);
    return;
  }
  for (const s of plan.toOpen) {
    try { gh(['issue', 'create', '--repo', repo, '--title', s.title, '--body-file', '-', '--label', s.labels.join(',')], s.body); }
    catch (e) { console.error(`   open failed: ${String((e as Error).message)}`); }
  }
  for (const u of plan.toUpdate) {
    try { gh(['issue', 'edit', String(u.number), '--repo', repo, '--body-file', '-'], u.spec.body); }
    catch (e) { console.error(`   update #${u.number} failed: ${String((e as Error).message)}`); }
  }
  for (const c of plan.toClose) {
    try { gh(['issue', 'close', String(c.number), '--repo', repo, '--comment', 'Resolved — this check now passes on the latest VibeTesting Agent scan.']); }
    catch (e) { console.error(`   close #${c.number} failed: ${String((e as Error).message)}`); }
  }
  console.error(`   done: opened ${plan.toOpen.length}, updated ${plan.toUpdate.length}, closed ${plan.toClose.length}`);
}

const failGate = (findings: Finding[], failOn: 'high' | 'medium' | 'any'): boolean => {
  const gate = findings.filter((f) => !f.pass);
  const h = gate.filter((f) => f.severity === 'high').length;
  const m = gate.filter((f) => f.severity === 'medium').length;
  return failOn === 'any' ? gate.length > 0 : failOn === 'medium' ? h + m > 0 : h > 0;
};

/** Scan a list of URLs (from --urls or --crawl) and aggregate — combined non-zero exit if any fails. */
async function runBatch(targets: string[], opts: ScanOptions, o: { failOn: 'high' | 'medium' | 'any'; quiet: boolean; json: boolean }) {
  const rows = [];
  let anyFail = false;
  for (const url of targets) {
    const findings = await probe(url, opts);
    const failed = failGate(findings, o.failOn);
    if (failed) anyFail = true;
    rows.push({ url, summary: summarize(findings), failed, findings });
  }
  if (o.json) {
    console.log(JSON.stringify(rows.map((r) => ({ url: r.url, summary: r.summary, failed: r.failed })), null, 2));
  } else {
    console.log(`\n🔬 vibetesting-agent — scanned ${targets.length} URL(s)\n`);
    for (const r of rows) {
      const s = r.summary;
      console.log(`${r.failed ? '🟥' : '✅'} ${r.url} — ${s.passed} passed, ${s.failed} failed  (🟥 ${s.failHigh} · 🟧 ${s.failMedium} · 🟨 ${s.failLow})`);
      if (!o.quiet) for (const f of r.findings.filter((x) => !x.pass)) console.log(`     ${SEV_ICON[f.severity]} [${f.category}] ${f.title}`);
    }
    console.log('');
  }
  process.exit(anyFail ? 1 : 0);
}

// ACTIVE recon subcommand — opt-in, authorization-gated, CDN-guarded. Identify only (no exploitation).
async function runRecon() {
  const target = process.argv[3];
  if (!target || target.startsWith('-')) {
    console.error('usage: vibetesting-agent recon <host|url> --yes-i-am-authorized [--ports common|all|top1000|22,80,...] [--cve] [--force] [--timeout <ms>] [--json]');
    process.exit(2); return;
  }
  if (!flag('--yes-i-am-authorized')) {
    console.error('⚠️  Active reconnaissance (port scanning) sends real connections to the target.\n' +
      '    Only run against systems you OWN or are explicitly AUTHORIZED to test — unauthorized scanning may be illegal.\n' +
      '    This is IDENTIFY-ONLY: no exploitation, no DoS/flooding, no credential brute-forcing.\n' +
      '    Re-run with --yes-i-am-authorized to confirm authorization.');
    process.exit(2); return;
  }
  let host: string;
  try { host = new URL(normalizeUrl(target)).hostname; } catch { console.error(`invalid target: ${target}`); process.exit(2); return; }

  // CDN guard: the resolved IPs of a CDN-fronted host are the edge, not the origin — scanning them scans
  // the CDN (a third party). Refuse unless --force.
  const probeRes = await fetch(normalizeUrl(target), { redirect: 'manual' }).catch(() => null);
  const edge = probeRes ? identifyEdge(probeRes.headers) : { providers: [], behindCdn: false };
  if (edge.behindCdn && !flag('--force')) {
    console.error(`🛑 ${host} is served via ${edge.providers.join('/')} (a CDN/edge). Its resolved IPs are ${edge.providers.join('/')} nodes,\n` +
      `    not your origin — scanning them scans ${edge.providers.join('/')}'s infrastructure (and likely breaks their ToS).\n` +
      `    Scan your origin's real IP directly instead. Override with --force ONLY if you're authorized to scan these IPs.`);
    process.exit(2); return;
  }

  const ports = parsePorts(arg('--ports'));
  const tRaw = arg('--timeout');
  const timeoutMs = tRaw && Number(tRaw) > 0 ? Number(tRaw) : undefined;
  console.error(`scanning ${host} — ${ports.length} port(s)${edge.behindCdn ? ' (forced, note: CDN edge)' : ''}…`);
  const result = await recon(host, ports, { timeoutMs });

  // --cve: correlate each identified service version against NVD (sequential — respects NVD rate limit).
  const cveByPort: Record<number, any[]> = {};
  if (flag('--cve')) {
    for (const p of result.open) {
      if (p.product && p.version) {
        cveByPort[p.port] = await lookupCves(p.product, p.version, { max: 5 });
        await new Promise((r) => setTimeout(r, 700));
      }
    }
  }

  if (flag('--json')) {
    (result as any).cves = cveByPort;
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`\n🖥️  recon ${host}  (${result.ips.join(', ') || 'no A record'}) — ${result.open.length} open of ${result.scanned} scanned\n`);
    for (const p of result.open) {
      const s = p.service;
      const icon = s ? SEV_ICON[s.severity] : 'ℹ️ ';
      console.log(`  ${icon} ${p.port}/tcp  ${s ? s.name : 'open'}${s?.note ? ` — ${s.note}` : ''}`);
      if (p.product || p.version) {
        const idn = [p.product, p.version].filter(Boolean).join(' ');
        const hits = cveByPort[p.port];
        if (hits && hits.length) {
          console.log(`        identified: ${idn} — ${hits.length} known CVE(s):`);
          for (const c of hits) console.log(`          • ${c.id}${c.severity ? ` [${c.severity}]` : ''}: ${c.summary}`);
        } else if (flag('--cve')) {
          console.log(`        identified: ${idn} — no CVEs matched (or NVD rate-limited; retry, or use \`vibetesting-agent cve ${idn}\`)`);
        } else {
          console.log(`        identified: ${idn}${p.version ? `  ↳ add --cve to check NVD (or see nvd.nist.gov)` : ''}`);
        }
      }
      if (p.banner) console.log(`        banner: ${p.banner}`);
    }
    if (!result.open.length) console.log('  (no open ports found)');
    console.log('');
  }
  process.exit(result.open.some((p) => p.service?.severity === 'high') ? 1 : 0);
}

// OPT-IN browser-functional mode (needs playwright-core): JS errors, broken images, failed requests,
// forms accepting input — across pages. Catches aberrant behaviour a fetch scan can't see.
async function runBrowse() {
  const target = process.argv[3];
  if (!target || target.startsWith('-')) { console.error('usage: vibetesting-agent browse <url> [--pages N] [--timeout ms] [--json] [--quiet]  (needs: npm i -D playwright-core)'); process.exit(2); return; }
  const { browseChecks } = await import('./browse.js');
  const url = normalizeUrl(target);
  const pagesRaw = arg('--pages');
  const tRaw = arg('--timeout');
  const findings = await browseChecks(url, {
    pages: pagesRaw && Number(pagesRaw) > 0 ? Number(pagesRaw) : 1,
    timeoutMs: tRaw && Number(tRaw) > 0 ? Number(tRaw) : undefined,
    headers: withCfBypassHeaders(url),
  });
  const sum = summarize(findings);
  if (flag('--json')) { console.log(JSON.stringify({ url, summary: sum, findings }, null, 2)); }
  else {
    const quiet = flag('--quiet');
    console.log(`\n🖥️  vibetesting-agent browse — functional check of ${url}\n`);
    for (const fnd of findings) {
      if (quiet && fnd.pass) continue;
      console.log(`  ${fnd.pass ? '✅' : SEV_ICON[fnd.severity]} [${fnd.severity.toUpperCase()}] ${fnd.title}`);
      console.log(`        ${fnd.detail}`);
      if (!fnd.pass && fnd.fix) console.log(`        ↳ fix: ${fnd.fix}`);
    }
    console.log(`\n${sum.passed} passed, ${sum.failed} failed  (🟥 ${sum.failHigh} · 🟧 ${sum.failMedium} · 🟨 ${sum.failLow})\n`);
  }
  process.exit(findings.some((fnd) => !fnd.pass && fnd.severity === 'high') ? 1 : 0);
}

// Standalone CVE lookup for a product + version (reads NVD; informational only).
async function runCve() {
  const product = process.argv[3];
  const version = process.argv[4];
  if (!product || product.startsWith('-')) { console.error('usage: vibetesting-agent cve <product> [version]   e.g. vibetesting-agent cve OpenSSH 7.4'); process.exit(2); return; }
  const hits = await lookupCves(product, version || '', { max: 10 });
  if (flag('--json')) { console.log(JSON.stringify(hits, null, 2)); }
  else {
    console.log(`\n🔎 NVD CVEs for "${product}${version ? ' ' + version : ''}" — ${hits.length} result(s)\n`);
    for (const c of hits) console.log(`  • ${c.id}${c.severity ? ` [${c.severity}]` : ''}: ${c.summary}`);
    if (!hits.length) console.log('  (none matched — try a different version string, or NVD may be rate-limiting)');
    console.log('');
  }
  process.exit(hits.some((c) => c.severity === 'CRITICAL' || c.severity === 'HIGH') ? 1 : 0);
}

// "Extra batteries" separation-of-accounts test (needs playwright-core + Chrome + a two-account config).
async function runSeparation() {
  const configPath = process.argv[3];
  if (!configPath || configPath.startsWith('-')) {
    console.error('usage: vibetesting-agent separation <config.json>   (needs: npm i -D playwright-core, + two logged-in Chrome profiles)\n       config: { origin, tenantParam, chromeProfilesDir, appPaths, owner{label,chromeProfile,tenant}, attacker{...}, endpoints[{name,match}] }');
    process.exit(2); return;
  }
  const { runSeparation: run } = await import('./separation.js');
  let cfg: any;
  try { cfg = JSON.parse(readFileSync(configPath, 'utf8')); }
  catch (e) { console.error(`could not read config ${configPath}: ${String((e as any)?.message || e)}`); process.exit(2); return; }
  console.error('⚠️  READ-ONLY separation test — drives your two Chrome profiles; never submits forms or mutates data.');
  console.error(`   Open ${cfg.origin} in both profiles first so their sessions are fresh, then this runs.\n`);
  let results: any[];
  try { results = await run(cfg); }
  catch (e) { console.error('separation error:', String((e as any)?.message || e)); process.exit(2); return; }

  const ICON: Record<string, string> = { isolated: '✅', leak: '🟥', inspect: '⚠️ ', inconclusive: '⚪' };
  if (flag('--json')) { console.log(JSON.stringify({ origin: cfg.origin, owner: cfg.owner.label, attacker: cfg.attacker.label, results }, null, 2)); }
  else {
    console.log(`\n🔐 separation-of-accounts — ${cfg.attacker.label} attempting ${cfg.owner.label}'s data on ${cfg.origin}\n`);
    for (const r of results) {
      console.log(`  ${ICON[r.verdict] || '·'} ${r.verdict.toUpperCase().padEnd(12)} ${r.name} — ${r.reason}`);
      console.log(`        statuses: owner ${r.statuses.baseline ?? '—'} · attacker→owner ${r.statuses.attack ?? '—'} · attacker→own ${r.statuses.control ?? '—'}`);
    }
    const leaks = results.filter((r) => r.verdict === 'leak').length;
    const incon = results.filter((r) => r.verdict === 'inconclusive').length;
    console.log(`\n${leaks ? '🟥' : '✅'} ${results.length - leaks} isolated · ${leaks} leak(s)${incon ? ` · ${incon} inconclusive (refresh both sessions & retry)` : ''}.\n`);
  }
  process.exit(results.some((r) => r.verdict === 'leak') ? 1 : 0);
}


// Dynamic Business CMS critical-path suite (auth/API dogfood). Missing creds SKIP, never false-fail.
async function runDbCritical() {
  const target = process.argv[3];
  if (!target || target.startsWith('-')) {
    console.error('usage: vibetesting-agent db-critical <url> [--json] [--quiet] [--timeout ms]\n       Env: VTA_EDITOR_EMAIL/PASSWORD, VTA_SUPERADMIN_EMAIL/PASSWORD, optional VTA_USER_*, VTA_TOTP_SECRET,\n            VTA_UNPUBLISHED_ARTICLE_URL, VTA_STRIPE_AMOUNT_PROBE=1, CF_SMOKE_KEY (see examples/db-critical-path/)');
    process.exit(2); return;
  }
  const { runDbCritical: run } = await import('./db-critical.js');
  const url = normalizeUrl(target);
  const tRaw = arg('--timeout');
  const findings = await run(url, { timeoutMs: tRaw && Number(tRaw) > 0 ? Number(tRaw) : undefined });
  const sum = summarize(findings);
  if (flag('--json')) { console.log(JSON.stringify({ url, summary: sum, findings }, null, 2)); }
  else {
    const quiet = flag('--quiet');
    console.log(`\n📰 vibetesting-agent db-critical — Dynamic Business CMS critical path on ${url}\n`);
    for (const fnd of findings) {
      if (quiet && fnd.pass) continue;
      const skipped = fnd.pass && /^SKIP:/i.test(fnd.detail);
      console.log(`  ${fnd.pass ? (skipped ? '⏭ ' : '✅') : SEV_ICON[fnd.severity]} [${fnd.severity.toUpperCase()}] ${fnd.title}`);
      console.log(`        ${fnd.detail}`);
      if (!fnd.pass && fnd.fix) console.log(`        ↳ fix: ${fnd.fix}`);
    }
    const skips = findings.filter((fnd) => fnd.pass && /^SKIP:/i.test(fnd.detail)).length;
    console.log(`\n${sum.passed} passed (${skips} skipped), ${sum.failed} failed  (🟥 ${sum.failHigh} · 🟧 ${sum.failMedium} · 🟨 ${sum.failLow})\n`);
  }
  // Skips are passes — only real failures (esp. high) gate exit.
  process.exit(findings.some((fnd) => !fnd.pass && (fnd.severity === 'high' || fnd.severity === 'medium')) ? 1 : 0);
}

// "Extra batteries" deep browser crawl + SAFE audit (needs playwright-core + Chrome).
async function runCrawl() {
  const target = process.argv[3];
  if (!target || target.startsWith('-')) {
    console.error('usage: vibetesting-agent crawl <url> [--profile "Profile 3"] [--cookie "<raw>"] [--pages 30] [--report f.html] [--pdf f.pdf]\n       (needs: npm i -D playwright-core; --profile reuses a logged-in Chrome profile. SAFE: GET-only, never submits create/edit/delete.)');
    process.exit(2); return;
  }
  const url = normalizeUrl(target);
  const { crawlAudit } = await import('./crawl.js');
  const pagesRaw = arg('--pages');
  console.error('⚠️  Browser crawl — GET navigation + read-only search fuzz only; never submits mutating forms.');
  const findings = await crawlAudit(url, {
    maxPages: pagesRaw && Number(pagesRaw) > 0 ? Number(pagesRaw) : 30,
    chromeProfile: arg('--profile'),
    cookie: arg('--cookie'),
  });
  const pages = (findings as any).pagesVisited || [];
  const sum = summarize(findings);

  const reportPath = arg('--report'); const pdfPath = arg('--pdf');
  if (reportPath || pdfPath) {
    const { renderReport } = await import('./report.js');
    const html = renderReport(`${url} — browser crawl (${pages.length} pages)`, findings);
    if (reportPath) { writeFileSync(reportPath, html); console.error(`📄 wrote ${reportPath}`); }
    if (pdfPath) {
      try {
        const { chromium } = await import('playwright-core');
        const b = await chromium.launch({ channel: 'chrome', headless: true }).catch(() => chromium.launch({ headless: true }));
        const p = await b.newPage(); await p.setContent(html, { waitUntil: 'load' });
        await p.pdf({ path: pdfPath, format: 'A4', printBackground: true, margin: { top: '14mm', bottom: '14mm', left: '12mm', right: '12mm' } });
        await b.close(); console.error(`📄 wrote ${pdfPath}`);
      } catch (e) { console.error(`--pdf: ${String((e as any)?.message || e)}`); }
    }
  }

  if (flag('--json')) { console.log(JSON.stringify({ url, pagesVisited: pages, summary: sum, findings }, null, 2)); }
  else {
    console.log(`\n🕷️  vibetesting-agent crawl — ${pages.length} page(s) of ${url}\n`);
    for (const fn of findings.filter((x) => !x.pass)) {
      console.log(`  ${SEV_ICON[fn.severity]} [${fn.category}] ${fn.title}`);
      console.log(`        ${fn.detail}`);
      if (fn.fix) console.log(`        ↳ fix: ${fn.fix}`);
    }
    if (!findings.some((x) => !x.pass)) console.log('  no functional/fuzz issues found on the reachable pages.');
    console.log(`\n  pages: ${pages.join(', ') || '(none reached — session may be stale)'}\n`);
  }
  process.exit(findings.some((fn) => !fn.pass && fn.severity === 'high') ? 1 : 0);
}

async function runInit() {
  const rawUrl = process.argv[3];
  if (!rawUrl || rawUrl.startsWith('-')) {
    console.error('usage: vibetesting-agent init <url> [--name <project>] [--cwd <dir>] [--force]');
    process.exit(2);
  }
  const url = normalizeUrl(rawUrl);
  const cwd = arg('--cwd') || process.cwd();
  const name = arg('--name');
  console.error(`🔬 init: scanning ${url} …`);
  let findings: Finding[] = [];
  try {
    findings = await probe(url, { timeoutMs: 15_000, maxCrawl: 15 });
  } catch (e) {
    console.error(`scan failed (scaffolding empty templates): ${String((e as Error)?.message || e)}`);
  }
  const result = initRepo({
    cwd,
    url,
    projectName: name,
    findings,
    force: flag('--force'),
  });
  for (const p of result.written) console.log(`  wrote ${p}`);
  for (const p of result.skipped) console.log(`  skip  ${p} (exists; use --force)`);
  console.log(`\nNext: open security-review.md · wire CI · re-run after deploys with:`);
  console.log(`  npx github:newsengine/vibetesting-agent review ${url}`);
  process.exit(0);
}

/** /security-review workflow: full scan + agent markdown + gherkin feature. */
async function runReview() {
  // Rewrite argv so main scan path sees: <url> --agent-report … --gherkin …
  const rest = process.argv.slice(3);
  const rawUrl = rest.find((a) => a && !a.startsWith('-'));
  if (!rawUrl) {
    console.error('usage: vibetesting-agent review <url> [--name <project>] [--fail-on high|medium|any] [same flags as scan]');
    process.exit(2);
  }
  const name = arg('--name');
  const agentOut = arg('--agent-report') || 'security-review.md';
  const gherkinOut = arg('--gherkin') || 'features/security/hygiene.feature';
  // Inject defaults if user didn't pass them
  if (!arg('--agent-report')) process.argv.push('--agent-report', agentOut);
  if (!arg('--gherkin')) process.argv.push('--gherkin', gherkinOut);
  if (name && !process.argv.includes('--project-name')) process.argv.push('--project-name', name);
  // Drop the "review" token so position 2 is the URL
  process.argv.splice(2, 1);
  // fall through — caller invokes main body via re-entry
  return mainScan();
}

async function main() {
  if (process.argv[2] === 'audit') return runAudit();
  if (process.argv[2] === 'recon') return runRecon();
  if (process.argv[2] === 'browse') return runBrowse();
  if (process.argv[2] === 'cve') return runCve();
  if (process.argv[2] === 'separation') return runSeparation();
  if (process.argv[2] === 'db-critical') return runDbCritical();
  if (process.argv[2] === 'crawl') return runCrawl();
  if (process.argv[2] === 'init') return runInit();
  if (process.argv[2] === 'review') return runReview();
  return mainScan();
}

async function mainScan() {
  const cfgResult = loadConfig(arg('--config'));
  if (cfgResult.error) { console.error(cfgResult.error); process.exit(2); }
  const config = cfgResult.config;

  const rawUrl = process.argv[2];
  if (!rawUrl || rawUrl.startsWith('-')) {
    console.error('usage:\n  npx github:newsengine/vibetesting-agent <url> [--agent-report security-review.md] [--gherkin features/security/hygiene.feature] [--only ...] [--fail-on high|medium|any] [--report f.html] [--json]\n  npx github:newsengine/vibetesting-agent review <url>     # security-review: scan + agent report + gherkin\n  npx github:newsengine/vibetesting-agent init <url>       # scaffold suite into a new repo\n  npx github:newsengine/vibetesting-agent audit [--prod] [--level high]');
    process.exit(2);
  }
  const url = normalizeUrl(rawUrl); // accept bare domains (example.com -> https://example.com)
  try { new URL(url); } catch { console.error(`invalid URL: ${rawUrl}`); process.exit(2); }

  // Parse numeric flags defensively so a typo can't silently become NaN and disable the cap/timeout.
  const num = (name: string, dflt: number): number => {
    const raw = arg(name);
    if (raw === undefined) return dflt;
    const n = Number(raw);
    if (!Number.isFinite(n) || n <= 0) { console.error(`${name} must be a positive number (got "${raw}")`); process.exit(2); }
    return n;
  };

  // Auth for scanning behind login: --cookie "<raw cookie header>" and/or repeatable --header "K: V".
  // These are sent ONLY on same-origin requests (see ScanOptions.extraHeaders).
  const extraHeaders: Record<string, string> = {};
  const cookie = arg('--cookie');
  if (cookie) extraHeaders['cookie'] = cookie;
  for (let i = 0; i < process.argv.length; i++) {
    if (process.argv[i] === '--header') {
      const raw = process.argv[i + 1] || '';
      const idx = raw.indexOf(':');
      if (idx > 0) extraHeaders[raw.slice(0, idx).trim().toLowerCase()] = raw.slice(idx + 1).trim();
      else { console.error(`--header must be "Name: value" (got "${raw}")`); process.exit(2); }
    }
  }
  // Cloudflare bot / Access bypass from env (CF_SMOKE_KEY + beta Access token).
  // CLI --header/--cookie still win on key collision via withCfBypassHeaders.
  const mergedHeaders = withCfBypassHeaders(url, Object.keys(extraHeaders).length ? extraHeaders : undefined);

  // Options: CLI flags win, else fall back to .analproberc.json.
  const opts: ScanOptions = {
    only: list(arg('--only')) ?? (config.only as Category[] | undefined),
    skip: list(arg('--skip')) ?? (config.skip as Category[] | undefined),
    corsTestPath: arg('--cors-path') ?? config.corsPath,
    rateLimitPath: arg('--rate-limit-path') ?? config.rateLimitPath,
    allowReportOnlyCsp: flag('--allow-report-only-csp') || !!config.allowReportOnlyCsp,
    maxCrawl: arg('--max-crawl') ? num('--max-crawl', 25) : config.maxCrawl,
    timeoutMs: arg('--timeout') ? num('--timeout', 10_000) : config.timeoutMs,
    pluginsDir: arg('--plugins') ?? config.pluginsDir,
    extraHeaders: mergedHeaders,
    apiWrite: flag('--api-write') || !!config.apiWrite,
    rateLimitScan: flag('--rate-limit-scan') || !!config.rateLimitScan,
    reflectedXss: flag('--xss') || !!config.reflectedXss,
    aiProbe: flag('--ai-probe') || !!config.aiProbe,
    authorizedActive: flag('--authorized-active'),
    authorizedGap: flag('--authorized-gap') || flag('--authorized-active'),
    repoPath: arg('--repo'),
  };
  const failOn = (arg('--fail-on') ?? config.failOn ?? 'high') as 'high' | 'medium' | 'any';
  const quiet = flag('--quiet') || !!config.quiet;

  // Batch mode: --urls <file> (one URL per line) or --crawl <N> (homepage + N same-origin pages).
  const urlsFile = arg('--urls');
  const crawlN = arg('--crawl') ? num('--crawl', 0) : config.crawl;
  if (urlsFile) {
    let targets: string[] = [];
    try { targets = readFileSync(urlsFile, 'utf8').split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith('#')).map(normalizeUrl); }
    catch (e) { console.error(`could not read --urls ${urlsFile}: ${String((e as any)?.message || e)}`); process.exit(2); }
    if (!targets.length) { console.error(`--urls ${urlsFile} contains no URLs`); process.exit(2); }
    return runBatch(targets, opts, { failOn, quiet, json: flag('--json') }); // batch even for a single listed URL
  }
  if (crawlN) {
    const targets = [url, ...await discoverPages(url, crawlN, opts)];
    if (targets.length > 1) return runBatch(targets, opts, { failOn, quiet, json: flag('--json') });
    // only the homepage was found — fall through to the normal single-URL flow below
  }

  const startedAt = new Date().toISOString();
  const findings = await probe(url, opts);

  // #43 — active injection engine (opt-in + authorized, non-destructive). Merged into findings so it flows
  // through the record/report/issue-feed like any other check.
  if (opts.authorizedGap && !opts.authorizedActive) {
    console.error('⚠️  Authorized gap checks (login rate-limit, sequential IDOR, unsigned webhooks) send a few extra probes.\n' +
      '    Non-destructive and low-volume, but only run against targets you OWN or are AUTHORIZED to test.');
  }
  if (opts.authorizedActive) {
    console.error('⚠️  Active injection testing (SQLi/SSTI/cmd/traversal) sends crafted values to GET parameters.\n' +
      '    Non-destructive (no writes/DoS/brute-force), but only run against targets you OWN or are AUTHORIZED to test.');
    const ctx = { baseUrl: url, origin: new URL(url).origin, url: new URL(url), res: {} as Response, html: '', headers: new Headers(), opts } as unknown as import('./probe.js').ScanContext;
    try { findings.push(...await activeInjectionScan(ctx)); }
    catch (e) { console.error(`active injection error: ${String((e as Error)?.message || e)}`); }
  }
  const sum = summarize(findings);

  // Run record: every sub-test keyed by its VTA number — logged to the ledger database and used for the
  // Priority-Status report. Built for every scan; only persisted when --ledger is given.
  const record = buildRunRecord(findings, { target: url, actor: arg('--actor') || process.env.VTA_ACTOR || 'cli', startedAt });
  const ledgerPath = arg('--ledger');
  let previousRun: RunRecord | null = null;
  if (ledgerPath) {
    previousRun = readRuns(ledgerPath).filter((r) => r.target === url).slice(-1)[0] || null;
    const stored = appendRun(ledgerPath, record);
    record.runNumber = stored.runNumber;
    console.error(`🗂️  recorded run #${stored.runNumber} (${record.subTests.length} sub-tests, priority ${record.priority}) → ${ledgerPath}`);
  }
  // --priority: print the daily-report cover page (Priority Status first) before anything else.
  if (flag('--priority')) console.log(renderPriorityReport(record, previousRun));

  // --fix-pack <file.md>: PR-ready fixes (consolidated header config + per-finding checklist).
  const fixPackPath = arg('--fix-pack');
  if (fixPackPath) {
    writeFileSync(fixPackPath, renderFixPack(findings, { target: url, projectName: arg('--project-name') || arg('--name') }));
    console.error(`🛠️  wrote fix pack → ${fixPackPath}`);
  }

  // --github-issues <owner/repo>: feed findings into the issue tracker (idempotent; --apply to write).
  const issuesRepo = arg('--github-issues');
  if (issuesRepo) syncGithubIssues(issuesRepo, findings, url, flag('--apply'));

  // --coverage <file.json>: authenticated deep-crawl coverage map (endpoints/params/forms/apis).
  const coveragePath = arg('--coverage');
  if (coveragePath) {
    const map = await buildCoverageMap(url, {
      extraHeaders: opts.extraHeaders,
      maxPages: arg('--max-crawl') ? num('--max-crawl', 50) : (config.maxCrawl ?? 50),
      timeoutMs: opts.timeoutMs,
    });
    writeFileSync(coveragePath, JSON.stringify(map, null, 2));
    console.error(`🗺️  ${summarizeCoverage(map)} → ${coveragePath}`);
  }

  // --report <file.html> / --pdf <file.pdf>: a shareable table report (every check + result + fix +
  // standards). PDF renders the same HTML via the optional playwright-core battery.
  const reportPath = arg('--report');
  const pdfPath = arg('--pdf');
  if (reportPath || pdfPath) {
    const { renderReport } = await import('./report.js');
    const html = renderReport(url, findings);
    if (reportPath) { writeFileSync(reportPath, html); console.error(`📄 wrote HTML report → ${reportPath} (open it, then Print → Save as PDF)`); }
    if (pdfPath) {
      try {
        const { chromium } = await import('playwright-core');
        const browser = await chromium.launch({ channel: 'chrome', headless: true }).catch(() => chromium.launch({ headless: true }));
        const page = await browser.newPage();
        await page.setContent(html, { waitUntil: 'load' });
        await page.pdf({ path: pdfPath, format: 'A4', printBackground: true, margin: { top: '14mm', bottom: '14mm', left: '12mm', right: '12mm' } });
        await browser.close();
        console.error(`📄 wrote PDF report → ${pdfPath}`);
      } catch (e) {
        console.error(`--pdf needs playwright-core + Chrome/Chromium (npm i -D playwright-core): ${String((e as any)?.message || e)}`);
      }
    }
  }

  // --agent-report <file.md>: ranked P1/P2 Claude/Cursor security-review artifact
  const agentReportPath = arg('--agent-report');
  if (agentReportPath) {
    const md = renderAgentReport(findings, {
      url,
      projectName: arg('--project-name') || arg('--name'),
    });
    mkdirSync(dirname(agentReportPath), { recursive: true });
    writeFileSync(agentReportPath, md);
    console.error(`📝 wrote agent security review → ${agentReportPath}`);
  }

  // --gherkin <file.feature>: BDD scenarios for each finding (new-repo security suite)
  const gherkinPath = arg('--gherkin');
  if (gherkinPath) {
    const feature = renderGherkinFeature(findings, {
      url,
      projectName: arg('--project-name') || arg('--name'),
      tags: true,
    });
    mkdirSync(dirname(gherkinPath), { recursive: true });
    writeFileSync(gherkinPath, feature);
    console.error(`🥒 wrote Gherkin feature → ${gherkinPath}`);
  }

  // --write-baseline: snapshot today's failing findings and exit 0 (nothing to gate on the first run).
  const writeBaselinePath = arg('--write-baseline');
  if (writeBaselinePath) {
    const baseline = buildBaseline(findings, url);
    writeFileSync(writeBaselinePath, JSON.stringify(baseline, null, 2) + '\n');
    console.error(`wrote baseline (${baseline.keys.length} finding(s)) to ${writeBaselinePath}`);
    process.exit(0);
  }

  // --baseline: partition failing findings into new (gate on these) vs already-accepted.
  const baselinePath = arg('--baseline');
  let diff: { newFailures: Finding[]; baselined: Finding[] } | null = null;
  if (baselinePath) {
    let baseline: Baseline = { keys: [] };
    try { baseline = JSON.parse(readFileSync(baselinePath, 'utf8')); }
    catch (e) { console.error(`could not read baseline ${baselinePath}: ${String((e as any)?.message || e)}`); process.exit(2); }
    diff = applyBaseline(findings, baseline);
  }

  // The set CI actually gates on: new-only when a baseline is in play, otherwise every failure.
  const gateFails = diff ? diff.newFailures : findings.filter((f) => !f.pass);

  if (flag('--sarif')) {
    // Report new-only under a baseline so the Security tab shows regressions, not accepted debt.
    console.log(JSON.stringify(toSarif(diff ? diff.newFailures : findings, { url, version: VERSION }), null, 2));
  } else if (flag('--json')) {
    const withStd = flag('--compliance') ? findings.map((f) => ({ ...f, standards: refsFor(f.id) })) : findings;
    const compliance = flag('--compliance') ? { asvsL1: asvsCoverage(findings), owaspTop10: owaspTop10Hit(findings), owaspApiTop10: apiTop10Hit(findings), cwe: cwesHit(findings), securityGrade: securityGrade(findings), tlsGrade: tlsGrade(findings) } : undefined;
    console.log(JSON.stringify({ url, summary: sum, findings: withStd, ...(compliance ? { compliance } : {}), ...(diff ? { baseline: { new: diff.newFailures.length, accepted: diff.baselined.length } } : {}) }, null, 2));
  } else {
    // --quiet: show only failures (good for CI logs); default shows passes too so a clean scan is visible.
    console.log(`\n🔬 vibetesting-agent — full app scan of ${url}${mergedHeaders ? ' (authenticated)' : ''}\n`);
    for (const cat of ALL_CATEGORIES) {
      const group = findings.filter((f) => f.category === cat);
      if (!group.length) continue;
      const failed = group.filter((g) => !g.pass).length;
      if (quiet && !failed) continue;
      console.log(`${CAT_TITLE[cat]}  ${failed ? `— ${failed} issue(s)` : '— ok'}`);
      for (const f of group as Finding[]) {
        if (quiet && f.pass) continue;
        const mark = f.pass ? '  ✅' : `  ${SEV_ICON[f.severity]}`;
        console.log(`${mark} [${f.severity.toUpperCase()}] ${f.title}`);
        console.log(`        ${f.detail}`);
        if (!f.pass && f.fix) console.log(`        ↳ fix: ${f.fix}`);
      }
      console.log('');
    }
    console.log(`${sum.passed} passed, ${sum.failed} failed  (🟥 ${sum.failHigh} high · 🟧 ${sum.failMedium} medium · 🟨 ${sum.failLow} low)`);
    if (diff) console.log(`baseline: ${diff.newFailures.length} new · ${diff.baselined.length} accepted`);
    console.log('');

    if (flag('--compliance')) {
      const cov = asvsCoverage(findings);
      const n = (s: string) => cov.filter((r) => r.status === s).length;
      const ICON: Record<string, string> = { pass: '✅', fail: '🟥', 'not-observed': '⚪', 'not-covered': '➖' };
      console.log('📋 OWASP ASVS 4.0.3 — Level 1 (black-box subset)');
      console.log(`   ${n('pass')} pass · ${n('fail')} fail · ${n('not-observed')} not-observed · ${n('not-covered')} not-covered  (of ${cov.length})`);
      for (const r of cov) console.log(`   ${ICON[r.status]} ${r.id}  ${r.text}`);
      const grade = securityGrade(findings);
      console.log(`\n🏅 Scorecard — security grade ${grade.grade} (${grade.score}/100) · TLS grade ${tlsGrade(findings)}`);

      const hits = owaspTop10Hit(findings);
      const keys = Object.keys(hits).sort();
      console.log(`\n🔟 OWASP Top 10 (2021) — categories with open issues`);
      if (!keys.length) console.log('   none');
      for (const k of keys) console.log(`   ${k} ${OWASP_TOP10_NAMES[k]} — ${hits[k]} issue(s)`);

      const api = apiTop10Hit(findings);
      const apiKeys = Object.keys(api).sort();
      if (apiKeys.length) {
        console.log(`\n🔌 OWASP API Security Top 10 (2023) — categories with open issues`);
        for (const k of apiKeys) console.log(`   ${k} ${OWASP_API_TOP10_NAMES[k]} — ${api[k]} issue(s)`);
      }

      const cwes = cwesHit(findings);
      if (cwes.length) console.log(`\n🏷️  CWE weaknesses flagged: ${cwes.join(', ')}`);
      console.log('');
    }
  }

  const gHigh = gateFails.filter((f) => f.severity === 'high').length;
  const gMed = gateFails.filter((f) => f.severity === 'medium').length;
  const shouldFail =
    failOn === 'any' ? gateFails.length > 0 :
    failOn === 'medium' ? gHigh + gMed > 0 :
    gHigh > 0;
  process.exit(shouldFail ? 1 : 0);
}

main().catch((e) => { console.error('probe error:', e); process.exit(2); });

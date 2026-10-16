import Link from 'next/link';
import { PLANS, TEST_CATALOG, SUITE_STATS, EXTRA_MODES, LITE_CATEGORIES } from '@/lib/plans';
import { LiteScanBox } from '@/components/forms';
import { config } from '@/lib/config';
import { COMPANY, providedByLine } from '@/lib/company';
import { getTestsByCategory, getTestCount, CATEGORY_LABELS } from '@/lib/test-list';

function FullTestList() {
  const testsByCategory = getTestsByCategory();
  const totalCount = getTestCount();
  const categories = Object.keys(testsByCategory).sort();

  return (
    <div className="mt-12 rounded-xl border border-[var(--edge)] bg-black/20 p-6">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="mono text-lg font-bold">Complete test catalog</h3>
          <p className="text-sm text-[var(--mut)]">{totalCount} tests across {categories.length} categories</p>
        </div>
      </div>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {categories.map((category) => (
          <div key={category} className="rounded-lg border border-[var(--edge)] bg-black/30 p-4">
            <div className="mono mb-2 text-xs font-semibold uppercase tracking-wider text-[var(--lime)]">
              {CATEGORY_LABELS[category] || category}
            </div>
            <ul className="space-y-1 text-xs text-[var(--mut)]">
              {testsByCategory[category].slice(0, 15).map((name, i) => (
                <li key={i} className="truncate">{name}</li>
              ))}
              {testsByCategory[category].length > 15 && (
                <li className="text-[var(--md)]">+{testsByCategory[category].length - 15} more</li>
              )}
            </ul>
          </div>
        ))}
      </div>
      <p className="mt-4 text-xs text-[var(--mut)]">
        This list is auto-generated from <code className="text-[var(--ink)]">src/catalog.ts</code> —
        the single source of truth for all checks. See{' '}
        <Link href="/docs/coverage" className="text-[var(--lime)] hover:underline">
          full coverage docs
        </Link>{' '}
        for details on each check.
      </p>
    </div>
  );
}

export default function HomePage() {
  const paid = [PLANS.weekly, PLANS.daily, PLANS.commit];

  return (
    <div className="relative overflow-x-hidden">
      <div className="pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(1000px_560px_at_80%_-10%,rgba(169,239,79,.12),transparent_55%),radial-gradient(700px_500px_at_0%_40%,rgba(80,140,255,.06),transparent_50%),radial-gradient(600px_400px_at_50%_100%,rgba(60,120,80,.12),transparent_55%)]" />

      <nav className="sticky top-0 z-30 border-b border-[var(--edge)] bg-[var(--bg)]/85 backdrop-blur-md">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-5">
          <Link href="/" className="mono flex items-center gap-2 font-extrabold tracking-tight">
            <span className="h-2.5 w-2.5 rounded-full bg-[var(--lime)] shadow-[0_0_14px_var(--lime)]" />
            VibeTesting Agent
          </Link>
          <div className="flex items-center gap-4 text-sm">
            <a href="#tests" className="hidden text-[var(--mut)] hover:text-[var(--lime)] sm:inline">
              Tests
            </a>
            <Link href="/docs/coverage" className="hidden text-[var(--mut)] hover:text-[var(--lime)] sm:inline">
              Coverage
            </Link>
            <a href="#pricing" className="hidden text-[var(--mut)] hover:text-[var(--lime)] sm:inline">
              Pricing
            </a>
            <a
              href={config.ossRepo}
              className="hidden text-[var(--mut)] hover:text-[var(--lime)] sm:inline"
              target="_blank"
              rel="noreferrer"
            >
              Open source
            </a>
            <Link href="/login" className="btn-primary !py-2 !px-4 text-xs">
              Dashboard
            </Link>
          </div>
        </div>
      </nav>

      <header className="mx-auto max-w-6xl px-5 pb-10 pt-16 sm:pt-20">
        <p className="mono mb-4 inline-flex items-center gap-2 rounded-full border border-[var(--edge)] px-3 py-1 text-[11px] uppercase tracking-[0.16em] text-[var(--lime)]">
          Security for vibe-coded apps · powered by vibetesting-agent
        </p>
        <h1 className="mono max-w-4xl text-4xl font-extrabold leading-[1.05] tracking-tight sm:text-6xl">
          Ship with vibe.
          <br />
          <span className="text-[var(--lime)]">
            Scan before <s className="opacity-70">customers</s> bad guys do.
          </span>
        </h1>
        <p className="mt-6 max-w-2xl text-lg text-[var(--mut)]">
          Continuous black-box security for AI-built software. Leaked keys, exposed{' '}
          <code className="text-[var(--ink)]">.env</code>, broken headers, framework footguns — ranked for
          agents with fix packs & Gherkin. Prove you own the app (domain email + inbox click, or DNS TXT).
          Then scan on a schedule or every commit.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <a href="#lite" className="btn-primary">
            Try free lite scan
          </a>
          <Link href="/login" className="btn-ghost">
            Sign in · WorkOS
          </Link>
        </div>
      </header>

      <section id="lite" className="mx-auto max-w-6xl px-5 pb-20">
        <LiteScanBox />
      </section>

      <section className="mx-auto max-w-6xl px-5 pb-20">
        <div className="grid gap-4 sm:grid-cols-3">
          {[
            [
              'Own it first',
              'Sign in with an email on the domain you are testing and click the inbox verify link — or place a DNS TXT record. No scanning other people’s apps.',
            ],
            ['Agent fix packs', 'Every finding becomes a ranked P1→Pn prompt for Claude / Cursor / Codex.'],
            ['Cadence that matches how you ship', 'Casual Coding · Business Prototyping · Mission Critical.'],
          ].map(([t, d]) => (
            <div key={t} className="panel p-5">
              <h3 className="mono font-bold text-[var(--lime)]">{t}</h3>
              <p className="mt-2 text-sm text-[var(--mut)]">{d}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="tests" className="mx-auto max-w-6xl px-5 pb-24">
        <div className="mb-8 max-w-3xl">
          <p className="mono text-xs uppercase tracking-[0.18em] text-[var(--lime)]">Full test suite</p>
          <h2 className="mono mt-2 text-3xl font-bold sm:text-4xl">
            {SUITE_STATS.ruleSurface}+ security rules.
            <br />
            <span className="text-[var(--lime)]">
              {SUITE_STATS.asvsL1Covered}/{SUITE_STATS.asvsL1Total} critical OWASP ASVS L1 checks covered.
            </span>
          </h2>
          <p className="mt-3 text-[var(--mut)]">
            <strong className="text-[var(--ink)]">{SUITE_STATS.blackBoxProbes}+ black-box probes</strong> across{' '}
            <strong className="text-[var(--ink)]">{SUITE_STATS.categories} categories</strong>, plus{' '}
            <strong className="text-[var(--ink)]">{SUITE_STATS.clientVulnRanges}+ client CVE ranges</strong> — mapped
            to OWASP Top 10, WSTG, and ASVS Level 1 for the risks you can verify from a URL (secrets, headers,
            TLS, exposure, misconfig). Not a toy checklist: the full engine evaluates {SUITE_STATS.ruleSurface}+
            rules every run. Lite samples four categories; paid fleet runs the complete suite.
          </p>
        </div>

        {/* Big honest stats */}
        <div className="mb-8 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          {[
            { n: `${SUITE_STATS.categories}`, l: 'Categories' },
            { n: `${SUITE_STATS.blackBoxProbes}+`, l: 'Black-box probes' },
            { n: `${SUITE_STATS.clientVulnRanges}+`, l: 'Client CVE ranges' },
            { n: `${SUITE_STATS.clientCveRefs}+`, l: 'CVE refs in feed' },
            { n: `${SUITE_STATS.exposurePaths}`, l: 'Exposure paths' },
            {
              n: `${SUITE_STATS.asvsL1Covered}/${SUITE_STATS.asvsL1Total}`,
              l: 'ASVS L1 (black-box)',
            },
          ].map((s) => (
            <div key={s.l} className="panel px-3 py-4 text-center">
              <div className="mono text-2xl font-extrabold text-[var(--lime)] sm:text-3xl">{s.n}</div>
              <div className="mt-1 text-[11px] uppercase tracking-wide text-[var(--mut)]">{s.l}</div>
            </div>
          ))}
        </div>

        <p className="mb-4 text-xs text-[var(--mut)]">
          <span className="mono rounded border border-[var(--lime)]/40 bg-[var(--lime)]/10 px-1.5 py-0.5 text-[var(--lime)]">
            lite
          </span>{' '}
          = included in free homepage scan ({LITE_CATEGORIES.length} categories, sampled). Full fleet +
          history needs ownership + a paid plan.
        </p>

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {TEST_CATALOG.map((t) => (
            <article
              key={t.id}
              className="panel group relative flex flex-col overflow-hidden p-5 transition hover:border-[var(--lime)]/50"
            >
              <div className="flex items-start justify-between gap-2">
                <span className="text-2xl" aria-hidden>
                  {t.icon}
                </span>
                <div className="flex flex-wrap items-center justify-end gap-1">
                  {t.lite && (
                    <span className="mono rounded border border-[var(--lime)]/40 bg-[var(--lime)]/10 px-1.5 py-0.5 text-[10px] uppercase text-[var(--lime)]">
                      lite
                    </span>
                  )}
                  <span className="mono rounded border border-[var(--edge)] px-2 py-0.5 text-[10px] uppercase text-[var(--mut)]">
                    {t.severity}
                  </span>
                </div>
              </div>
              <h3 className="mono mt-3 font-bold">{t.title}</h3>
              <p className="mt-1 mono text-[11px] text-[var(--lime)]">
                {t.probeCount > 0
                  ? t.id === 'components'
                    ? `${t.probeCount}+ version ranges`
                    : `${t.probeCount}+ probes`
                  : 'user-defined'}
                <span className="text-[var(--mut)]"> · {t.id}</span>
              </p>
              <p className="mt-2 text-sm leading-relaxed text-[var(--mut)]">{t.description}</p>
              <ul className="mt-3 flex flex-wrap gap-1.5">
                {t.samples.slice(0, 6).map((s) => (
                  <li
                    key={s}
                    className="mono rounded border border-[var(--edge)] bg-black/25 px-1.5 py-0.5 text-[10px] text-[var(--mut)]"
                  >
                    {s}
                  </li>
                ))}
                {t.samples.length > 6 && (
                  <li className="mono px-1.5 py-0.5 text-[10px] text-[var(--mut)]">
                    +{t.samples.length - 6} more
                  </li>
                )}
              </ul>
            </article>
          ))}
        </div>

        <div className="mt-10">
          <h3 className="mono text-lg font-bold">Beyond the default pass</h3>
          <p className="mt-1 max-w-2xl text-sm text-[var(--mut)]">
            Opt-in modes and white-box helpers — not silent &quot;we test everything&quot; claims. Active
            exploit fuzzing (SQLi/SSRF) stays out of scope on purpose.
          </p>
          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {EXTRA_MODES.map((m) => (
              <div key={m.id} className="panel p-4">
                <div className="mono text-xs uppercase tracking-wider text-[var(--md)]">{m.id}</div>
                <div className="mt-1 font-semibold">{m.title}</div>
                <p className="mt-1 text-sm text-[var(--mut)]">{m.detail}</p>
              </div>
            ))}
          </div>
        </div>

        <p className="mt-8 rounded-lg border border-[var(--edge)] bg-black/20 px-4 py-3 text-xs leading-relaxed text-[var(--mut)]">
          <strong className="text-[var(--ink)]">How we count (honestly):</strong> ~{SUITE_STATS.blackBoxProbes}+
          are discrete black-box probes in the engine. ~{SUITE_STATS.clientVulnRanges}+ are client-library
          version ranges ({SUITE_STATS.clientLibs} libs, {SUITE_STATS.clientCveRefs}+ CVE refs) matched when
          those libraries appear on the page. A single full scan often emits 40–120 findings depending on the
          target; crawl/recon modes add more. We do <em>not</em> claim &quot;1,000 tests&quot; as fixed
          checkboxes — that would be inflated. The surface is large because of rules + dynamic coverage, not
          fake line items.
        </p>

        {/* Full test list - derived from catalog */}
        <FullTestList />
      </section>

      <section id="pricing" className="mx-auto max-w-6xl px-5 pb-24">
        <p className="mono text-xs uppercase tracking-[0.18em] text-[var(--lime)]">Pricing</p>
        <h2 className="mono mt-2 text-3xl font-bold">Hosted plans</h2>
        <p className="mt-2 max-w-xl text-[var(--mut)]">
          Open-source CLI is free forever. Hosted plans add ownership verification, dashboard, cadence, and
          commit hooks.
        </p>
        <div className="mt-8 grid gap-4 lg:grid-cols-4">
          <div className="panel p-6">
            <div className="mono text-sm text-[var(--mut)]">Lite</div>
            <div className="mt-2 text-4xl font-extrabold">$0</div>
            <p className="mt-2 text-sm text-[var(--mut)]">{PLANS.free.tagline}</p>
            <ul className="mt-4 space-y-1.5 text-sm text-[var(--mut)]">
              <li>Public homepage scanner</li>
              <li>Secrets · exposure · headers · DNS</li>
              <li>Rate-limited</li>
            </ul>
            <a href="#lite" className="btn-ghost mt-6 w-full">
              Try lite scan
            </a>
          </div>
          {paid.map((p) => (
            <div
              key={p.id}
              className={`panel p-6 ${p.id === 'commit' ? 'ring-1 ring-[var(--lime)]' : ''}`}
            >
              <div className="mono text-sm text-[var(--mut)]">{p.name}</div>
              <div className="mt-2 text-4xl font-extrabold">
                ${p.priceMonthlyUsd}
                <span className="text-sm font-normal text-[var(--mut)]">/mo</span>
              </div>
              <p className="mt-2 text-sm text-[var(--mut)]">{p.tagline}</p>
              <ul className="mt-4 space-y-1.5 text-sm text-[var(--mut)]">
                <li>{p.maxProjects} verified project{p.maxProjects === 1 ? '' : 's'}</li>
                <li>Ownership proof required</li>
                <li>{p.commitHooks ? 'Every commit / deploy hook' : p.deployHooks ? 'Deploy hooks' : 'Manual + scheduled'}</li>
                <li>{p.retentionDays}d history · agent fix packs</li>
                {p.githubApp && <li>GitHub checks</li>}
                {p.mcp && <li>MCP + API keys</li>}
              </ul>
              <Link href="/login" className={p.id === 'commit' ? 'btn-primary mt-6 w-full' : 'btn-ghost mt-6 w-full'}>
                Start {p.name}
              </Link>
            </div>
          ))}
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-5 pb-24">
        <div className="panel overflow-hidden p-0 sm:flex">
          <div className="flex-1 p-8">
            <h2 className="mono text-2xl font-bold">Open source core</h2>
            <p className="mt-3 text-sm text-[var(--mut)]">
              The scanner engine is Apache-2.0. Run it locally, in CI, or fork it. Hosted VibeTesting Agent
              adds auth (WorkOS), billing (Stripe), ownership gates, and always-on cadence.
            </p>
            <pre className="mono mt-4 overflow-x-auto rounded-lg bg-black/40 p-4 text-xs text-[var(--mut)]">
              npx github:newsengine/vibetesting-agent review https://your-app.example.com
            </pre>
            <div className="mt-4 flex flex-wrap gap-3">
              <a href={config.scannerRepo} className="btn-ghost" target="_blank" rel="noreferrer">
                vibetesting-agent on GitHub
              </a>
              <a href={config.ossRepo} className="btn-ghost" target="_blank" rel="noreferrer">
                vibetesting-agent
              </a>
            </div>
          </div>
          <div className="flex-1 border-t border-[var(--edge)] bg-black/20 p-8 sm:border-l sm:border-t-0">
            <h3 className="mono font-bold text-[var(--lime)]">Ownership security</h3>
            <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm text-[var(--mut)]">
              <li>Create a project with your production URL</li>
              <li>
                <strong className="text-[var(--ink)]">Domain email:</strong> sign in with an address on that
                domain, then click the one-time link we email to prove you control the inbox
              </li>
              <li>
                <strong className="text-[var(--ink)]">Or DNS TXT:</strong> place{' '}
                <code className="text-[var(--ink)]">vibetesting-verify=…</code> on the host (or{' '}
                <code className="text-[var(--ink)]">_vta.</code>) in your DNS control panel
              </li>
              <li>Only then: full scans, schedules, deploy/commit webhooks</li>
              <li>Authorization checkbox + audit log on every scan</li>
            </ol>
          </div>
        </div>
      </section>

      <footer className="border-t border-[var(--edge)] py-10 text-center text-sm text-[var(--mut)]">
        <div className="mx-auto flex max-w-6xl flex-col items-center gap-3 px-5">
          <div className="flex flex-wrap items-center justify-center gap-4">
            <span className="mono text-[var(--ink)]">{COMPANY.productDomain}</span>
            <Link href="/legal/terms">Terms</Link>
            <Link href="/legal/privacy">Privacy</Link>
            <Link href="/legal/acceptable-use">Acceptable use</Link>
            <Link href="/docs">Docs</Link>
            <Link href="/docs/coverage">Coverage</Link>
            <span>Authorized testing only</span>
          </div>
          <p className="text-xs opacity-70">{providedByLine()}</p>
        </div>
      </footer>
    </div>
  );
}

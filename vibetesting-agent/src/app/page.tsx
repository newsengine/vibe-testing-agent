import { TEST_CATALOG, SUITE_STATS, EXTRA_MODES } from '@/lib/plans';
import { OSS_LINKS } from '@/lib/oss';

const QUICKSTART = `# Scan a site you own
npx vibetesting-agent https://your-app.example.com

# Scan + agent fix report + Gherkin
npx vibetesting-agent review https://your-app.example.com`;

const GLOBAL_INSTALL = `npm install -g vibetesting-agent

vibetesting-agent https://your-app.example.com
vta https://your-app.example.com   # alias`;

const FROM_SOURCE = `git clone ${OSS_LINKS.repo}.git
cd vibe-testing-agent
npm ci
npm run build
node dist/cli.js https://your-app.example.com`;

const COMMANDS: { cmd: string; what: string }[] = [
  { cmd: 'vibetesting-agent <url>', what: 'Full black-box scan of a deployed URL. Exits non-zero on findings at or above --fail-on.' },
  { cmd: 'vibetesting-agent review <url>', what: 'Scan, then write security-review.md (ranked P1/P2 fixes for Claude, Cursor or Codex) and a Gherkin feature file.' },
  { cmd: 'vibetesting-agent init <url> --name my-app', what: 'Scaffold a security suite, CI workflow and baseline into the current repo.' },
  { cmd: 'vibetesting-agent audit --level high', what: 'Wrap npm audit and gate CI on dependency advisories.' },
  { cmd: 'vibetesting-agent recon <url> --yes-i-am-authorized', what: 'Opt-in port scan and service ID (authorization-gated, identify-only).' },
  { cmd: 'vibetesting-agent crawl | browse | separation', what: 'Opt-in browser modes (need playwright-core): deep crawl, functional smoke, two-account tenant isolation.' },
];

const FLAGS: { flag: string; what: string }[] = [
  { flag: '--only <cats> / --skip <cats>', what: 'Run or exclude categories, e.g. --only secrets,exposure,security' },
  { flag: '--fail-on high|medium|any', what: 'CI exit threshold (default high)' },
  { flag: '--json / --sarif', what: 'Machine-readable output; SARIF 2.1.0 for GitHub code scanning' },
  { flag: '--baseline <f> / --write-baseline <f>', what: 'Fail only on new findings versus a committed baseline' },
  { flag: '--agent-report <f.md>', what: 'Ranked P1/P2 fix report for coding agents' },
  { flag: '--gherkin <f.feature>', what: 'Gherkin security scenarios from findings' },
  { flag: '--cookie / --header "K: V"', what: 'Scan behind login (sent same-origin only)' },
  { flag: '--crawl <n> / --urls <file>', what: 'Scan multiple pages in one run' },
  { flag: '--cors-path / --rate-limit-path', what: 'Test CORS reflection or 429 rate limiting on a path' },
  { flag: '--plugins <dir>', what: 'Run your own JSON check templates, no code' },
  { flag: '--compliance', what: 'OWASP ASVS L1, Top 10 and WSTG coverage report' },
  { flag: '--allow-report-only-csp', what: 'Accept CSP Report-Only while you roll out CSP' },
];

const CI_REUSABLE = `# .github/workflows/security.yml
name: security
on: [pull_request, workflow_dispatch]
jobs:
  scan:
    uses: newsengine/vibe-testing-agent/.github/workflows/probe.yml@main
    with:
      url: https://your-deploy.example.com
      fail_on: high          # high | medium | any`;

const CI_NPX = `jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx --yes vibetesting-agent https://your-deploy.example.com --fail-on high`;

const LIBRARY = `import { idorProbe, checkSecurityHeaders, scanSecrets } from 'vibetesting-agent';

// Headers on any fetch Response must be clean:
expect(checkSecurityHeaders(res.headers, { requireEnforcedCsp: true })).toEqual([]);`;

function Code({ children, label }: { children: string; label?: string }) {
  return (
    <div className="min-w-0">
      {label && <div className="mono mb-2 text-[11px] uppercase tracking-[0.16em] text-[var(--lime)]">{label}</div>}
      <pre className="mono overflow-x-auto rounded-lg border border-[var(--edge)] bg-black/40 p-4 text-xs leading-relaxed text-[var(--ink)]">
        <code>{children}</code>
      </pre>
    </div>
  );
}

function SectionHead({ kicker, title, children }: { kicker: string; title: string; children?: React.ReactNode }) {
  return (
    <div className="mb-8 max-w-3xl">
      <p className="mono text-xs uppercase tracking-[0.18em] text-[var(--lime)]">{kicker}</p>
      <h2 className="mono mt-2 text-2xl font-bold sm:text-4xl">{title}</h2>
      {children && <div className="mt-3 text-[var(--mut)]">{children}</div>}
    </div>
  );
}

export default function HomePage() {
  return (
    <div className="relative overflow-x-hidden">
      <div className="pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(1000px_560px_at_80%_-10%,rgba(169,239,79,.12),transparent_55%),radial-gradient(700px_500px_at_0%_40%,rgba(80,140,255,.06),transparent_50%),radial-gradient(600px_400px_at_50%_100%,rgba(60,120,80,.12),transparent_55%)]" />

      <nav className="sticky top-0 z-30 border-b border-[var(--edge)] bg-[var(--bg)]/85 backdrop-blur-md">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between gap-3 px-4 sm:px-5">
          <a href="#top" className="mono flex min-w-0 items-center gap-2 font-extrabold tracking-tight">
            <span className="h-2.5 w-2.5 shrink-0 rounded-full bg-[var(--lime)] shadow-[0_0_14px_var(--lime)]" />
            <span className="truncate">vibetesting-agent</span>
          </a>
          <div className="flex items-center gap-4 text-sm">
            <a href="#install" className="hidden text-[var(--mut)] hover:text-[var(--lime)] sm:inline">
              Install
            </a>
            <a href="#checks" className="hidden text-[var(--mut)] hover:text-[var(--lime)] sm:inline">
              Checks
            </a>
            <a href="#ci" className="hidden text-[var(--mut)] hover:text-[var(--lime)] md:inline">
              CI
            </a>
            <a href="#contribute" className="hidden text-[var(--mut)] hover:text-[var(--lime)] md:inline">
              Contribute
            </a>
            <a href={OSS_LINKS.repo} className="btn-primary !py-2 !px-4 text-xs" target="_blank" rel="noreferrer">
              GitHub
            </a>
          </div>
        </div>
      </nav>

      <header id="top" className="mx-auto max-w-6xl px-4 pb-12 pt-14 sm:px-5 sm:pt-20">
        <p className="mono mb-4 inline-flex flex-wrap items-center gap-2 rounded-full border border-[var(--edge)] px-3 py-1 text-[11px] uppercase tracking-[0.16em] text-[var(--lime)]">
          Open source · Apache-2.0 · CLI + library
        </p>
        <h1 className="mono max-w-4xl text-3xl font-extrabold leading-[1.08] tracking-tight sm:text-6xl">
          Point it at your app.
          <br />
          <span className="text-[var(--lime)]">It tells you what is wrong.</span>
        </h1>
        <p className="mt-6 max-w-2xl text-base text-[var(--mut)] sm:text-lg">
          vibetesting-agent is a free, open-source security scanner for deployed web apps. From just a URL it
          finds leaked API keys in your JS bundle, an exposed <code className="text-[var(--ink)]">.env</code> or{' '}
          <code className="text-[var(--ink)]">.git</code>, missing security headers, broken links, and SEO,
          accessibility and performance gaps. Every failing finding comes with a one-line fix, and it exits
          non-zero so it doubles as a CI gate.
        </p>

        <div className="mt-8 max-w-2xl">
          <Code>{'npx vibetesting-agent https://your-app.example.com'}</Code>
        </div>

        <div className="mt-6 flex flex-wrap gap-3">
          <a href={OSS_LINKS.repo} className="btn-primary" target="_blank" rel="noreferrer">
            View on GitHub
          </a>
          <a href="#install" className="btn-ghost">
            Install and usage
          </a>
          <a href={OSS_LINKS.npm} className="btn-ghost" target="_blank" rel="noreferrer">
            npm package
          </a>
        </div>
      </header>

      <section className="mx-auto max-w-6xl px-4 pb-20 sm:px-5">
        <div className="grid gap-4 sm:grid-cols-3">
          {[
            ['Zero install, black-box', 'No source access and no headless browser for the default scan. Node 20+ and a URL is all it needs.'],
            ['Fixes for humans and agents', 'Ranked P1/P2 findings with fix and verify steps, ready to paste into Claude Code, Cursor or Codex.'],
            ['Built for CI', 'SARIF for the GitHub Security tab, baselines to fail only on regressions, and a reusable workflow.'],
          ].map(([t, d]) => (
            <div key={t} className="panel p-5">
              <h3 className="mono font-bold text-[var(--lime)]">{t}</h3>
              <p className="mt-2 text-sm text-[var(--mut)]">{d}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="install" className="mx-auto max-w-6xl scroll-mt-16 px-4 pb-24 sm:px-5">
        <SectionHead kicker="Install" title="Three ways to run it">
          Requires Node.js 20 or newer. Only scan systems you own or have written permission to test.
        </SectionHead>
        <div className="grid max-w-3xl gap-6">
          <Code label="1. npx (no install)">{QUICKSTART}</Code>
          <Code label="2. Global install">{GLOBAL_INSTALL}</Code>
          <Code label="3. From source">{FROM_SOURCE}</Code>
        </div>

        <h3 className="mono mt-12 text-lg font-bold">Commands</h3>
        <div className="mt-4 grid gap-3 md:grid-cols-2">
          {COMMANDS.map((c) => (
            <div key={c.cmd} className="panel min-w-0 p-4">
              <code className="mono block break-words text-xs text-[var(--lime)]">{c.cmd}</code>
              <p className="mt-2 text-sm text-[var(--mut)]">{c.what}</p>
            </div>
          ))}
        </div>

        <h3 className="mono mt-12 text-lg font-bold">Useful flags</h3>
        <div className="panel mt-4 divide-y divide-[var(--edge)] p-0">
          {FLAGS.map((f) => (
            <div key={f.flag} className="flex flex-col gap-1 px-4 py-3 sm:flex-row sm:items-baseline sm:gap-6">
              <code className="mono shrink-0 break-words text-xs text-[var(--ink)] sm:w-80">{f.flag}</code>
              <span className="text-sm text-[var(--mut)]">{f.what}</span>
            </div>
          ))}
        </div>
        <p className="mt-4 text-sm text-[var(--mut)]">
          The full flag list, config file (<code className="text-[var(--ink)]">.analproberc.json</code>) and
          examples are in the{' '}
          <a href={`${OSS_LINKS.repo}#readme`} className="text-[var(--lime)] hover:underline" target="_blank" rel="noreferrer">
            README
          </a>
          .
        </p>
      </section>

      <section id="checks" className="mx-auto max-w-6xl scroll-mt-16 px-4 pb-24 sm:px-5">
        <SectionHead
          kicker="What it checks"
          title={`${SUITE_STATS.categories} categories, ${SUITE_STATS.ruleSurface}+ rules`}
        >
          <p>
            {SUITE_STATS.blackBoxProbes}+ black-box probes plus {SUITE_STATS.clientVulnRanges}+ known-vulnerable
            client library ranges, mapped to OWASP Top 10, WSTG and ASVS Level 1 (
            {SUITE_STATS.asvsL1Covered}/{SUITE_STATS.asvsL1Total} black-box requirements). Every check has a
            stable <code className="text-[var(--ink)]">VTA-NNNN</code> id and is listed in{' '}
            <a href={OSS_LINKS.checks} className="text-[var(--lime)] hover:underline" target="_blank" rel="noreferrer">
              docs/CHECKS.md
            </a>
            .
          </p>
        </SectionHead>

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {TEST_CATALOG.map((t) => (
            <article
              key={t.id}
              className="panel group relative flex min-w-0 flex-col overflow-hidden p-5 transition hover:border-[var(--lime)]/50"
            >
              <div className="flex items-start justify-between gap-2">
                <span className="text-2xl" aria-hidden>
                  {t.icon}
                </span>
                <span className="mono rounded border border-[var(--edge)] px-2 py-0.5 text-[10px] uppercase text-[var(--mut)]">
                  {t.severity}
                </span>
              </div>
              <h3 className="mono mt-3 font-bold">{t.title}</h3>
              <p className="mt-1 mono text-[11px] text-[var(--lime)]">
                {t.probeCount > 0
                  ? t.id === 'components'
                    ? `${t.probeCount}+ version ranges`
                    : `${t.probeCount}+ probes`
                  : 'user-defined'}
                <span className="text-[var(--mut)]"> · --only {t.id}</span>
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
                  <li className="mono px-1.5 py-0.5 text-[10px] text-[var(--mut)]">+{t.samples.length - 6} more</li>
                )}
              </ul>
            </article>
          ))}
        </div>

        <div className="mt-10">
          <h3 className="mono text-lg font-bold">Beyond the default pass</h3>
          <p className="mt-1 max-w-2xl text-sm text-[var(--mut)]">
            Opt-in modes and white-box helpers. The default scan is read-only; active modes are off unless you
            ask for them.
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
      </section>

      <section id="ci" className="mx-auto max-w-6xl scroll-mt-16 px-4 pb-24 sm:px-5">
        <SectionHead kicker="Run it in CI" title="Gate every deploy">
          Call the reusable workflow from any repo, or run it with npx in your own job. Add{' '}
          <code className="text-[var(--ink)]">--sarif</code> to send findings to the GitHub Security tab, or{' '}
          <code className="text-[var(--ink)]">--baseline</code> to fail only on new issues.
        </SectionHead>
        <div className="grid gap-6 lg:grid-cols-2">
          <Code label="Reusable workflow">{CI_REUSABLE}</Code>
          <Code label="Or plain npx">{CI_NPX}</Code>
        </div>
        <div className="mt-6">
          <Code label="Use it as a library in your tests">{LIBRARY}</Code>
          <p className="mt-3 text-sm text-[var(--mut)]">
            White-box helpers include <code className="text-[var(--ink)]">idorProbe</code>,{' '}
            <code className="text-[var(--ink)]">rbacProbe</code>,{' '}
            <code className="text-[var(--ink)]">dataIsolationProbe</code>,{' '}
            <code className="text-[var(--ink)]">massAssignmentProbe</code>,{' '}
            <code className="text-[var(--ink)]">checkCookieFlags</code> and{' '}
            <code className="text-[var(--ink)]">scanSecrets</code>.
          </p>
        </div>
      </section>

      <section id="contribute" className="mx-auto max-w-6xl scroll-mt-16 px-4 pb-24 sm:px-5">
        <div className="panel overflow-hidden p-0 md:flex">
          <div className="min-w-0 flex-1 p-6 sm:p-8">
            <h2 className="mono text-2xl font-bold">Contribute</h2>
            <p className="mt-3 text-sm text-[var(--mut)]">
              Issues and pull requests are welcome. New checks need a known-bad and known-good fixture so they
              never false-positive. Custom checks can also ship as JSON plugins without touching the engine.
            </p>
            <pre className="mono mt-4 overflow-x-auto rounded-lg bg-black/40 p-4 text-xs text-[var(--mut)]">
              <code>{'npm ci && npm run build && npm test'}</code>
            </pre>
            <div className="mt-4 flex flex-wrap gap-3">
              <a href={OSS_LINKS.repo} className="btn-primary" target="_blank" rel="noreferrer">
                Star or fork on GitHub
              </a>
              <a href={OSS_LINKS.issues} className="btn-ghost" target="_blank" rel="noreferrer">
                Open an issue
              </a>
              <a href={OSS_LINKS.contributing} className="btn-ghost" target="_blank" rel="noreferrer">
                CONTRIBUTING.md
              </a>
            </div>
          </div>
          <div className="min-w-0 flex-1 border-t border-[var(--edge)] bg-black/20 p-6 sm:p-8 md:border-l md:border-t-0">
            <h3 className="mono font-bold text-[var(--lime)]">License and responsible use</h3>
            <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-[var(--mut)]">
              <li>
                Licensed under{' '}
                <a href={OSS_LINKS.license} className="text-[var(--ink)] hover:underline" target="_blank" rel="noreferrer">
                  Apache-2.0
                </a>
                . Provided as is, without warranty.
              </li>
              <li>Only test systems you own or have explicit written permission to test.</li>
              <li>Active recon is gated behind an explicit authorization flag.</li>
              <li>
                A hygiene scanner and first line of defense, not a substitute for a professional penetration
                test.
              </li>
              <li>
                Found a vulnerability in the scanner itself? See{' '}
                <a href={OSS_LINKS.security} className="text-[var(--ink)] hover:underline" target="_blank" rel="noreferrer">
                  SECURITY.md
                </a>
                .
              </li>
            </ul>
          </div>
        </div>
      </section>
    </div>
  );
}

import Link from 'next/link';
import type { Metadata } from 'next';
import {
  SECURITY_ZONES,
  WSTG_CATEGORIES,
  ASVS_L1_ROWS,
  coverageLabel,
  coverageCounts,
  type CoverageLevel,
} from '@/lib/coverage';
import { config } from '@/lib/config';

export const metadata: Metadata = {
  title: 'Security coverage — zones, WSTG & ASVS · VibeTesting Agent',
  description:
    'Honest map of what VibeTesting Agent / vibetesting-agent automates across web security zones and OWASP WSTG / ASVS L1 — and what still needs auth or active testing.',
  alternates: { canonical: 'https://vibetestingagent.com/docs/coverage' },
};

function CovPill({ level }: { level: CoverageLevel }) {
  const styles =
    level === 'covered'
      ? 'border-[var(--lime)]/40 bg-[var(--lime)]/10 text-[var(--lime)]'
      : level === 'partial'
        ? 'border-sky-400/40 bg-sky-400/10 text-sky-300'
        : 'border-[var(--hi)]/40 bg-[var(--hi)]/10 text-[var(--hi)]';
  return (
    <span className={`mono inline-flex rounded-md border px-2 py-0.5 text-[10px] uppercase tracking-wide ${styles}`}>
      {coverageLabel(level)}
    </span>
  );
}

export default function CoveragePage() {
  const wstg = coverageCounts(WSTG_CATEGORIES);
  const asvsCovered = ASVS_L1_ROWS.filter((r) => r.covered).length;
  const asvsTotal = ASVS_L1_ROWS.length;
  const zoneItems = SECURITY_ZONES.flatMap((z) => z.items);
  const zones = coverageCounts(zoneItems);

  return (
    <div className="relative min-h-screen overflow-x-hidden">
      <div className="pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(900px_500px_at_70%_-10%,rgba(169,239,79,.08),transparent_55%),radial-gradient(600px_400px_at_0%_50%,rgba(80,140,255,.05),transparent_50%)]" />

      <nav className="sticky top-0 z-30 border-b border-[var(--edge)] bg-[var(--bg)]/85 backdrop-blur-md">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-5">
          <Link href="/" className="mono flex items-center gap-2 font-extrabold tracking-tight">
            <span className="h-2.5 w-2.5 rounded-full bg-[var(--lime)] shadow-[0_0_14px_var(--lime)]" />
            VibeTesting Agent
          </Link>
          <div className="flex items-center gap-4 text-sm">
            <Link href="/docs" className="text-[var(--mut)] hover:text-[var(--lime)]">
              Docs
            </Link>
            <Link href="/#tests" className="hidden text-[var(--mut)] hover:text-[var(--lime)] sm:inline">
              Tests
            </Link>
            <Link href="/login" className="btn-primary !py-2 !px-4 text-xs">
              Dashboard
            </Link>
          </div>
        </div>
      </nav>

      <main className="mx-auto max-w-6xl px-5 pb-24 pt-12">
        <p className="mono text-xs uppercase tracking-[0.18em] text-[var(--lime)]">Coverage map</p>
        <h1 className="mono mt-2 max-w-3xl text-3xl font-extrabold tracking-tight sm:text-4xl">
          Security zones &amp; OWASP WSTG — what we actually automate
        </h1>
        <p className="mt-4 max-w-3xl text-[var(--mut)]">
          Honest inventory of trust boundaries and standards mapping for{' '}
          <strong className="text-[var(--ink)]">vibetesting-agent</strong> / VibeTesting Agent. We automate the{' '}
          <em>black-box observable</em> slice — not a full pentest mind map. Gaps are deliberate: active
          injection, full auth abuse, and business logic need sessions and (often) staging.
        </p>

        {/* Summary stats */}
        <div className="mt-8 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { n: `${zones.covered}/${zones.total}`, l: 'Zone items covered', d: `${zones.partial} partial · ${zones.out} out` },
            { n: `${wstg.covered}`, l: 'WSTG cats strong', d: `${wstg.partial} partial · ${wstg.out} out of ${wstg.total}` },
            { n: `${asvsCovered}/${asvsTotal}`, l: 'ASVS L1 rows covered', d: 'Black-box subset' },
            { n: 'URL-only', l: 'Default scan mode', d: 'No source · no auth · no exploit payloads' },
          ].map((s) => (
            <div key={s.l} className="panel p-4">
              <div className="mono text-2xl font-extrabold text-[var(--lime)]">{s.n}</div>
              <div className="mt-1 text-sm font-medium">{s.l}</div>
              <div className="mt-1 text-xs text-[var(--mut)]">{s.d}</div>
            </div>
          ))}
        </div>

        <div className="mt-6 flex flex-wrap gap-4 text-xs text-[var(--mut)]">
          <span className="inline-flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-[var(--lime)]" /> Covered (black-box)
          </span>
          <span className="inline-flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-sky-400" /> Partial (opt-in / white-box helper)
          </span>
          <span className="inline-flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-[var(--hi)]" /> Out of scope
          </span>
        </div>

        {/* Zones */}
        <section id="zones" className="mt-14">
          <h2 className="mono text-2xl font-bold">Security zones</h2>
          <p className="mt-2 max-w-2xl text-sm text-[var(--mut)]">
            From the public internet to multi-tenant isolation. Each card is a trust boundary attackers
            (or bad guys) try to cross.
          </p>

          <div className="mt-6 space-y-4">
            {SECURITY_ZONES.map((zone, i) => (
              <div key={zone.id}>
                {i > 0 && (
                  <div className="mono py-2 text-center text-[11px] tracking-wide text-[var(--mut)]">
                    {i === 3 ? '↓ authentication boundary' : i === 5 ? '↓ strongest isolation' : '↓'}
                  </div>
                )}
                <article
                  className="panel relative overflow-hidden p-5"
                  style={{ borderLeftWidth: 4, borderLeftColor: zone.accent }}
                >
                  <div className="flex flex-wrap items-baseline gap-3">
                    <h3 className="mono text-base font-bold">{zone.name}</h3>
                    <span className="mono text-[10px] uppercase tracking-wider text-[var(--mut)]">
                      {zone.tagline}
                    </span>
                  </div>
                  <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                    {zone.items.map((item) => (
                      <div
                        key={item.title}
                        className="rounded-lg border border-[var(--edge)] bg-black/20 p-3"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="text-sm font-semibold">{item.title}</div>
                          <CovPill level={item.coverage} />
                        </div>
                        <p className="mt-1.5 text-xs leading-relaxed text-[var(--mut)]">{item.detail}</p>
                        {item.note && (
                          <p className="mono mt-2 text-[10px] text-[var(--md)]">{item.note}</p>
                        )}
                      </div>
                    ))}
                  </div>
                </article>
              </div>
            ))}
          </div>
        </section>

        {/* WSTG */}
        <section id="wstg" className="mt-16">
          <h2 className="mono text-2xl font-bold">OWASP WSTG categories</h2>
          <p className="mt-2 max-w-2xl text-sm text-[var(--mut)]">
            Web Security Testing Guide v4.2 — the structure behind mind-map checklists like{' '}
            <a
              className="text-[var(--lime)] hover:underline"
              href="https://owasp.org/www-project-web-security-testing-guide/"
              target="_blank"
              rel="noreferrer"
            >
              OWASP WSTG
            </a>
            . We do <strong className="text-[var(--ink)]">not</strong> claim 100% of every test ID.
          </p>

          <div className="mt-6 overflow-x-auto rounded-xl border border-[var(--edge)]">
            <table className="w-full min-w-[720px] text-left text-sm">
              <thead className="border-b border-[var(--edge)] bg-black/30 text-xs uppercase tracking-wider text-[var(--mut)]">
                <tr>
                  <th className="px-4 py-3 font-medium">Category</th>
                  <th className="px-4 py-3 font-medium">Coverage</th>
                  <th className="px-4 py-3 font-medium">What we do</th>
                  <th className="px-4 py-3 font-medium">How / limits</th>
                </tr>
              </thead>
              <tbody>
                {WSTG_CATEGORIES.map((c) => (
                  <tr key={c.id} className="border-b border-[var(--edge)]/80 align-top">
                    <td className="px-4 py-3">
                      <div className="mono text-xs text-[var(--lime)]">WSTG-{c.id}</div>
                      <div className="font-semibold text-[var(--ink)]">{c.name}</div>
                      <div className="mt-0.5 text-xs text-[var(--mut)]">{c.summary}</div>
                    </td>
                    <td className="px-4 py-3">
                      <CovPill level={c.coverage} />
                    </td>
                    <td className="px-4 py-3">
                      <ul className="space-y-1 text-xs text-[var(--mut)]">
                        {c.examples.map((e) => (
                          <li key={e} className="mono">
                            · {e}
                          </li>
                        ))}
                      </ul>
                    </td>
                    <td className="px-4 py-3 text-xs text-[var(--mut)]">{c.how}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* ASVS */}
        <section id="asvs" className="mt-16">
          <h2 className="mono text-2xl font-bold">OWASP ASVS 4.0.3 — Level 1 (black-box subset)</h2>
          <p className="mt-2 max-w-2xl text-sm text-[var(--mut)]">
            Requirements verifiable without source access or active exploitation. Full detail lives in the
            OSS package (
            <a
              className="text-[var(--lime)] hover:underline"
              href={`${config.scannerRepo}/blob/main/docs/compliance.md`}
              target="_blank"
              rel="noreferrer"
            >
              docs/compliance.md
            </a>
            ). Run <code className="text-[var(--ink)]">vibetesting-agent URL --compliance</code> for a live grade.
          </p>
          <div className="mt-6 grid gap-2 sm:grid-cols-2">
            {ASVS_L1_ROWS.map((r) => (
              <div
                key={r.id}
                className="flex items-start gap-3 rounded-lg border border-[var(--edge)] bg-black/20 px-3 py-2.5"
              >
                <span
                  className={`mono mt-0.5 text-[10px] ${r.covered ? 'text-[var(--lime)]' : 'text-[var(--hi)]'}`}
                >
                  {r.covered ? '●' : '○'}
                </span>
                <div>
                  <div className="mono text-xs text-[var(--lime)]">{r.id}</div>
                  <div className="text-sm text-[var(--mut)]">{r.text}</div>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* CTA */}
        <section className="mt-16 panel p-6 sm:flex sm:items-center sm:justify-between sm:gap-6">
          <div>
            <h2 className="mono text-lg font-bold">Try it on a URL</h2>
            <p className="mt-1 text-sm text-[var(--mut)]">
              Free lite scan on the homepage, or the full CLI with compliance output.
            </p>
            <pre className="mono mt-3 overflow-x-auto rounded-lg bg-black/40 p-3 text-xs text-[var(--mut)]">
              npx vibetesting-agent https://your-app.example.com --compliance
            </pre>
          </div>
          <div className="mt-4 flex flex-wrap gap-3 sm:mt-0 sm:shrink-0">
            <Link href="/#lite" className="btn-primary">
              Free lite scan
            </Link>
            <Link href="/docs" className="btn-ghost">
              Docs
            </Link>
            <a href={config.scannerRepo} className="btn-ghost" target="_blank" rel="noreferrer">
              vibetesting-agent
            </a>
          </div>
        </section>

        <p className="mt-10 text-xs leading-relaxed text-[var(--mut)]">
          <strong className="text-[var(--ink)]">Not a substitute for a professional pentest.</strong> A clean
          scan does not mean the application is secure. Active WSTG items (injection, full auth abuse, business
          logic) belong on staging with authorization — ZAP, Burp, or a human tester — plus our white-box helpers
          for multi-tenant suites.
        </p>
      </main>
    </div>
  );
}

import Link from 'next/link';
import { notFound } from 'next/navigation';
import { getSessionUser } from '@/lib/auth';
import { getScanForUser, parseFindings } from '@/lib/scans';
import { CopyButton } from '@/components/forms';

export default async function ScanDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const user = await getSessionUser();
  if (!user) return null;
  const { id } = await params;
  const scan = await getScanForUser(id, user.id);
  if (!scan) notFound();

  const allFindings = parseFindings(scan);
  const findings = allFindings.filter((f) => !f.pass || f.inconclusive || f.quarantined);
  let summary: { failHigh?: number; failMedium?: number; failed?: number; passed?: number } = {};
  let baselineDiff: { newFailures?: { id: string; title: string; severity: string }[]; resolved?: string[] } = {};
  try {
    summary = scan.summaryJson ? JSON.parse(scan.summaryJson) : {};
  } catch { /* */ }
  try {
    baselineDiff = scan.baselineDiffJson ? JSON.parse(scan.baselineDiffJson) : {};
  } catch { /* */ }

  return (
    <div className="space-y-8">
      <div>
        <Link href="/dashboard/scans" className="text-sm text-[var(--mut)] hover:text-[var(--lime)]">
          ← Scans
        </Link>
        <h1 className="mono mt-2 text-2xl font-bold">Scan {scan.id}</h1>
        <p className="mono text-sm text-[var(--mut)]">{scan.url}</p>
      </div>

      <div className="grid gap-4 sm:grid-cols-4">
        <div className="panel p-4">
          <div className="text-xs uppercase text-[var(--mut)]">Grade</div>
          <div className="mono text-3xl font-extrabold text-[var(--lime)]">{scan.grade || '—'}</div>
        </div>
        <div className="panel p-4">
          <div className="text-xs uppercase text-[var(--mut)]">Score</div>
          <div className="mono text-3xl font-extrabold">{scan.score ?? '—'}</div>
        </div>
        <div className="panel p-4">
          <div className="text-xs uppercase text-[var(--mut)]">Status</div>
          <div className="mt-1 font-semibold">{scan.status}</div>
          <div className="text-xs text-[var(--mut)]">
            {scan.mode} · {scan.trigger}
          </div>
        </div>
        <div className="panel p-4">
          <div className="text-xs uppercase text-[var(--mut)]">Failures</div>
          <div className="mt-1 text-sm">
            🟥 {summary.failHigh ?? 0} · 🟧 {summary.failMedium ?? 0} · total {summary.failed ?? findings.length}
          </div>
        </div>
      </div>

      {scan.error && (
        <div className="rounded-lg border border-[var(--hi)]/40 bg-[var(--hi)]/10 p-4 text-sm text-[var(--hi)]">
          {scan.error}
        </div>
      )}

      {baselineDiff.newFailures && baselineDiff.newFailures.length > 0 && (
        <section className="panel border-[var(--md)] p-4">
          <h2 className="mono font-bold text-[var(--md)]">New vs baseline</h2>
          <ul className="mt-2 space-y-1 text-sm">
            {baselineDiff.newFailures.map((f) => (
              <li key={f.id}>
                [{f.severity}] {f.title}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="panel p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="mono font-bold">/security-review (Claude · Codex)</h2>
            <p className="mt-1 text-xs text-[var(--mut)]">
              Ranked P1→Pn agent report produced at end of every completed run. Paste into Claude Code or Codex.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {scan.status === 'completed' && (
              <>
                {scan.fixPackMarkdown && (
                  <CopyButton text={scan.fixPackMarkdown} label="Copy security-review.md" />
                )}
                <a
                  className="btn-ghost text-xs"
                  href={`/api/v1/scans/${scan.id}/security-review?format=md`}
                >
                  Download .md
                </a>
                <a className="btn-primary text-xs" href={`/api/v1/scans/${scan.id}/report.pdf`}>
                  Download PDF report
                </a>
              </>
            )}
          </div>
        </div>
        <pre className="mono max-h-80 overflow-auto whitespace-pre-wrap rounded bg-black/40 p-4 text-xs text-[var(--mut)]">
          {scan.fixPackMarkdown || 'No security-review yet (scan not completed).'}
        </pre>
      </section>

      <section>
        <h2 className="mono mb-3 font-bold">Findings ({findings.length})</h2>
        <div className="space-y-3">
          {findings.map((f) => (
            <div key={f.id} className="panel p-4">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`mono rounded px-2 py-0.5 text-xs uppercase ${
                    f.severity === 'high'
                      ? 'bg-[var(--hi)]/20 text-[var(--hi)]'
                      : f.severity === 'medium'
                        ? 'bg-[var(--md)]/20 text-[var(--md)]'
                        : 'bg-[var(--lo)]/20 text-[var(--lo)]'
                  }`}
                >
                  {f.severity}
                </span>
                <span className="text-xs text-[var(--mut)]">{f.category}</span>
                {f.inconclusive && (
                  <span className="mono rounded border border-[var(--mut)] px-2 py-0.5 text-[10px] uppercase text-[var(--mut)]">
                    error/inconclusive
                  </span>
                )}
                {f.quarantined && (
                  <span className="mono rounded border border-[var(--md)]/40 px-2 py-0.5 text-[10px] uppercase text-[var(--md)]">
                    quarantined
                  </span>
                )}
                {(f.retries ?? 0) > 0 && (
                  <span className="mono text-[10px] text-[var(--mut)]">retries: {f.retries}</span>
                )}
                <span className="font-semibold">{f.title}</span>
              </div>
              <p className="mt-2 text-sm text-[var(--mut)]">{f.detail}</p>
              {f.fix && (
                <p className="mt-2 text-sm">
                  <span className="text-[var(--lime)]">Fix:</span> {f.fix}
                </p>
              )}
              <div className="mt-3">
                <CopyButton
                  label="Copy fix prompt"
                  text={`Fix this VibeTesting Agent finding on ${scan.url}:\n\nID: ${f.id}\nSeverity: ${f.severity}\nCategory: ${f.category}\nTitle: ${f.title}\nDetail: ${f.detail}\nRecommended fix: ${f.fix || 'Harden safely.'}\n\nVerify with a VibeTesting Agent rescan.`}
                />
              </div>
            </div>
          ))}
          {findings.length === 0 && scan.status === 'completed' && (
            <p className="text-[var(--lime)]">All checks passed.</p>
          )}
        </div>
      </section>

      {scan.reportHtml && (
        <section className="panel p-5">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <h2 className="mono font-bold">HTML report</h2>
            {scan.status === 'completed' && (
              <a className="btn-ghost text-xs" href={`/api/v1/scans/${scan.id}/report.pdf`}>
                PDF
              </a>
            )}
          </div>
          <iframe title="report" className="h-[480px] w-full rounded border border-[var(--edge)] bg-white" srcDoc={scan.reportHtml} />
        </section>
      )}
    </div>
  );
}

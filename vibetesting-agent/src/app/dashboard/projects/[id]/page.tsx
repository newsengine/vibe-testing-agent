import Link from 'next/link';
import { notFound } from 'next/navigation';
import { getSessionUser } from '@/lib/auth';
import { getProject } from '@/lib/projects';
import { config } from '@/lib/config';
import { authPublicStatus } from '@/lib/project-auth';
import { OwnershipVerifyPanel, RunScanForm, CopyButton, AuthAccessPanel, PreviewPatternsPanel, QuarantinePanel } from '@/components/forms';

export default async function ProjectDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const user = await getSessionUser();
  if (!user) return null;
  const { id } = await params;
  const project = await getProject(user.id, id);
  if (!project) notFound();

  const webhookUrl = `${config.appUrl}/api/webhooks/deploy/${project.deployWebhookSecret}`;
  const badgeUrl = `${config.appUrl}/api/badge/${project.shareToken}`;
  const shareUrl = `${config.appUrl}/share/${project.shareToken}`;
  const badgeMd = `![ship-score](${badgeUrl})`;
  const auth = authPublicStatus(project);

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <Link href="/dashboard/projects" className="text-sm text-[var(--mut)] hover:text-[var(--lime)]">
            ← Projects
          </Link>
          <h1 className="mono mt-2 text-2xl font-bold">{project.name}</h1>
          <p className="mono text-sm text-[var(--mut)]">{project.url}</p>
          <div className="mt-2 flex flex-wrap gap-2 text-[10px] uppercase tracking-wide">
            <span
              className={`mono rounded border px-2 py-0.5 ${
                project.verified
                  ? 'border-[var(--lime)]/40 text-[var(--lime)]'
                  : 'border-[var(--md)]/40 text-[var(--md)]'
              }`}
            >
              ownership {project.verified ? '✓' : '…'}
            </span>
            <span
              className={`mono rounded border px-2 py-0.5 ${
                auth.ready
                  ? 'border-[var(--lime)]/40 text-[var(--lime)]'
                  : 'border-[var(--edge)] text-[var(--mut)]'
              }`}
            >
              internal auth {auth.ready ? '✓' : 'off'}
            </span>
          </div>
        </div>
        <div className="text-right">
          <div className="mono text-4xl font-extrabold text-[var(--lime)]">{project.lastGrade || '—'}</div>
          <div className="text-sm text-[var(--mut)]">
            {project.lastScore != null ? `${project.lastScore}/100` : 'No scans yet'}
          </div>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="panel space-y-3 p-5 lg:col-span-2">
          <div className="text-xs uppercase text-[var(--mut)]">1 · Ownership security</div>
          <div className="font-semibold">
            {project.verified ? (
              <span className="text-[var(--lime)]">
                Verified
                {project.verifyMethod ? (
                  <span className="mono ml-2 text-xs font-normal text-[var(--mut)]">
                    via {project.verifyMethod}
                  </span>
                ) : null}
              </span>
            ) : (
              'Unverified — full scans locked'
            )}
          </div>
          {!project.verified && (
            <OwnershipVerifyPanel
              projectId={project.id}
              hostname={project.hostname}
              verifyToken={project.verifyToken}
              userEmail={user.email}
              emailVerified={Boolean(user.emailVerifiedAt)}
            />
          )}
          {project.verified && (
            <p className="text-sm text-[var(--mut)]">
              Domain ownership proven. External black-box scans are allowed. Optionally add a test session
              below for dashboard / API coverage.
            </p>
          )}
        </div>
        <div className="space-y-4">
          <div className="panel p-4 text-sm">
            <div className="text-xs uppercase text-[var(--mut)]">Policy</div>
            <div className="mt-1 font-semibold capitalize">{project.policy}</div>
            <div className="mt-1 text-[var(--mut)]">
              Continuous scanning {project.shipCheckEnabled ? 'enabled' : 'disabled'}
            </div>
          </div>
          <div className="panel p-4 text-sm">
            <div className="text-xs uppercase text-[var(--mut)]">GitHub repo</div>
            <div className="mt-1 mono text-xs">{project.githubRepo || 'Not linked'}</div>
            <p className="mt-2 text-[var(--mut)]">Optional for commit hooks — not used for ownership.</p>
          </div>
        </div>
      </div>

      {/* Step 2: authenticated testing */}
      <div>
        <div className="mb-2 text-xs uppercase tracking-wide text-[var(--mut)]">
          2 · Authenticated testing (opt-in)
        </div>
        <AuthAccessPanel projectId={project.id} projectUrl={project.url} initial={auth} />
      </div>

      {project.verified && <PreviewPatternsPanel projectId={project.id} />}
      {project.verified && <QuarantinePanel projectId={project.id} />}

      <section className="panel space-y-3 p-5">
        <h2 className="mono font-bold">Deploy webhook (every software update)</h2>
        <p className="text-sm text-[var(--mut)]">
          POST this URL from Vercel / Railway / GitHub Actions after a successful deploy. Requires a paid
          plan and verified ownership.
        </p>
        <code className="mono block break-all rounded bg-black/40 p-3 text-xs">{webhookUrl}</code>
        <CopyButton text={webhookUrl} label="Copy webhook URL" />
        <pre className="mono overflow-x-auto rounded bg-black/40 p-3 text-xs text-[var(--mut)]">{`curl -X POST '${webhookUrl}' -H 'content-type: application/json' -d '{"url":"${project.url}"}'`}</pre>
      </section>

      <section className="panel space-y-3 p-5">
        <h2 className="mono font-bold">Badge & share</h2>
        <code className="mono block break-all text-xs">{badgeMd}</code>
        <CopyButton text={badgeMd} label="Copy badge markdown" />
        <div className="text-sm text-[var(--mut)]">
          Share report:{' '}
          <a className="text-[var(--lime)]" href={shareUrl}>
            {shareUrl}
          </a>
        </div>
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={badgeUrl} alt="ship score badge" height={20} />
      </section>

      <section>
        <h2 className="mono mb-3 text-lg font-bold">3 · Run scan</h2>
        {!project.verified && (
          <p className="mb-3 text-sm text-[var(--md)]">
            Prove ownership above before full scans will run.
          </p>
        )}
        <RunScanForm projectId={project.id} authReady={auth.ready} />
      </section>
    </div>
  );
}

import { eq } from 'drizzle-orm';
import { verifyGithubWebhookSignature, postCheckRun, postPrComment, policyConclusion } from '@/lib/github-app';
import { getDb, schema } from '@/lib/db';
import { enqueueScan, parseFindings } from '@/lib/scans';
import { planOf } from '@/lib/plans';
import { config } from '@/lib/config';
import { json, errorResponse } from '@/lib/http';
import { resolveWebhookTarget, webhookHostMismatchSummary } from '@/lib/webhook-target';

export async function POST(req: Request) {
  try {
    const rawBody = await req.text();
    const signature = req.headers.get('x-hub-signature-256');
    if (!verifyGithubWebhookSignature(rawBody, signature)) {
      return json({ error: 'Invalid signature' }, 401);
    }

    const event = req.headers.get('x-github-event');
    const payload = JSON.parse(rawBody) as Record<string, unknown>;

    if (event === 'ping') return json({ ok: true, zen: true });

    // deployment_status → run ship check against environment URL
    if (event === 'deployment_status') {
      const deployment = payload.deployment as { payload?: { web_url?: string }; environment?: string; sha?: string } | undefined;
      const deploymentStatus = payload.deployment_status as { state?: string; environment_url?: string; target_url?: string } | undefined;
      const repository = payload.repository as { full_name?: string } | undefined;
      const installation = payload.installation as { id?: number } | undefined;

      if (deploymentStatus?.state !== 'success') return json({ ok: true, skipped: 'not_success' });

      const repo = repository?.full_name;
      if (!repo) return json({ ok: true, skipped: 'no_repo' });

      const db = await getDb();
      const projects = await db.select().from(schema.projects).where(eq(schema.projects.githubRepo, repo)).limit(5);
      if (!projects.length) return json({ ok: true, skipped: 'no_project' });

      const results = [];
      for (const project of projects) {
        if (!project.shipCheckEnabled) continue;
        if (!project.verified) continue;
        const users = await db.select().from(schema.users).where(eq(schema.users.id, project.userId)).limit(1);
        const user = users[0];
        if (!user || !planOf(user.plan).githubApp) continue;

        const candidate =
          deploymentStatus.environment_url ||
          deploymentStatus.target_url ||
          deployment?.payload?.web_url;
        const target = resolveWebhookTarget(project, candidate);
        if (!target.ok) {
          // Reject — do not fall back to project.url (that would scan production
          // and report a false pass for an untested preview).
          if (installation?.id && deployment?.sha) {
            const [owner, name] = repo.split('/');
            await postCheckRun({
              installationId: String(installation.id),
              owner,
              repo: name,
              headSha: deployment.sha,
              conclusion: 'neutral',
              title: 'Scan skipped — host mismatch',
              summary: webhookHostMismatchSummary(project),
            });
          }
          results.push({ projectId: project.id, skipped: target.code });
          continue;
        }

        const scan = await enqueueScan({
          user,
          project,
          url: target.url,
          mode: project.policy === 'launch' ? 'crawl' : 'full',
          trigger: 'github',
          authorized: project.verified,
          meta: { sha: deployment?.sha, repo, installationId: installation?.id },
          runInline: true,
        });

        const findings = parseFindings(scan);
        let baselineDiff: { newFailures?: { severity: string }[] } = {};
        try {
          baselineDiff = scan.baselineDiffJson ? JSON.parse(scan.baselineDiffJson) : {};
        } catch { /* */ }
        const newHighs = (baselineDiff.newFailures || []).filter((f) => f.severity === 'high').length;
        const newMediums = (baselineDiff.newFailures || []).filter((f) => f.severity === 'medium').length;
        const conclusion = policyConclusion(project.policy, newHighs, newMediums);

        if (installation?.id && deployment?.sha) {
          const [owner, name] = repo.split('/');
          await postCheckRun({
            installationId: String(installation.id),
            owner,
            repo: name,
            headSha: deployment.sha,
            conclusion,
            title: `VibeTesting Agent ${scan.grade || '?'} (${scan.score ?? '—'}/100)`,
            summary: `URL: ${scan.url}\nNew highs: ${newHighs}\nNew mediums: ${newMediums}\n[Open report](${config.appUrl}/dashboard/scans/${scan.id})`,
            detailsUrl: `${config.appUrl}/dashboard/scans/${scan.id}`,
          });
        }

        results.push({ projectId: project.id, scanId: scan.id, conclusion, findings: findings.length });
      }
      return json({ ok: true, results });
    }

    // pull_request — optional comment with last project score pointer
    if (event === 'pull_request') {
      const action = payload.action as string;
      if (!['opened', 'synchronize', 'reopened'].includes(action)) return json({ ok: true, skipped: action });
      const repository = payload.repository as { full_name?: string } | undefined;
      const pull = payload.pull_request as { number?: number; head?: { sha?: string } } | undefined;
      const installation = payload.installation as { id?: number } | undefined;
      const repo = repository?.full_name;
      if (!repo || !pull?.number || !installation?.id) return json({ ok: true, skipped: 'incomplete' });

      const db = await getDb();
      const projects = await db.select().from(schema.projects).where(eq(schema.projects.githubRepo, repo)).limit(1);
      const project = projects[0];
      if (!project?.shipCheckEnabled) return json({ ok: true, skipped: 'no_project' });

      const [owner, name] = repo.split('/');
      await postPrComment({
        installationId: String(installation.id),
        owner,
        repo: name,
        issueNumber: pull.number,
        body: [
          `### VibeTesting Agent`,
          `Production target: \`${project.url}\``,
          project.lastGrade
            ? `Last ship score: **${project.lastGrade}** (${project.lastScore}/100)`
            : `No scans yet — add a deploy webhook or run a manual scan.`,
          ``,
          `Ship Check runs on successful deployments (every software update).`,
          `[Open dashboard](${config.appUrl}/dashboard/projects/${project.id})`,
        ].join('\n'),
      });
      return json({ ok: true });
    }

    return json({ ok: true, ignored: event });
  } catch (err) {
    return errorResponse(err);
  }
}

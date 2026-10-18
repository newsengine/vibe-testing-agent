import { eq } from 'drizzle-orm';
import { getProjectByWebhookSecret } from '@/lib/projects';
import { enqueueScan } from '@/lib/scans';
import { getDb, schema } from '@/lib/db';
import { planOf } from '@/lib/plans';
import { json, errorResponse, clientIp } from '@/lib/http';
import { rateLimit } from '@/lib/rate-limit';
import { audit } from '@/lib/audit';
import { resolveWebhookTarget } from '@/lib/webhook-target';

/**
 * Generic deploy webhook — call after every software update:
 *   POST /api/webhooks/deploy/:secret
 *   Optional JSON: { url?, sha?, environment? }
 * Also accepts Vercel-style deployment payloads.
 */
export async function POST(req: Request, ctx: { params: Promise<{ secret: string }> }) {
  try {
    const { secret } = await ctx.params;
    const project = await getProjectByWebhookSecret(secret);
    if (!project) return json({ error: 'Unknown webhook' }, 404);
    if (!project.shipCheckEnabled) return json({ ok: true, skipped: 'ship_check_disabled' });

    const db = await getDb();
    const users = await db.select().from(schema.users).where(eq(schema.users.id, project.userId)).limit(1);
    const user = users[0];
    if (!user) return json({ error: 'User missing' }, 500);

    const plan = planOf(user.plan);
    if (!project.verified) {
      return json({ error: 'Project ownership must be verified before deploy scans', code: 'verify' }, 403);
    }
    // commit plan = every push; daily = deploy hooks; weekly has no auto hooks
    if (!plan.deployHooks && !plan.commitHooks) {
      return json(
        {
          error: 'Deploy/commit hooks require Daily ($100) or Every commit ($250) plan',
          code: 'upgrade',
        },
        402,
      );
    }

    const ip = clientIp(req);
    const burst = plan.commitHooks ? 60 : 20;
    const rl = await rateLimit(`deploy:${project.id}:${ip}`, burst, 60_000);
    if (!rl.ok) return json({ error: 'Rate limited' }, 429);

    let body: Record<string, unknown> = {};
    try {
      body = (await req.json()) as Record<string, unknown>;
    } catch {
      body = {};
    }

    // Vercel deployment webhook shape
    const vercelUrl =
      (body?.payload as { deployment?: { url?: string } } | undefined)?.deployment?.url ||
      (body?.url as string | undefined);
    const candidate = typeof vercelUrl === 'string' ? vercelUrl : undefined;
    const target = resolveWebhookTarget(project, candidate);
    if (!target.ok) {
      // Reject — do not fall back to project.url (that would scan production
      // and report a false pass for an untested preview).
      return json({ error: target.error, code: target.code }, 400);
    }

    const mode = project.policy === 'launch' ? 'crawl' : project.policy === 'client' ? 'full' : 'full';

    const scan = await enqueueScan({
      user,
      project,
      url: target.url,
      mode: mode as 'full' | 'crawl',
      trigger: 'deploy',
      authorized: project.verified,
      meta: body,
      runInline: true,
    });

    await audit('webhook.deploy', {
      userId: user.id,
      target: project.id,
      detail: { scanId: scan.id, url: target.url },
      ip,
    });

    return json({ ok: true, scanId: scan.id, status: scan.status, score: scan.score, grade: scan.grade });
  } catch (err) {
    return errorResponse(err);
  }
}

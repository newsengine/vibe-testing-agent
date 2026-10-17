import { eq, count } from 'drizzle-orm';
import { getDb, schema } from './db';
import { planOf, type PlanLimits, type ScanMode, type PlanId } from './plans';
import { monthKey, QuotaError, ForbiddenError } from './auth';
import type { User, Project } from './db/schema';

export async function getEntitlements(user: User): Promise<
  PlanLimits & {
    scansUsed: number;
    crawlUsed: number;
    scansRemaining: number;
    crawlRemaining: number;
    projectCount: number;
  }
> {
  const plan = planOf(user.plan);
  const db = await getDb();
  const mk = monthKey();
  let scansUsed = user.scansUsedMonth;
  let crawlUsed = user.crawlUsedMonth;
  if (user.usageMonth !== mk) {
    scansUsed = 0;
    crawlUsed = 0;
  }
  const [{ value: projectCount }] = await db
    .select({ value: count() })
    .from(schema.projects)
    .where(eq(schema.projects.userId, user.id));

  return {
    ...plan,
    scansUsed,
    crawlUsed,
    scansRemaining: Math.max(0, plan.scansPerMonth - scansUsed),
    crawlRemaining: Math.max(0, plan.crawlPerMonth - crawlUsed),
    projectCount: Number(projectCount),
  };
}

export async function assertCanCreateProject(user: User): Promise<void> {
  const e = await getEntitlements(user);
  if (e.maxProjects <= 0) {
    throw new QuotaError('Add a paid plan to create verified projects and run full scans.');
  }
  if (e.projectCount >= e.maxProjects) {
    throw new QuotaError(
      `Project limit reached (${e.maxProjects} on ${e.name}). Upgrade for more apps at /dashboard/billing.`,
    );
  }
}

/**
 * Ownership + plan gates for full scans.
 * Lite public scans skip this (no user / free mode).
 */
export async function assertCanScan(
  user: User,
  mode: ScanMode,
  opts: { project?: Project | null; isLite?: boolean } = {},
): Promise<void> {
  const e = await getEntitlements(user);

  if (opts.isLite || mode === 'lite') {
    if (e.scansRemaining <= 0 && user.plan === 'free') {
      throw new QuotaError('Lite scan quota exhausted. Sign up for Weekly ($25) or higher.');
    }
    return;
  }

  if (!e.modes.includes(mode)) {
    throw new ForbiddenError(`Mode "${mode}" is not included on the ${e.name} plan.`);
  }

  // Ownership: paid full scans require verified project
  if (e.requireOwnership) {
    if (!opts.project) {
      throw new ForbiddenError(
        'Full scans require a verified project you own. Add a project and prove ownership via domain email or DNS TXT.',
      );
    }
    if (!opts.project.verified) {
      throw new ForbiddenError(
        'Prove ownership first: sign in with an email on your domain and click the inbox verify link, or add DNS TXT vibetesting-verify=…',
      );
    }
  }

  if (mode === 'crawl' && e.crawlRemaining <= 0) {
    throw new QuotaError('Crawl scan quota exhausted for this month.');
  }
  if (e.scansRemaining <= 0) {
    throw new QuotaError(
      `Scan quota exhausted (${e.scansPerMonth}/mo on ${e.name}). Upgrade or wait for next month.`,
    );
  }

  // Cadence: weekly / daily min interval
  if (e.minHoursBetweenScans > 0 && opts.project?.lastScanAt) {
    const elapsedH =
      (Date.now() - new Date(opts.project.lastScanAt).getTime()) / (1000 * 60 * 60);
    if (elapsedH < e.minHoursBetweenScans) {
      const wait = Math.ceil(e.minHoursBetweenScans - elapsedH);
      throw new QuotaError(
        `Plan cadence: next full scan available in ~${wait}h (${e.name} = ${e.tagline}).`,
      );
    }
  }

  // Commit plan required for commit-trigger density is enforced at webhook
  if (opts.project && !e.commitHooks && false) {
    /* webhook checks commitHooks */
  }
}

export async function consumeScanQuota(userId: string, mode: ScanMode): Promise<void> {
  const db = await getDb();
  const users = await db.select().from(schema.users).where(eq(schema.users.id, userId)).limit(1);
  const user = users[0];
  if (!user) return;
  const mk = monthKey();
  const reset = user.usageMonth !== mk;
  await db
    .update(schema.users)
    .set({
      usageMonth: mk,
      scansUsedMonth: (reset ? 0 : user.scansUsedMonth) + 1,
      crawlUsedMonth: (reset ? 0 : user.crawlUsedMonth) + (mode === 'crawl' ? 1 : 0),
      updatedAt: new Date(),
    })
    .where(eq(schema.users.id, userId));
}

export async function setUserPlan(
  userId: string,
  plan: PlanId | 'vibe' | 'studio' | 'free',
  opts: { subscriptionId?: string | null; status?: string } = {},
): Promise<void> {
  const normalized: PlanId =
    plan === 'vibe' ? 'weekly' : plan === 'studio' ? 'daily' : (plan as PlanId);
  const db = await getDb();
  await db
    .update(schema.users)
    .set({
      plan: normalized,
      planStatus: opts.status || 'active',
      stripeSubscriptionId: opts.subscriptionId ?? null,
      updatedAt: new Date(),
    })
    .where(eq(schema.users.id, userId));
}

/**
 * Gap analysis checks: determine which checks can run based on project verification status.
 * Passive checks (dns.dkim, csrf.token, disclosure.pii-in-response) run without verification.
 * Active checks (auth.*, authz.*, api.*, agent.*, upload.*, db.*, storage.*) require verified ownership.
 */
export const PASSIVE_GAP_CHECKS = new Set([
  'dns.dkim',
  'csrf.token',
  'disclosure.pii-in-response',
]);

export const VERIFIED_GAP_CHECKS = new Set([
  'auth.login-rate-limit',
  'auth.reset-token-reuse',
  'auth.session-invalidation',
  'auth.email-plus-alias',
  'authz.idor-sequential',
  'api.webhook-unsigned',
  'api.idempotency',
  'api.key-revocation',
  'agent.prompt-injection',
  'agent.llm-data-leak',
  'agent.llm-rate-limit',
  'upload.content-type',
  'db.firebase-rules',
  'storage.public-bucket',
  'exposure.preview-deployments',
  'repo.secrets',
]);

export function canRunGapCheck(checkId: string, verified: boolean): boolean {
  if (PASSIVE_GAP_CHECKS.has(checkId)) return true;
  if (VERIFIED_GAP_CHECKS.has(checkId)) return verified;
  return true;
}

/**
 * Nightly full crawls for verified projects on plans that include cadence.
 * Reuses enqueueScan + minHoursBetweenScans — does not invent a parallel queue.
 */
import { and, desc, eq } from 'drizzle-orm';
import { getDb, schema } from './db';
import { planOf } from './plans';
import { enqueueScan } from './scans';
import { dueForScheduledCrawl, scheduledModeForPlan } from './schedule-policy';

export {
  dueForScheduledCrawl,
  scheduledModeForPlan,
  webhookScanMode,
  NIGHTLY_FLOOR_HOURS,
} from './schedule-policy';

export async function enqueueDueScheduledCrawls(): Promise<{
  enqueued: number;
  skipped: number;
  errors: number;
}> {
  const db = await getDb();
  const projects = await db.select().from(schema.projects);
  let enqueued = 0;
  let skipped = 0;
  let errors = 0;
  const now = Date.now();

  for (const project of projects) {
    if (!project.verified) {
      skipped++;
      continue;
    }
    const users = await db.select().from(schema.users).where(eq(schema.users.id, project.userId)).limit(1);
    const user = users[0];
    if (!user) {
      skipped++;
      continue;
    }
    const plan = planOf(user.plan);
    const mode = scheduledModeForPlan(plan.modes);
    if (!mode) {
      skipped++;
      continue;
    }

    const recent = await db
      .select()
      .from(schema.scans)
      .where(and(eq(schema.scans.projectId, project.id), eq(schema.scans.trigger, 'schedule')))
      .orderBy(desc(schema.scans.createdAt))
      .limit(1);
    const lastScheduledAtMs = recent[0]?.createdAt ? new Date(recent[0].createdAt).getTime() : null;

    if (!dueForScheduledCrawl({
      verified: project.verified,
      planModes: plan.modes,
      minHoursBetweenScans: plan.minHoursBetweenScans,
      lastScheduledAtMs,
      nowMs: now,
    })) {
      skipped++;
      continue;
    }

    try {
      await enqueueScan({
        user,
        project,
        url: project.url,
        mode,
        trigger: 'schedule',
        authorized: project.verified,
        meta: { reason: 'nightly-cadence' },
      });
      enqueued++;
    } catch {
      errors++;
    }
  }

  return { enqueued, skipped, errors };
}

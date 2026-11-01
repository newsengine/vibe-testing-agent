import { and, desc, eq, isNull } from 'drizzle-orm';
import { getDb, schema } from './db';
import { id } from './ids';
import { audit } from './audit';
import { evaluateFlaky, FLAKY_WINDOW_SCANS, type CheckOutcome } from './flaky';
import type { Finding } from './scanner';

export async function listActiveQuarantine(projectId: string) {
  const db = await getDb();
  return db
    .select()
    .from(schema.quarantinedChecks)
    .where(and(eq(schema.quarantinedChecks.projectId, projectId), isNull(schema.quarantinedChecks.unquarantinedAt)));
}

export async function isCheckQuarantined(projectId: string, target: string, checkId: string): Promise<boolean> {
  const db = await getDb();
  const rows = await db
    .select()
    .from(schema.quarantinedChecks)
    .where(
      and(
        eq(schema.quarantinedChecks.projectId, projectId),
        eq(schema.quarantinedChecks.target, target),
        eq(schema.quarantinedChecks.checkId, checkId),
        isNull(schema.quarantinedChecks.unquarantinedAt),
      ),
    )
    .limit(1);
  return Boolean(rows[0]);
}

export function labelQuarantined(findings: Finding[], quarantinedIds: Set<string>): Finding[] {
  return findings.map((f) => {
    if (!quarantinedIds.has(f.id)) return f;
    return {
      ...f,
      quarantined: true,
      title: f.title.startsWith('[quarantined]') ? f.title : `[quarantined] ${f.title}`,
    };
  });
}

export async function recordScanQuarantine(input: {
  projectId: string;
  userId: string;
  scanId: string;
  target: string;
  findings: Finding[];
  deployFingerprint?: string | null;
}): Promise<Finding[]> {
  const db = await getDb();
  const now = new Date();
  const fingerprint = input.deployFingerprint ?? '';

  for (const f of input.findings) {
    if (f.inconclusive) continue;
    await db.insert(schema.checkHistory).values({
      id: id('hst'),
      projectId: input.projectId,
      target: input.target,
      checkId: f.id,
      pass: f.pass,
      severity: f.severity,
      scanId: input.scanId,
      deployFingerprint: fingerprint,
      createdAt: now,
    });

    const rows = await db
      .select()
      .from(schema.checkHistory)
      .where(
        and(
          eq(schema.checkHistory.projectId, input.projectId),
          eq(schema.checkHistory.target, input.target),
          eq(schema.checkHistory.checkId, f.id),
        ),
      )
      .orderBy(desc(schema.checkHistory.createdAt))
      .limit(FLAKY_WINDOW_SCANS);

    const history: CheckOutcome[] = [...rows].reverse().map((r) => ({
      checkId: r.checkId,
      target: r.target,
      pass: r.pass,
      severity: r.severity || 'info',
      at: new Date(r.createdAt).toISOString(),
      deployFingerprint: r.deployFingerprint,
    }));

    const verdict = evaluateFlaky(history);
    if (!verdict.flaky) continue;

    const already = await isCheckQuarantined(input.projectId, input.target, f.id);
    if (already) continue;
    await db.insert(schema.quarantinedChecks).values({
      id: id('qrn'),
      projectId: input.projectId,
      target: input.target,
      checkId: f.id,
      reason: verdict.reason,
      quarantinedAt: now,
      unquarantinedAt: null,
      auto: true,
    });
    await audit('check.quarantined', {
      userId: input.userId,
      target: input.projectId,
      detail: { checkId: f.id, url: input.target, reason: verdict.reason },
    });
  }

  const active = await listActiveQuarantine(input.projectId);
  const ids = new Set(active.filter((q) => q.target === input.target).map((q) => q.checkId));
  return labelQuarantined(input.findings, ids);
}

export async function unquarantineCheck(input: {
  projectId: string;
  userId: string;
  quarantineId: string;
}): Promise<boolean> {
  const db = await getDb();
  const rows = await db
    .select()
    .from(schema.quarantinedChecks)
    .where(
      and(
        eq(schema.quarantinedChecks.id, input.quarantineId),
        eq(schema.quarantinedChecks.projectId, input.projectId),
      ),
    )
    .limit(1);
  const row = rows[0];
  if (!row || row.unquarantinedAt) return false;
  await db
    .update(schema.quarantinedChecks)
    .set({ unquarantinedAt: new Date() })
    .where(eq(schema.quarantinedChecks.id, row.id));
  await audit('check.unquarantined', {
    userId: input.userId,
    target: input.projectId,
    detail: { checkId: row.checkId, quarantineId: row.id },
  });
  return true;
}

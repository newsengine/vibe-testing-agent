import { eq, desc, and, asc } from 'drizzle-orm';
import { getDb, schema } from './db';
import { id } from './ids';
import { assertCanScan, consumeScanQuota } from './entitlements';
import { runScan, buildFixPack, type Finding, type ScanResult } from './scanner';
import { buildSecurityReviewHtml } from './security-review';
import { audit } from './audit';
import { notifyScanComplete } from './notify';
import { recordRun } from './test-ledger';
import { config } from './config';
import { assertSafeScanUrl } from './url-safety';
import { resolveAuthHeaders } from './project-auth';
import type { User, Project, Scan } from './db/schema';
import type { ScanMode } from './plans';

export interface EnqueueScanInput {
  user: User;
  project?: Project | null;
  url: string;
  mode?: ScanMode;
  trigger?: 'manual' | 'api' | 'mcp' | 'deploy' | 'github' | 'schedule' | 'rescan';
  authorized: boolean;
  meta?: Record<string, unknown>;
  /**
   * Force edge/local inline processing.
   * Default: lite always inline; full/fast/crawl queue to OVH agent when SCAN_AGENT_SECRET is set.
   */
  runInline?: boolean;
}

/** Lite/acquisition runs on Workers; full suite goes to jclaw1 when agent is configured. */
function shouldRunInline(mode: ScanMode, runInline?: boolean): boolean {
  if (runInline === true) return true;
  if (runInline === false) return false;
  if (mode === 'lite') return true;
  // Full scans need OVH agent when secret is configured (production Workers)
  if (config.scanAgentSecret) return false;
  // Local dev without agent: run inline (monorepo probe or worker scan)
  return true;
}

export async function enqueueScan(input: EnqueueScanInput) {
  const mode = input.mode || 'fast';
  if (!input.authorized) {
    throw new Error('Authorization required: you must confirm you own or may test this target.');
  }

  const safe = assertSafeScanUrl(input.url);
  if (!safe.ok) throw new Error(`Unsafe scan target: ${safe.reason}`);
  const safeUrl = safe.url;

  await assertCanScan(input.user, mode, {
    project: input.project,
    isLite: mode === 'lite',
  });

  const db = await getDb();
  const scanId = id('scn');
  const now = new Date();
  await db.insert(schema.scans).values({
    id: scanId,
    userId: input.user.id,
    projectId: input.project?.id ?? null,
    url: safeUrl,
    mode,
    trigger: input.trigger || 'manual',
    status: 'queued',
    authorized: true,
    createdAt: now,
    metaJson: input.meta ? JSON.stringify(input.meta) : null,
  });

  await audit('scan.enqueued', {
    userId: input.user.id,
    target: safeUrl,
    detail: {
      scanId,
      mode,
      trigger: input.trigger,
      runner: shouldRunInline(mode, input.runInline) ? 'edge' : 'ovh-jclaw1',
      hostname: safe.hostname,
    },
  });

  if (shouldRunInline(mode, input.runInline)) {
    await processScan(scanId);
  }

  const rows = await db.select().from(schema.scans).where(eq(schema.scans.id, scanId)).limit(1);
  return rows[0]!;
}

export async function processScan(scanId: string): Promise<void> {
  const db = await getDb();
  const rows = await db.select().from(schema.scans).where(eq(schema.scans.id, scanId)).limit(1);
  const scan = rows[0];
  if (!scan || scan.status === 'running' || scan.status === 'completed') return;

  await db
    .update(schema.scans)
    .set({ status: 'running', startedAt: new Date() })
    .where(eq(schema.scans.id, scanId));

  try {
    let baselineIds: string[] | null = null;
    let extraHeaders: Record<string, string> | undefined;
    let verified = false;
    if (scan.projectId) {
      const prows = await db.select().from(schema.projects).where(eq(schema.projects.id, scan.projectId)).limit(1);
      const project = prows[0];
      verified = project?.verified === true;
      if (project?.baselineJson) {
        try {
          baselineIds = JSON.parse(project.baselineJson) as string[];
        } catch {
          baselineIds = null;
        }
      }
      if (project) {
        const auth = await resolveAuthHeaders(project);
        if (auth) extraHeaders = auth;
      }
    }

    const result = await runScan(scan.url, {
      mode: scan.mode as ScanMode,
      baselineIds,
      extraHeaders,
      verified,
    });

    await finalizeScanSuccess(scan, result);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await finalizeScanFailure(scan, message);
  }
}

/** Claim next queued full scan for OVH agent. */
export async function claimNextScan(agentId: string): Promise<Scan | null> {
  const db = await getDb();
  const queued = await db
    .select()
    .from(schema.scans)
    .where(eq(schema.scans.status, 'queued'))
    .orderBy(asc(schema.scans.createdAt))
    .limit(1);
  const scan = queued[0];
  if (!scan) return null;

  // Prefer non-lite for agent; if only lite left, agent can skip (edge handles lite)
  if (scan.mode === 'lite') return null;

  await db
    .update(schema.scans)
    .set({
      status: 'running',
      startedAt: new Date(),
      metaJson: JSON.stringify({
        ...(safeJson(scan.metaJson) || {}),
        claimedBy: agentId,
        claimedAt: new Date().toISOString(),
      }),
    })
    .where(and(eq(schema.scans.id, scan.id), eq(schema.scans.status, 'queued')));

  // re-read — if another agent won, status may still be queued for them; check claimedBy
  const again = await db.select().from(schema.scans).where(eq(schema.scans.id, scan.id)).limit(1);
  const claimed = again[0];
  if (!claimed || claimed.status !== 'running') return null;
  const meta = safeJson(claimed.metaJson) as { claimedBy?: string } | null;
  if (meta?.claimedBy && meta.claimedBy !== agentId) return null;
  return claimed;
}

export async function completeAgentScan(
  scanId: string,
  payload: {
    agentId: string;
    score: number;
    grade: string;
    summary: ScanResult['summary'];
    findings: Finding[];
    fixPackMarkdown?: string;
    reportHtml?: string;
    baselineDiff?: ScanResult['baselineDiff'];
    error?: string;
  },
): Promise<Scan | null> {
  const db = await getDb();
  const rows = await db.select().from(schema.scans).where(eq(schema.scans.id, scanId)).limit(1);
  const scan = rows[0];
  if (!scan) return null;

  if (payload.error) {
    await finalizeScanFailure(scan, payload.error);
    return (await db.select().from(schema.scans).where(eq(schema.scans.id, scanId)).limit(1))[0] ?? null;
  }

  const result: ScanResult = {
    url: scan.url,
    findings: payload.findings,
    summary: payload.summary,
    score: payload.score,
    grade: payload.grade,
    fixPackMarkdown: payload.fixPackMarkdown || '',
    reportHtml: payload.reportHtml || '',
    baselineDiff: payload.baselineDiff || { newFailures: [], resolved: [], stillFailing: [] },
  };

  await finalizeScanSuccess(scan, result, { agentId: payload.agentId });
  return (await db.select().from(schema.scans).where(eq(schema.scans.id, scanId)).limit(1))[0] ?? null;
}

async function finalizeScanSuccess(
  scan: Scan,
  result: ScanResult,
  extra?: { agentId?: string },
): Promise<void> {
  const db = await getDb();
  await consumeScanQuota(scan.userId, scan.mode as ScanMode);
  const failingIds = result.findings.filter((f) => !f.pass).map((f) => f.id);

  // Always materialize Claude /security-review + HTML twin at end of run
  const reviewOpts = {
    mode: scan.mode,
    scanId: scan.id,
    suite: `VibeTesting Agent ${scan.mode} suite`,
  };
  const fixPackMarkdown = buildFixPack(
    scan.url,
    result.findings,
    result.score,
    result.grade,
    reviewOpts,
  );
  const reportHtml = buildSecurityReviewHtml(
    scan.url,
    result.findings,
    result.score,
    result.grade,
    reviewOpts,
  );

  await db
    .update(schema.scans)
    .set({
      status: 'completed',
      score: result.score,
      grade: result.grade,
      summaryJson: JSON.stringify(result.summary),
      findingsJson: JSON.stringify(result.findings),
      fixPackMarkdown,
      reportHtml,
      baselineDiffJson: JSON.stringify(result.baselineDiff),
      finishedAt: new Date(),
      error: null,
      metaJson: JSON.stringify({
        ...(safeJson(scan.metaJson) || {}),
        ...(extra?.agentId ? { completedBy: extra.agentId } : { completedBy: 'edge' }),
        registryNote: extra?.agentId ? 'full-vibetesting-agent-ovh' : 'edge-or-local',
        securityReview: true,
        securityReviewFormat: 'claude-/security-review',
      }),
    })
    .where(eq(schema.scans.id, scan.id));

  let project: Project | null = null;
  if (scan.projectId) {
    const prows = await db.select().from(schema.projects).where(eq(schema.projects.id, scan.projectId)).limit(1);
    project = prows[0] ?? null;
    if (project) {
      await db
        .update(schema.projects)
        .set({
          lastScore: result.score,
          lastGrade: result.grade,
          lastScanAt: new Date(),
          baselineJson: JSON.stringify(failingIds),
          updatedAt: new Date(),
        })
        .where(eq(schema.projects.id, project.id));
    }
  }

  await audit('scan.completed', {
    userId: scan.userId,
    target: scan.url,
    detail: { scanId: scan.id, score: result.score, grade: result.grade, agentId: extra?.agentId },
  });

  // #32 — log this run + every sub-test (keyed by VTA number) to the ledger. Non-fatal by contract.
  await recordRun({
    scanId: scan.id, userId: scan.userId, projectId: scan.projectId, target: scan.url,
    actor: extra?.agentId || 'edge', trigger: scan.trigger, findings: result.findings,
    startedAt: scan.startedAt ?? undefined, finishedAt: new Date(),
  });

  const users = await db.select().from(schema.users).where(eq(schema.users.id, scan.userId)).limit(1);
  if (users[0]) {
    await notifyScanComplete(users[0], {
      scanId: scan.id,
      url: scan.url,
      score: result.score,
      grade: result.grade,
      summary: result.summary,
      newHighs: result.baselineDiff.newFailures.filter((f) => f.severity === 'high').length,
      projectName: project?.name,
    });
  }
}

async function finalizeScanFailure(scan: Scan, message: string): Promise<void> {
  const db = await getDb();
  await db
    .update(schema.scans)
    .set({ status: 'failed', error: message, finishedAt: new Date() })
    .where(eq(schema.scans.id, scan.id));
  await audit('scan.failed', {
    userId: scan.userId,
    target: scan.url,
    detail: { scanId: scan.id, error: message },
  });
}

function safeJson(s: string | null): Record<string, unknown> | null {
  if (!s) return null;
  try {
    return JSON.parse(s) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export async function getScanForUser(scanId: string, userId: string) {
  const db = await getDb();
  const rows = await db
    .select()
    .from(schema.scans)
    .where(and(eq(schema.scans.id, scanId), eq(schema.scans.userId, userId)))
    .limit(1);
  return rows[0] ?? null;
}

export async function listScansForUser(userId: string, limit = 50) {
  const db = await getDb();
  return db
    .select()
    .from(schema.scans)
    .where(eq(schema.scans.userId, userId))
    .orderBy(desc(schema.scans.createdAt))
    .limit(limit);
}

export function parseFindings(scan: { findingsJson: string | null }): Finding[] {
  if (!scan.findingsJson) return [];
  try {
    return JSON.parse(scan.findingsJson) as Finding[];
  } catch {
    return [];
  }
}

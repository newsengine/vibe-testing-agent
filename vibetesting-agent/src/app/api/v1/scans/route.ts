import { z } from 'zod';
import { eq } from 'drizzle-orm';
import { resolveRequestUser, AuthError } from '@/lib/auth';
import { enqueueScan, listScansForUser } from '@/lib/scans';
import { getProject } from '@/lib/projects';
import { getDb, schema } from '@/lib/db';
import { json, errorResponse, readJson, clientIp } from '@/lib/http';
import { rateLimit } from '@/lib/rate-limit';
import { planOf } from '@/lib/plans';

const createSchema = z.object({
  url: z.string().min(3).max(500).optional(),
  projectId: z.string().optional(),
  mode: z.enum(['lite', 'smoke', 'fast', 'full', 'crawl']).optional(),
  authorized: z.boolean(),
  trigger: z.enum(['manual', 'api', 'mcp', 'deploy', 'github', 'schedule', 'rescan']).optional(),
});

export async function GET(req: Request) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const scans = await listScansForUser(user.id);
    return json({
      scans: scans.map((s) => ({
        id: s.id,
        projectId: s.projectId,
        url: s.url,
        mode: s.mode,
        trigger: s.trigger,
        status: s.status,
        score: s.score,
        grade: s.grade,
        createdAt: s.createdAt,
        finishedAt: s.finishedAt,
        error: s.error,
      })),
    });
  } catch (err) {
    return errorResponse(err);
  }
}

export async function POST(req: Request) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const ip = clientIp(req);
    const rl = await rateLimit(`scan:${user.id}:${ip}`, 10, 60_000);
    if (!rl.ok) return json({ error: 'Rate limited' }, 429);

    const body = createSchema.parse(await readJson(req));
    if (!body.authorized) {
      return json({ error: 'You must confirm authorization to scan this target.' }, 400);
    }

    let project = null;
    let url = body.url;
    if (body.projectId) {
      project = await getProject(user.id, body.projectId);
      if (!project) return json({ error: 'Project not found' }, 404);
      url = project.url;
      if (!project.verified && planOf(user.plan).id !== 'free') {
        // paid plans should verify for deploy hooks; still allow manual
      }
    }
    if (!url) return json({ error: 'url or projectId required' }, 400);
    if (!/^https?:\/\//i.test(url)) url = `https://${url}`;

    // Lite/acquisition on edge; full modes queue to OVH jclaw1 when SCAN_AGENT_SECRET is set
    const mode = body.mode || 'full';
    const scan = await enqueueScan({
      user,
      project,
      url,
      mode,
      trigger: body.trigger || 'api',
      authorized: true,
      // only force edge when explicitly lite
      runInline: mode === 'lite' ? true : undefined,
    });

    return json(
      {
        scan: {
          id: scan.id,
          status: scan.status,
          url: scan.url,
          mode: scan.mode,
          score: scan.score,
          grade: scan.grade,
          error: scan.error,
        },
      },
      201,
    );
  } catch (err) {
    return errorResponse(err);
  }
}

import { z } from 'zod';
import { resolveRequestUser, AuthError } from '@/lib/auth';
import { getProject } from '@/lib/projects';
import { json, errorResponse, readJson } from '@/lib/http';
import { listActiveQuarantine, unquarantineCheck } from '@/lib/quarantine-store';

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    const project = await getProject(user.id, id);
    if (!project) return json({ error: 'Project not found' }, 404);
    const items = await listActiveQuarantine(project.id);
    return json({
      items,
      heuristic:
        'A check is flaky when its result flips twice in the last 5 scans of the same target with no deploy/config change. Two consecutive high-severity failures are never auto-quarantined. Quarantined checks still run and are reported but do not gate.',
    });
  } catch (err) {
    return errorResponse(err);
  }
}

const unq = z.object({ id: z.string().min(1) });

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    const project = await getProject(user.id, id);
    if (!project) return json({ error: 'Project not found' }, 404);
    const body = unq.parse(await readJson(req));
    const ok = await unquarantineCheck({ projectId: project.id, userId: user.id, quarantineId: body.id });
    if (!ok) return json({ error: 'Quarantine entry not found' }, 404);
    const items = await listActiveQuarantine(project.id);
    return json({ ok: true, items });
  } catch (err) {
    return errorResponse(err);
  }
}

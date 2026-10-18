import { resolveRequestUser, AuthError } from '@/lib/auth';
import { getProject, verifyProject } from '@/lib/projects';
import { describeOwnershipOptions } from '@/lib/ownership';
import { parseVerifyRequest } from '@/lib/verify-method';
import { json, errorResponse } from '@/lib/http';

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    const project = await getProject(user.id, id);
    if (!project) return json({ error: 'Project not found' }, 404);
    return json({
      project: {
        id: project.id,
        hostname: project.hostname,
        verified: project.verified,
        verifyMethod: project.verifyMethod,
      },
      ownership: describeOwnershipOptions(user, project),
    });
  } catch (err) {
    return errorResponse(err);
  }
}

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    const method = await parseVerifyRequest(req);
    const project = await verifyProject(user, id, method);
    return json({ project, verified: true, method: project.verifyMethod || method });
  } catch (err) {
    return errorResponse(err);
  }
}

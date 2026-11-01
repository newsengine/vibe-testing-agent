import { z } from 'zod';
import { resolveRequestUser, AuthError } from '@/lib/auth';
import { getProject } from '@/lib/projects';
import { json, errorResponse, readJson } from '@/lib/http';
import {
  addPreviewPattern,
  listPreviewPatterns,
  removePreviewPattern,
  describePreviewPatternRules,
} from '@/lib/preview-hosts';

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    const project = await getProject(user.id, id);
    if (!project) return json({ error: 'Project not found' }, 404);
    const patterns = await listPreviewPatterns(project.id);
    return json({ patterns, rules: describePreviewPatternRules() });
  } catch (err) {
    return errorResponse(err);
  }
}

const createSchema = z.object({
  pattern: z.string().min(1).max(253),
  method: z.enum(['dns', 'file', 'meta']).optional(),
});

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    const project = await getProject(user.id, id);
    if (!project) return json({ error: 'Project not found' }, 404);
    const body = createSchema.parse(await readJson(req));
    const added = await addPreviewPattern(project, body.pattern, { method: body.method });
    const patterns = await listPreviewPatterns(project.id);
    return json({ ok: true, added, patterns }, 201);
  } catch (err) {
    return errorResponse(err);
  }
}

const deleteSchema = z.object({
  id: z.string().min(1),
});

export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    const project = await getProject(user.id, id);
    if (!project) return json({ error: 'Project not found' }, 404);
    const body = deleteSchema.parse(await readJson(req));
    await removePreviewPattern(project, body.id);
    const patterns = await listPreviewPatterns(project.id);
    return json({ ok: true, patterns });
  } catch (err) {
    return errorResponse(err);
  }
}

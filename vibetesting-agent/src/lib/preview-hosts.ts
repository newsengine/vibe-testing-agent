import { eq, and } from 'drizzle-orm';
import { getDb, schema } from './db';
import { id } from './ids';
import { audit } from './audit';
import { verifyDomainOwnership } from './dns-verify';
import { verifyHostHttp, type HttpVerifyMethod } from './http-verify';
import {
  validatePreviewPattern,
  parsePreviewPattern,
  type PreviewPatternParse,
} from './preview-patterns';
import type { Project } from './db/schema';

export type PreviewVerifyMethod = 'dns' | 'file' | 'meta';

export async function listPreviewPatterns(projectId: string) {
  const db = await getDb();
  return db
    .select()
    .from(schema.projectPreviewPatterns)
    .where(eq(schema.projectPreviewPatterns.projectId, projectId));
}

export async function previewPatternStrings(projectId: string): Promise<string[]> {
  const rows = await listPreviewPatterns(projectId);
  return rows.filter((r) => r.verified).map((r) => r.pattern);
}

async function proveHost(
  hostname: string,
  token: string,
  method: PreviewVerifyMethod,
): Promise<{ ok: boolean; detail: string }> {
  if (method === 'dns') return verifyDomainOwnership(hostname, token);
  return verifyHostHttp(hostname, token, method as HttpVerifyMethod);
}

export async function addPreviewPattern(
  project: Project,
  rawPattern: string,
  opts: { method?: PreviewVerifyMethod } = {},
): Promise<{ pattern: string; proofHost: string; verifyMethod: string | null; detail: string }> {
  const parsed = parsePreviewPattern(rawPattern);
  if (!parsed.ok) throw new Error(parsed.error);

  const authorizedByProject = validatePreviewPattern(parsed.pattern, [project.hostname]);
  let verifyMethod: PreviewVerifyMethod | null = null;
  let detail = `Authorized by verified project host ${project.hostname}`;

  if (!authorizedByProject.ok) {
    if (!project.verified) {
      throw new Error('Verify the project host before adding preview patterns.');
    }
    const method = opts.method || 'dns';
    const proof = await proveHost(parsed.proofHost, project.verifyToken, method);
    if (!proof.ok) {
      throw new Error(
        `${authorizedByProject.error} Proof of ${parsed.proofHost} failed (${method}): ${proof.detail}`,
      );
    }
    verifyMethod = method;
    detail = proof.detail;
  } else if (!project.verified) {
    throw new Error('Verify the project host before adding preview patterns.');
  }

  const db = await getDb();
  const now = new Date();
  const rowId = id('pvp');
  await db.insert(schema.projectPreviewPatterns).values({
    id: rowId,
    projectId: project.id,
    pattern: parsed.pattern,
    proofHost: parsed.proofHost,
    verified: true,
    verifyMethod,
    createdAt: now,
    updatedAt: now,
  });
  await audit('project.preview_pattern_added', {
    userId: project.userId,
    target: project.id,
    detail: { pattern: parsed.pattern, proofHost: parsed.proofHost, method: verifyMethod },
  });
  return { pattern: parsed.pattern, proofHost: parsed.proofHost, verifyMethod, detail };
}

export async function removePreviewPattern(project: Project, patternId: string): Promise<void> {
  const db = await getDb();
  await db
    .delete(schema.projectPreviewPatterns)
    .where(
      and(
        eq(schema.projectPreviewPatterns.id, patternId),
        eq(schema.projectPreviewPatterns.projectId, project.id),
      ),
    );
  await audit('project.preview_pattern_removed', {
    userId: project.userId,
    target: project.id,
    detail: { patternId },
  });
}

export function describePreviewPatternRules(): { ok: PreviewPatternParse } | Record<string, unknown> {
  return {
    model:
      'A preview pattern may only be added if you have verified the parent domain or the specific preview host (DNS TXT, /.well-known/vibetesting-verify.txt, or a homepage meta tag). Shared platform apexes (pages.dev, vercel.app, netlify.app) are rejected as bare patterns.',
    examples: ['*.sparkle-forms.pages.dev', 'staging.example.com', '*.preview.example.com'],
    rejected: ['*.pages.dev', 'vercel.app', '*.netlify.app', '*.com'],
  };
}

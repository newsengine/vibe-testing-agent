import { resolveRequestUser, AuthError } from '@/lib/auth';
import { getScanForUser, parseFindings } from '@/lib/scans';
import { buildFixPack } from '@/lib/scanner';
import { json, errorResponse } from '@/lib/http';

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    const scan = await getScanForUser(id, user.id);
    if (!scan) return json({ error: 'Not found' }, 404);

    const url = new URL(req.url);
    const findingId = url.searchParams.get('findingId');
    const findings = parseFindings(scan);

    if (findingId) {
      const f = findings.find((x) => x.id === findingId);
      if (!f) return json({ error: 'Finding not found' }, 404);
      const prompt = [
        `Fix this VibeTesting Agent finding on ${scan.url}:`,
        ``,
        `ID: ${f.id}`,
        `Severity: ${f.severity}`,
        `Category: ${f.category}`,
        `Title: ${f.title}`,
        `Detail: ${f.detail}`,
        `Recommended fix: ${f.fix || 'Harden this surface safely.'}`,
        ``,
        `After fixing, verify with VibeTesting Agent rescan or: npx vibetesting-agent ${scan.url} --only ${f.category}`,
      ].join('\n');
      return json({ prompt, finding: f });
    }

    const markdown =
      scan.fixPackMarkdown ||
      buildFixPack(scan.url, findings, scan.score ?? 0, scan.grade ?? '?', {
        mode: scan.mode,
        scanId: scan.id,
      });
    return json({
      prompt: markdown,
      markdown,
      format: 'claude-/security-review',
      downloads: {
        markdown: `/api/v1/scans/${scan.id}/security-review?format=md`,
        pdf: `/api/v1/scans/${scan.id}/report.pdf`,
      },
    });
  } catch (err) {
    return errorResponse(err);
  }
}

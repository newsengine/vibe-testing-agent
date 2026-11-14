/**
 * Claude `/security-review` style agent report + printable PDF.
 * Shape matches vibetesting-agent agent-report (P1…Pn, standards, problem, where, fix, verify).
 */
import type { Finding } from './scanner';

const SEV_RANK: Record<Finding['severity'], number> = {
  high: 0,
  medium: 1,
  low: 2,
  info: 3,
};
const SEV_ICON: Record<Finding['severity'], string> = {
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

function whereHint(f: Finding): string {
  if (f.category === 'secrets') {
    return 'Browser-shipped JS / HTML — search the secret pattern; check env leakage in Next/Vite builds.';
  }
  if (f.category === 'exposure') {
    return 'Public HTTP paths and deploy config (static hosting rules, SPA catch-alls).';
  }
  if (f.category === 'dns') {
    return 'DNS zone at your registrar/CDN (Cloudflare, Route53, …).';
  }
  if (f.category === 'security') {
    return 'Response headers / TLS / cookies — middleware, `_headers`, reverse proxy, or framework config.';
  }
  if (f.category === 'framework') {
    return 'Stack-specific surface for the detected framework.';
  }
  if (f.category === 'agent') {
    return 'HTML + `/llms.txt` + `robots.txt` + `/.well-known` agent manifests.';
  }
  if (f.category === 'seo' || f.category === 'a11y' || f.category === 'performance' || f.category === 'reliability') {
    return 'App shell / marketing HTML and static assets.';
  }
  return `Category \`${f.category}\` — search the repo for related config/handlers.`;
}

function standardsLine(id: string): string {
  // Lightweight mapping without shipping full compliance tables
  if (id.startsWith('csp.') || id.includes('content-security')) return 'CWE-79 · OWASP A05 · ASVS V14.4.3 · WSTG-CONF-12';
  if (id.startsWith('header.') || id.startsWith('tls.')) return 'CWE-693 · OWASP A05 · ASVS V14.4 · WSTG-CONF-07';
  if (id.startsWith('dns.')) return 'CWE-290 · email/CA hygiene · DMARC/SPF/CAA';
  if (id.startsWith('secret.')) return 'CWE-798 · OWASP A07 · ASVS V2/V6';
  if (id.startsWith('exposure.')) return 'CWE-200 · OWASP A01 · WSTG-CONF';
  if (id.startsWith('open-redirect') || id.includes('redirect')) return 'CWE-601 · OWASP A01 · WSTG-CLNT-04';
  return 'general hygiene · black-box suite';
}

export interface SecurityReviewOpts {
  projectName?: string;
  mode?: string;
  scanId?: string;
  suite?: string;
}

/** Full Claude `/security-review` markdown artifact. */
export function buildSecurityReviewMarkdown(
  url: string,
  findings: Finding[],
  score: number,
  grade: string,
  opts: SecurityReviewOpts = {},
): string {
  const when = new Date().toISOString();
  const fails = findings
    .filter((f) => !f.pass)
    .sort(
      (a, b) =>
        SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.title.localeCompare(b.title),
    );
  const passed = findings.filter((f) => f.pass);
  const title = opts.projectName || url;
  const suite = opts.suite || `VibeTesting Agent ${opts.mode || 'full'} suite`;

  const lines: string[] = [];
  lines.push(`# ${title} — security-review`);
  lines.push('');
  lines.push(`**For:** Claude Code / Codex / Cursor working on this repository.`);
  lines.push(`**Command style:** \`/security-review\` (vibetesting-agent agent-report)`);
  lines.push(`**Source:** black-box scan via VibeTesting Agent · **${suite}**.`);
  lines.push(`**URL:** \`${url}\``);
  if (opts.scanId) lines.push(`**Scan id:** \`${opts.scanId}\``);
  lines.push(`**Generated:** ${when}`);
  lines.push(`**Grade:** security **${grade} (${score}/100)**`);
  lines.push(
    `**Overall:** ${
      fails.length === 0
        ? 'no open hygiene failures on this pass.'
        : `${fails.length} open issue(s) ranked below (high → low).`
    }`,
  );
  lines.push('');
  lines.push(
    '> **Authorized use only.** Hygiene scan — first line of defense, not a pentest. A clean scan does not mean the app is secure.',
  );
  lines.push('');
  lines.push('---');
  lines.push('');

  if (fails.length === 0) {
    lines.push('## No failing findings');
    lines.push('');
    lines.push(
      'Ship score is green for black-box hygiene. Keep deploy-triggered scans enabled and re-run after each software update.',
    );
    lines.push('');
  } else {
    fails.forEach((f, i) => {
      const p = `P${i + 1}`;
      lines.push(`## ${p} — ${f.title}  [${SEV_ICON[f.severity]}]`);
      lines.push(`- **${standardsLine(f.id)}**`);
      lines.push(`- **id:** \`${f.id}\` · **category:** \`${f.category}\``);
      lines.push(`- **Problem:** ${f.detail}`);
      lines.push(`- **Where:** ${whereHint(f)}`);
      lines.push(
        `- **Fix:** ${f.fix || 'Investigate and harden this surface with least privilege and safe defaults.'}`,
      );
      lines.push(
        `- **Verify (accept):** \`npx vibetesting-agent ${url} --only ${f.category}\`; confirm \`${f.id}\` no longer fails.`,
      );
      lines.push('');
    });
  }

  lines.push('---');
  lines.push('');
  lines.push('## Agent instructions');
  lines.push('');
  lines.push('1. Work **top-down** (P1 first). Do not invent secrets or weaken auth to make a check pass.');
  lines.push('2. Prefer reversible, scoped fixes (headers, CSP nonces, DNS records, env hygiene).');
  lines.push('3. After each fix, re-run the verify command for that finding.');
  lines.push(
    `4. Full rescan: \`npx vibetesting-agent ${url} --agent-report security-review.md\``,
  );
  lines.push(
    '5. Or trigger VibeTesting Agent deploy webhook / `start_scan` MCP with `mode=full` and re-pull this report.',
  );
  lines.push('');

  if (passed.length) {
    lines.push('## Passing checks (no action)');
    lines.push('');
    const byCat = new Map<string, number>();
    for (const f of passed) byCat.set(f.category, (byCat.get(f.category) || 0) + 1);
    for (const [cat, n] of [...byCat.entries()].sort()) {
      lines.push(`- **${cat}:** ${n} pass`);
    }
    lines.push('');
  }

  lines.push('---');
  lines.push('');
  lines.push(`*Generated by VibeTesting Agent · security-review · ${url}*`);
  lines.push('');
  return lines.join('\n');
}

/** Printable HTML twin of the security-review (also used for iframe + PDF layout source). */
export function buildSecurityReviewHtml(
  url: string,
  findings: Finding[],
  score: number,
  grade: string,
  opts: SecurityReviewOpts = {},
): string {
  const md = buildSecurityReviewMarkdown(url, findings, score, grade, opts);
  // Convert light markdown-ish structure to HTML without a parser dep
  const fails = findings.filter((f) => !f.pass).sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
  const rows = fails
    .map((f, i) => {
      return `<tr>
        <td class="mono">P${i + 1}</td>
        <td class="sev sev-${esc(f.severity)}">${esc(f.severity)}</td>
        <td><strong>${esc(f.title)}</strong><div class="muted mono">${esc(f.id)}</div>
          <div class="detail">${esc(f.detail)}</div>
          <div class="fix"><strong>Fix:</strong> ${esc(f.fix || 'Harden safely.')}</div>
        </td>
      </tr>`;
    })
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>security-review — ${esc(url)}</title>
<style>
  @page { margin: 18mm; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; color: #111; max-width: 900px; margin: 0 auto; padding: 32px 24px; line-height: 1.45; }
  h1 { font-size: 22px; margin: 0 0 8px; }
  .meta { color: #555; font-size: 12px; margin-bottom: 20px; }
  .grade { font-size: 42px; font-weight: 800; letter-spacing: -0.03em; }
  .score { font-size: 16px; color: #444; }
  table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 12px; }
  th, td { border-bottom: 1px solid #e5e7eb; padding: 10px 8px; vertical-align: top; text-align: left; }
  th { font-size: 11px; text-transform: uppercase; color: #666; }
  .sev { font-weight: 700; text-transform: uppercase; font-size: 11px; }
  .sev-high { color: #b91c1c; }
  .sev-medium { color: #c2410c; }
  .sev-low { color: #a16207; }
  .sev-info { color: #475569; }
  .muted { color: #64748b; font-size: 11px; margin-top: 2px; }
  .detail, .fix { margin-top: 6px; color: #334155; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .banner { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 14px; font-size: 12px; margin: 16px 0; }
  footer { margin-top: 28px; font-size: 11px; color: #64748b; }
  @media print {
    body { padding: 0; }
    a { color: inherit; text-decoration: none; }
  }
</style>
</head>
<body>
  <h1>VibeTesting Agent — security-review</h1>
  <div class="meta mono">${esc(url)} · ${esc(new Date().toISOString())}${opts.scanId ? ` · scan ${esc(opts.scanId)}` : ''}</div>
  <div class="grade">${esc(grade)} <span class="score">${score}/100</span></div>
  <div class="banner">Claude / Codex artifact: ranked P1→Pn findings with problem, where, fix, and verify steps. Authorized black-box hygiene — not a pentest.</div>
  <table>
    <thead><tr><th>#</th><th>Sev</th><th>Finding</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="3">All checks passed.</td></tr>'}</tbody>
  </table>
  <footer>
    Generated by VibeTesting Agent · /security-review format · ${esc(url)}
    <pre style="display:none">${esc(md)}</pre>
  </footer>
</body>
</html>`;
}

function esc(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!,
  );
}

/**
 * Minimal multi-page PDF (Helveticalike built-in font) — no native deps, Workers-safe.
 */
export function buildSecurityReviewPdf(
  url: string,
  findings: Finding[],
  score: number,
  grade: string,
  opts: SecurityReviewOpts = {},
): Uint8Array {
  const lines: string[] = [];
  lines.push('VibeTesting Agent — security-review');
  lines.push(`URL: ${url}`);
  if (opts.scanId) lines.push(`Scan: ${opts.scanId}`);
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push(`Grade: ${grade} (${score}/100)`);
  lines.push(`Suite: ${opts.suite || opts.mode || 'full'}`);
  lines.push('');
  lines.push('Authorized black-box hygiene scan. Not a pentest.');
  lines.push('');

  const fails = findings
    .filter((f) => !f.pass)
    .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.title.localeCompare(b.title));

  if (!fails.length) {
    lines.push('No failing findings. Keep deploy-triggered scans enabled.');
  } else {
    fails.forEach((f, i) => {
      lines.push(`P${i + 1}. [${f.severity.toUpperCase()}] ${f.title}`);
      lines.push(`  id: ${f.id}  category: ${f.category}`);
      lines.push(`  Problem: ${f.detail}`);
      lines.push(`  Where: ${whereHint(f)}`);
      lines.push(`  Fix: ${f.fix || 'Harden safely.'}`);
      lines.push(`  Verify: npx vibetesting-agent ${url} --only ${f.category}`);
      lines.push('');
    });
  }

  lines.push('Agent instructions: work top-down (P1 first); re-scan after fixes.');
  lines.push(`Full rescan: npx vibetesting-agent ${url} --agent-report security-review.md`);

  return textLinesToPdf(lines, {
    title: `security-review ${url}`,
    author: 'VibeTesting Agent',
  });
}

/** Escape PDF string literals (WinAnsi-ish subset). */
function pdfEscape(s: string): string {
  return s
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)')
    .replace(/[^\x20-\x7E]/g, (ch) => {
      // Drop non-ascii for core fonts; keep simple dash
      if (ch === '—' || ch === '–') return '-';
      if (ch === '“' || ch === '”' || ch === '„') return '"';
      if (ch === '‘' || ch === '’') return "'";
      if (ch === '…') return '...';
      return '?';
    });
}

function wrapLine(text: string, maxChars: number): string[] {
  const words = text.split(/\s+/);
  const out: string[] = [];
  let cur = '';
  for (const w of words) {
    if (!cur) {
      cur = w;
      continue;
    }
    if ((cur + ' ' + w).length <= maxChars) cur = cur + ' ' + w;
    else {
      out.push(cur);
      cur = w;
    }
  }
  if (cur) out.push(cur);
  return out.length ? out : [''];
}

function textLinesToPdf(
  rawLines: string[],
  meta: { title: string; author: string },
): Uint8Array {
  const pageWidth = 612; // letter
  const pageHeight = 792;
  const margin = 54;
  const fontSize = 10;
  const leading = 13;
  const maxChars = 90;
  const usableHeight = pageHeight - margin * 2;
  const linesPerPage = Math.floor(usableHeight / leading);

  const wrapped: string[] = [];
  for (const line of rawLines) {
    if (!line) {
      wrapped.push('');
      continue;
    }
    wrapped.push(...wrapLine(line, maxChars));
  }

  const pages: string[][] = [];
  for (let i = 0; i < wrapped.length; i += linesPerPage) {
    pages.push(wrapped.slice(i, i + linesPerPage));
  }
  if (!pages.length) pages.push(['(empty report)']);

  const objects: string[] = [];
  const offsets: number[] = [0]; // 1-indexed later

  const addObj = (body: string) => {
    objects.push(body);
    return objects.length;
  };

  // 1: Catalog
  const catalogId = addObj('<< /Type /Catalog /Pages 2 0 R >>');
  // 2: Pages (filled later)
  const pagesId = addObj('PLACEHOLDER_PAGES');
  // 3: Font
  const fontId = addObj('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  // 4: Info
  addObj(
    `<< /Title (${pdfEscape(meta.title)}) /Author (${pdfEscape(meta.author)}) /Creator (VibeTesting Agent) /Producer (VibeTesting Agent PDF) >>`,
  );

  const pageIds: number[] = [];
  const contentIds: number[] = [];

  for (const pageLines of pages) {
    let y = pageHeight - margin;
    const ops: string[] = [];
    ops.push('BT');
    ops.push(`/F1 ${fontSize} Tf`);
    ops.push(`${leading} TL`);
    ops.push(`${margin} ${y} Td`);
    pageLines.forEach((line, idx) => {
      const safe = pdfEscape(line);
      if (idx === 0) ops.push(`(${safe}) Tj`);
      else ops.push(`T* (${safe}) Tj`);
    });
    ops.push('ET');
    const stream = ops.join('\n');
    const contentId = addObj(
      `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
    );
    contentIds.push(contentId);
    const pageId = addObj(
      `<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 ${pageWidth} ${pageHeight}] /Contents ${contentId} 0 R /Resources << /Font << /F1 ${fontId} 0 R >> >> >>`,
    );
    pageIds.push(pageId);
  }

  // Fix pages object
  const kids = pageIds.map((id) => `${id} 0 R`).join(' ');
  objects[pagesId - 1] = `<< /Type /Pages /Kids [${kids}] /Count ${pageIds.length} >>`;

  // Assemble
  const encoder = new TextEncoder();
  const chunks: Uint8Array[] = [];
  let pos = 0;
  const push = (s: string) => {
    const b = encoder.encode(s);
    chunks.push(b);
    pos += b.length;
  };

  push('%PDF-1.4\n');
  const xref: number[] = [0];
  for (let i = 0; i < objects.length; i++) {
    xref.push(pos);
    push(`${i + 1} 0 obj\n${objects[i]}\nendobj\n`);
  }
  const xrefStart = pos;
  push(`xref\n0 ${objects.length + 1}\n`);
  push('0000000000 65535 f \n');
  for (let i = 1; i <= objects.length; i++) {
    push(`${String(xref[i]).padStart(10, '0')} 00000 n \n`);
  }
  push(
    `trailer\n<< /Size ${objects.length + 1} /Root ${catalogId} 0 R /Info 4 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`,
  );

  // Merge
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

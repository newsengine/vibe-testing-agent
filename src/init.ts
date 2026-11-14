// Scaffold security suite into a consumer repo: Gherkin features, agent-report path, CI, templates.

import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding } from './types.js';
import { renderAgentReport } from './agent-report.js';
import { renderGherkinFeature, renderGherkinStepStub } from './gherkin.js';
import { buildBaseline } from './baseline.js';
import { PINNED_SPEC } from './pin.js';

export interface InitOptions {
  cwd: string;
  url: string;
  projectName?: string;
  findings?: Finding[];
  /** Write GitHub Actions workflow. Default true. */
  ci?: boolean;
}

export interface InitResult {
  written: string[];
  skipped: string[];
}

function writeIfMissing(path: string, content: string, force: boolean, written: string[], skipped: string[]) {
  if (!force && existsSync(path)) {
    skipped.push(path);
    return;
  }
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content);
  written.push(path);
}

export function initRepo(opts: InitOptions & { force?: boolean }): InitResult {
  const written: string[] = [];
  const skipped: string[] = [];
  const force = !!opts.force;
  const root = opts.cwd;
  const name = opts.projectName || 'app';
  const findings = opts.findings || [];

  // Agent report
  const report = findings.length
    ? renderAgentReport(findings, { url: opts.url, projectName: name })
    : `# ${name} — security review\n\nRun: \`npx --yes ${PINNED_SPEC} ${opts.url} --agent-report security-review.md\`\n`;
  writeIfMissing(join(root, 'security-review.md'), report, force, written, skipped);

  // Gherkin
  const feature = renderGherkinFeature(findings, { url: opts.url, projectName: name, tags: true });
  writeIfMissing(join(root, 'features/security/hygiene.feature'), feature, force, written, skipped);
  writeIfMissing(join(root, 'features/support/vibetesting-agent.steps.mjs'), renderGherkinStepStub(), force, written, skipped);

  // Baseline
  if (findings.length) {
    const baseline = buildBaseline(findings, opts.url);
    writeIfMissing(
      join(root, 'vibetesting-agent-baseline.json'),
      JSON.stringify(baseline, null, 2) + '\n',
      force,
      written,
      skipped,
    );
  }

  // Config
  const config = {
    url: opts.url,
    failOn: 'high',
    allowReportOnlyCsp: true,
  };
  writeIfMissing(join(root, 'vibetesting-agent.config.json'), JSON.stringify(config, null, 2) + '\n', force, written, skipped);

  // SECURITY.md pointer
  writeIfMissing(
    join(root, 'SECURITY.md'),
    `# Security\n\nThis repo uses [vibetesting-agent](https://github.com/newsengine/vibe-testing-agent) for deploy hygiene.\n\n` +
      `- Run review: \`npx --yes ${PINNED_SPEC} ${opts.url} --agent-report security-review.md --gherkin features/security/hygiene.feature\`\n` +
      `- Baseline: \`vibetesting-agent-baseline.json\` (CI fails only on new highs)\n` +
      `- Gherkin: \`features/security/\`\n` +
      `- Authorized testing only.\n`,
    force,
    written,
    skipped,
  );

  if (opts.ci !== false) {
    const wf = `name: security
on:
  pull_request:
  workflow_dispatch:
  # Also trigger after deploy via repository_dispatch or your host webhook → VibeTesting Agent
permissions:
  contents: read
jobs:
  probe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: vibetesting-agent
        env:
          TARGET_URL: ${JSON.stringify(opts.url)}
        run: |
          npx --yes ${PINNED_SPEC} "$TARGET_URL" \\
            --fail-on high \\
            --baseline vibetesting-agent-baseline.json \\
            --agent-report security-review.md \\
            --gherkin features/security/hygiene.feature || true
          # Gate separately so artifacts always upload
          npx --yes ${PINNED_SPEC} "$TARGET_URL" --fail-on high --baseline vibetesting-agent-baseline.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-review
          path: |
            security-review.md
            features/security/
`;
    writeIfMissing(join(root, '.github/workflows/security.yml'), wf, force, written, skipped);
  }

  return { written, skipped };
}

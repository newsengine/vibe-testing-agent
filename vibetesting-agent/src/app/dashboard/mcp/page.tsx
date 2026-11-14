import { getSessionUser } from '@/lib/auth';
import { config } from '@/lib/config';
import { listProjects } from '@/lib/projects';
import { CopyButton } from '@/components/forms';
import Link from 'next/link';

export default async function McpPage() {
  const user = await getSessionUser();
  if (!user) return null;
  const projects = await listProjects(user.id);
  const first = projects[0];
  const projectId = first?.id || 'prj_…';
  const webhookExample = first
    ? `${config.appUrl}/api/webhooks/deploy/${first.deployWebhookSecret}`
    : `${config.appUrl}/api/webhooks/deploy/YOUR_PROJECT_SECRET`;

  const mcpJson = `{
  "mcpServers": {
    "vibetesting-agent": {
      "command": "npx",
      "args": ["-y", "tsx", "mcp/src/index.ts"],
      "cwd": "/path/to/vibetesting-agent",
      "env": {
        "VTA_API_URL": "${config.appUrl}",
        "VTA_API_KEY": "sk_live_YOUR_KEY"
      }
    }
  }
}`;

  const claudeMcp = `# 1) Clone or vendor the MCP package once
#    (repo path that contains mcp/src/index.ts)

export VTA_API_URL=${config.appUrl}
export VTA_API_KEY=sk_live_YOUR_KEY   # from Dashboard → API keys

# 2) Register with Claude Code (project or user scope)
claude mcp add vibetesting-agent \\
  --env VTA_API_URL=${config.appUrl} \\
  --env VTA_API_KEY=sk_live_YOUR_KEY \\
  -- npx -y tsx mcp/src/index.ts

# 3) Confirm tools appear
claude mcp list
# should show: list_projects, start_scan, get_scan, list_findings,
#              get_fix_prompt, compare_baseline, whoami, …`;

  const codexMcp = `# Codex CLI / Cursor MCP settings
# Add a stdio server:

Name:    vibetesting-agent
Command: npx
Args:    -y  tsx  mcp/src/index.ts
Cwd:     /path/to/vibetesting-agent   # folder that contains mcp/
Env:
  VTA_API_URL=${config.appUrl}
  VTA_API_KEY=sk_live_YOUR_KEY

# Cursor: Settings → MCP → Add server (same fields)
# Codex: ~/.codex/config.toml or project .mcp.json depending on your build`;

  const ghAction = `name: VibeTesting Agent — post-deploy scan + agent fix loop
on:
  deployment_status:
  workflow_dispatch:

jobs:
  ship-scan:
    if: github.event.deployment_status.state == 'success' || github.event_name == 'workflow_dispatch'
    runs-on: ubuntu-latest
    steps:
      - name: Trigger full suite on production
        env:
          VTA_WEBHOOK: \${{ secrets.VTA_DEPLOY_WEBHOOK_URL }}
          PROD_URL: \${{ secrets.PROD_URL }}
        run: |
          curl -fsS -X POST "$VTA_WEBHOOK" \\
            -H "content-type: application/json" \\
            -d "{\\"url\\":\\"\${PROD_URL:-}\\",\\"sha\\":\\"\${{ github.sha }}\\",\\"ref\\":\\"\${{ github.ref }}\\"}"

      # Optional: after the scan is queued, kick Claude Code in CI to fix recursively
      # (requires ANTHROPIC_API_KEY + MCP wired in the runner)
      # - uses: anthropics/claude-code-action@v1
      #   with:
      #     prompt: file://.github/prompts/vta-fix-loop.md`;

  const recursiveFixPrompt = `You are the ship-security agent for this repo. Use the vibetesting-agent MCP tools. Do not invent findings.

RECURSIVE FIX LOOP (full suite):
1. whoami — confirm plan includes full/crawl modes and MCP.
2. list_projects — find project_id for the production URL (or use ${projectId}).
3. Prefer the latest scan created by the deploy webhook. If none is running/completed for this SHA:
   start_scan project_id=${projectId} mode=full authorized=true
4. Poll get_scan every 15–30s until status is completed (or failed).
5. list_findings for that scan_id. Sort: high → medium → low. Ignore pure-info passes.
6. get_fix_prompt for the full scan (or per finding_id for highs).
7. Apply P1→Pn fixes in THIS repository. Prefer minimal, production-safe patches.
8. Commit on a branch (e.g. fix/vta-scan-<scan_id>), open/update a PR.
9. If you can reach a preview/prod URL for the fix, start_scan again (mode=full, authorized=true)
   and repeat steps 4–8 until:
   - no high findings remain, OR
   - remaining fails need human/DNS/vendor action (document them and stop).
10. compare_baseline on the final scan and summarize score/grade + residual risks.

RULES:
- authorized=true only for targets the team owns.
- Do not disable security controls to make the scan pass.
- DNS-only findings (SPF/DMARC/CAA) need DNS panel access — report, do not fake.
- Stop after 5 scan rounds unless the user asks to continue.`;

  const agentsMdSnippet = `## VibeTesting Agent (continuous ship security)

After every production deploy, a full black-box suite runs via VibeTesting Agent
(${config.appUrl}). Fix regressions with MCP:

- MCP server: vibetesting-agent (VTA_API_URL + VTA_API_KEY)
- Project: ${projectId}
- Loop: get latest scan → get_fix_prompt → patch → re-scan until highs are gone

When the user says "fix ship score", "security review", or after deploy:
run the recursive fix loop from Dashboard → MCP (copy prompt).`;

  const claudeHeadless = `# Example: Claude Code headless after deploy (local or CI)
export VTA_API_URL=${config.appUrl}
export VTA_API_KEY=sk_live_YOUR_KEY

claude -p "$(cat <<'PROMPT'
${recursiveFixPrompt}
PROMPT
)" --allowedTools "mcp__vibetesting-agent__*" "Edit" "Write" "Bash" "Read"`;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="mono text-2xl font-bold">Claude Code · Codex · every commit</h1>
        <p className="mt-2 max-w-2xl text-sm text-[var(--mut)]">
          Goal: <strong className="text-[var(--ink)]">every production deploy</strong> runs the full
          VibeTesting suite, then Claude Code or Codex <strong className="text-[var(--ink)]">recursively
          fixes</strong> failures until highs are gone (or only human/DNS work remains).
        </p>
      </div>

      <div className="panel space-y-3 p-5 text-sm text-[var(--mut)]">
        <h2 className="mono font-bold text-[var(--ink)]">Architecture (two layers)</h2>
        <ol className="list-decimal space-y-2 pl-5">
          <li>
            <strong className="text-[var(--ink)]">Trigger (always on)</strong> — CI/CD or GitHub posts the
            project deploy webhook when production is live. VibeTesting Agent runs the full black-box suite
            (headers, TLS, CSP, DNS, secrets, exposure, SEO, a11y, agent readiness, …). No agent process
            needs to be online.
          </li>
          <li>
            <strong className="text-[var(--ink)]">Remediation (agent)</strong> — Claude Code / Codex via MCP
            pulls findings + <code className="text-[var(--ink)]">get_fix_prompt</code>, patches the repo,
            optionally re-scans, and opens a PR. Agents do not replace the webhook.
          </li>
        </ol>
        <pre className="mono mt-2 overflow-x-auto rounded bg-black/40 p-3 text-[11px] text-[var(--ink)]">{`push → deploy succeeds → POST /api/webhooks/deploy/:secret
       → full suite scan → agent MCP get_fix_prompt
       → patch + PR → (optional) re-scan → until clean`}</pre>
        <p className="text-xs">
          Plan: deploy/commit hooks need <strong className="text-[var(--ink)]">Daily ($100)</strong> or{' '}
          <strong className="text-[var(--ink)]">Every commit ($250)</strong>. MCP works on plans that include
          API keys.
        </p>
      </div>

      <div className="panel space-y-3 p-5">
        <h2 className="mono font-bold">0. Prerequisites (once)</h2>
        <ol className="list-decimal space-y-1 pl-5 text-sm text-[var(--mut)]">
          <li>
            <Link className="text-[var(--lime)]" href="/dashboard/projects">
              Create a project
            </Link>{' '}
            with the production URL.
          </li>
          <li>Verify ownership (domain email inbox click or DNS TXT).</li>
          <li>
            Upgrade to Daily or Every commit —{' '}
            <Link className="text-[var(--lime)]" href="/dashboard/billing">
              Billing
            </Link>
            .
          </li>
          <li>
            Create an API key —{' '}
            <Link className="text-[var(--lime)]" href="/dashboard/keys">
              API keys
            </Link>
            .
          </li>
          <li>Install Claude Code or Codex/Cursor with MCP support on the machine that will fix code.</li>
        </ol>
      </div>

      <div className="panel space-y-4 p-5">
        <h2 className="mono font-bold text-[var(--lime)]">1. Automatic full suite on every production deploy</h2>
        <p className="text-sm text-[var(--mut)]">
          This is the reliable “every commit to production” trigger.
        </p>

        <div>
          <h3 className="mono text-sm font-bold">1a. Project deploy webhook</h3>
          <pre className="mono mt-2 overflow-x-auto rounded bg-black/40 p-3 text-xs">
            {`curl -X POST '${webhookExample}' \\
  -H 'content-type: application/json' \\
  -d '{"url":"https://your-prod.example.com","sha":"$GIT_SHA"}'`}
          </pre>
          <CopyButton text={webhookExample} label="Copy webhook URL" />
          <p className="mt-2 text-xs text-[var(--mut)]">
            Fire only after production is live (Vercel deploy hook, Railway release command, k8s job, etc.).
          </p>
        </div>

        <div>
          <h3 className="mono text-sm font-bold">1b. GitHub Actions</h3>
          <pre className="mono mt-2 max-h-64 overflow-auto rounded bg-black/40 p-3 text-xs">{ghAction}</pre>
          <CopyButton text={ghAction} label="Copy workflow skeleton" />
          <p className="mt-2 text-xs text-[var(--mut)]">
            Secret <code className="text-[var(--ink)]">VTA_DEPLOY_WEBHOOK_URL</code> = full webhook URL from
            the project page.
          </p>
        </div>

        <div>
          <h3 className="mono text-sm font-bold">1c. GitHub App (optional)</h3>
          <p className="text-sm text-[var(--mut)]">
            Webhook → <code className="text-[var(--ink)]">{config.appUrl}/api/webhooks/github</code>, set
            project <code className="text-[var(--ink)]">githubRepo</code> to <code>owner/name</code>. On{' '}
            <code className="text-[var(--ink)]">deployment_status=success</code> we scan and can post a Check
            Run.
          </p>
        </div>
      </div>

      <div className="panel space-y-4 p-5">
        <h2 className="mono font-bold text-[var(--lime)]">2. Connect Claude Code or Codex (MCP)</h2>
        <p className="text-sm text-[var(--mut)]">
          One-time MCP wiring so the agent can start scans, read findings, and pull the same fix pack as the
          dashboard.
        </p>

        <div>
          <h3 className="mono text-sm font-bold">2a. MCP server JSON</h3>
          <pre className="mono mt-2 overflow-x-auto rounded bg-black/40 p-3 text-xs">{mcpJson}</pre>
          <CopyButton text={mcpJson} label="Copy MCP JSON" />
        </div>

        <div>
          <h3 className="mono text-sm font-bold">2b. Claude Code</h3>
          <pre className="mono mt-2 overflow-x-auto rounded bg-black/40 p-3 text-xs">{claudeMcp}</pre>
          <CopyButton text={claudeMcp} label="Copy Claude setup" />
        </div>

        <div>
          <h3 className="mono text-sm font-bold">2c. Codex / Cursor</h3>
          <pre className="mono mt-2 overflow-x-auto rounded bg-black/40 p-3 text-xs">{codexMcp}</pre>
          <CopyButton text={codexMcp} label="Copy Codex notes" />
        </div>

        <div>
          <h3 className="mono text-sm font-bold">MCP tools</h3>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-[var(--mut)]">
            <li>
              <code className="text-[var(--ink)]">list_projects</code> /{' '}
              <code className="text-[var(--ink)]">whoami</code>
            </li>
            <li>
              <code className="text-[var(--ink)]">start_scan</code> — project_id + authorized=true · mode=full
            </li>
            <li>
              <code className="text-[var(--ink)]">get_scan</code> ·{' '}
              <code className="text-[var(--ink)]">list_findings</code>
            </li>
            <li>
              <code className="text-[var(--ink)]">get_fix_prompt</code> /{' '}
              <code className="text-[var(--ink)]">get_security_review</code> — Claude{' '}
              <code className="text-[var(--ink)]">/security-review</code> pack (PDF via{' '}
              <code className="text-[var(--ink)]">/api/v1/scans/:id/report.pdf</code>)
            </li>
            <li>
              <code className="text-[var(--ink)]">compare_baseline</code> ·{' '}
              <code className="text-[var(--ink)]">get_badge_markdown</code>
            </li>
          </ul>
        </div>
      </div>

      <div className="panel space-y-4 p-5">
        <h2 className="mono font-bold text-[var(--lime)]">3. Recursive fix loop (full suite)</h2>
        <p className="text-sm text-[var(--mut)]">
          Paste this into Claude Code or Codex after a deploy (or on a schedule). It re-scans until highs are
          cleared or residual items need a human.
        </p>
        <pre className="mono max-h-96 overflow-auto rounded bg-black/40 p-3 text-xs">{recursiveFixPrompt}</pre>
        <CopyButton text={recursiveFixPrompt} label="Copy recursive fix prompt" />

        <div>
          <h3 className="mono text-sm font-bold">3b. Drop into AGENTS.md / CLAUDE.md</h3>
          <pre className="mono mt-2 overflow-x-auto rounded bg-black/40 p-3 text-xs">{agentsMdSnippet}</pre>
          <CopyButton text={agentsMdSnippet} label="Copy AGENTS.md snippet" />
        </div>

        <div>
          <h3 className="mono text-sm font-bold">3c. Optional headless Claude after deploy</h3>
          <pre className="mono mt-2 max-h-64 overflow-auto rounded bg-black/40 p-3 text-xs">{claudeHeadless}</pre>
          <CopyButton text={claudeHeadless} label="Copy headless example" />
        </div>
      </div>

      <div className="panel space-y-3 p-5">
        <h2 className="mono font-bold">4. API without MCP</h2>
        <pre className="mono overflow-x-auto rounded bg-black/40 p-3 text-xs">{`curl -X POST ${config.appUrl}/api/v1/scans \\
  -H "Authorization: Bearer sk_live_…" \\
  -H "content-type: application/json" \\
  -d '{"projectId":"${projectId}","authorized":true,"mode":"full","trigger":"api"}'`}</pre>
        <p className="text-sm text-[var(--mut)]">
          Or OSS offline:{' '}
          <code className="text-[var(--ink)]">
            npx vibetesting-agent https://prod.example.com --fail-on high
          </code>
        </p>
      </div>

      <p className="text-xs text-[var(--mut)]">
        Claude and Codex cannot listen to git by themselves. Always wire{' '}
        <strong className="text-[var(--ink)]">production deploy → VTA webhook</strong>, then{' '}
        <strong className="text-[var(--ink)]">agent → MCP recursive fix loop</strong> for automatic remediation.
      </p>
    </div>
  );
}

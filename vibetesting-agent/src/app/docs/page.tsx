import Link from 'next/link';

export default function DocsPage() {
  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <Link href="/" className="mono text-[var(--lime)]">
        ← VibeTesting Agent
      </Link>
      <h1 className="mono mt-6 text-3xl font-bold">Docs</h1>
      <div className="mt-8 space-y-8 text-sm leading-relaxed text-[var(--mut)]">
        <section>
          <h2 className="mono text-lg font-bold text-[var(--ink)]">What is VibeTesting Agent?</h2>
          <p className="mt-2">
            Hosted orchestration around the open-source <strong className="text-[var(--ink)]">vibetesting-agent</strong>{' '}
            scanner: dashboard, billing, deploy webhooks, GitHub checks, MCP for agents, badges, and
            history. The OSS CLI stays free forever.
          </p>
          <p className="mt-3">
            <Link href="/docs/coverage" className="text-[var(--lime)] hover:underline">
              Security coverage map →
            </Link>{' '}
            zones, OWASP WSTG categories, and ASVS L1 — what we automate vs what needs auth or active tests.
          </p>
        </section>
        <section>
          <h2 className="mono text-lg font-bold text-[var(--ink)]">Ownership security</h2>
          <p className="mt-2">
            Full scans only run against apps you prove you control. Two paths:
          </p>
          <ol className="mt-2 list-decimal space-y-2 pl-5">
            <li>
              <strong className="text-[var(--ink)]">Domain email + inbox click</strong> — Sign in with an
              email on the same domain as the app (e.g. <code className="text-[var(--ink)]">you@acme.com</code>{' '}
              for <code className="text-[var(--ink)]">app.acme.com</code>). We email a one-click link; open it
              to prove you control that inbox. Free/public mail (Gmail, etc.) cannot prove app ownership this
              way.
            </li>
            <li>
              <strong className="text-[var(--ink)]">DNS TXT</strong> — In your DNS control panel, add{' '}
              <code className="text-[var(--ink)]">vibetesting-verify=&lt;token&gt;</code> on the hostname or{' '}
              <code className="text-[var(--ink)]">_vta.&lt;hostname&gt;</code>, then click Check DNS.
            </li>
          </ol>
        </section>
        <section>
          <h2 className="mono text-lg font-bold text-[var(--ink)]">Preview / staging hosts</h2>
          <p className="mt-2">
            After the production host is verified, add allowed preview patterns on the project page
            (for example <code className="text-[var(--ink)]">*.your-app.pages.dev</code> or{' '}
            <code className="text-[var(--ink)]">staging.example.com</code>). A pattern is accepted only
            if you have proven the parent domain or that specific preview host via DNS TXT,{' '}
            <code className="text-[var(--ink)]">/.well-known/vibetesting-verify.txt</code>, or a homepage
            meta tag. Shared platform apexes (<code className="text-[var(--ink)]">pages.dev</code>,{' '}
            <code className="text-[var(--ink)]">vercel.app</code>,{' '}
            <code className="text-[var(--ink)]">netlify.app</code>) cannot be added as bare patterns.
            Deploy and GitHub webhooks then accept matching preview URLs; anything else is still{' '}
            <code className="text-[var(--ink)]">host_mismatch</code>.
          </p>
          <p className="mt-2">
            The CLI already scans any URL you pass — use it on preview deploys you own. The hosted app
            is stricter so we never scan a host the owner has not proven.
          </p>
        </section>
        <section>
          <h2 className="mono text-lg font-bold text-[var(--ink)]">Authenticated / internal testing</h2>
          <p className="mt-2">
            Optional. After ownership, open the project and enable{' '}
            <strong className="text-[var(--ink)]">Authenticated testing</strong>:
          </p>
          <ol className="mt-2 list-decimal space-y-1 pl-5">
            <li>Create a dedicated test user on your app (not a real customer / not prod admin).</li>
            <li>Confirm that user&apos;s email link.</li>
            <li>Log in, copy the session cookie or a test API bearer token.</li>
            <li>Paste it into the project panel, save, and click Verify session.</li>
            <li>Scans then attach that session on same-origin requests.</li>
          </ol>
          <p className="mt-2">
            <strong className="text-[var(--ink)]">Opt out anytime:</strong> “Opt out &amp; delete credentials”
            disables internal scans and wipes stored secrets. External black-box still works.
          </p>
          <p className="mt-2">
            See also{' '}
            <Link href="/docs/coverage" className="text-[var(--lime)] hover:underline">
              coverage map
            </Link>{' '}
            (Zones 3–5).
          </p>
        </section>
        <section>
          <h2 className="mono text-lg font-bold text-[var(--ink)]">Hosted workflow</h2>
          <ol className="mt-2 list-decimal space-y-1 pl-5">
            <li>Sign in (prefer an email on your product domain when possible).</li>
            <li>Create a project with your production URL.</li>
            <li>Prove ownership via domain email (inbox click) or DNS TXT.</li>
            <li>Upgrade for cadence (weekly / daily / every commit).</li>
            <li>POST the deploy webhook after every successful release.</li>
            <li>Review score, baseline diffs, and agent fix packs.</li>
          </ol>
        </section>
        <section>
          <h2 className="mono text-lg font-bold text-[var(--ink)]">API</h2>
          <pre className="mono mt-2 overflow-x-auto rounded-lg border border-[var(--edge)] bg-black/40 p-4 text-xs text-[var(--ink)]">{`curl -X POST $APP/api/v1/scans \\
  -H "Authorization: Bearer sk_live_…" \\
  -H "content-type: application/json" \\
  -d '{"url":"https://example.com","authorized":true,"mode":"fast"}'`}</pre>
        </section>
        <section>
          <h2 className="mono text-lg font-bold text-[var(--ink)]">
            Every production commit → full suite → Claude / Codex recursive fix
          </h2>
          <p className="mt-2">
            Agents do not watch git alone. Wire two layers:
          </p>
          <ol className="mt-2 list-decimal space-y-2 pl-5">
            <li>
              <strong className="text-[var(--ink)]">Deploy webhook</strong> (or GitHub{' '}
              <code className="text-[var(--ink)]">deployment_status</code>) so every production deploy starts a
              VibeTesting Agent <strong className="text-[var(--ink)]">full</strong> suite scan. Needs Daily
              ($100) or Every commit ($250).
            </li>
            <li>
              <strong className="text-[var(--ink)]">MCP</strong> on Claude Code / Codex:{' '}
              <code className="text-[var(--ink)]">start_scan</code> / <code className="text-[var(--ink)]">get_scan</code>{' '}
              / <code className="text-[var(--ink)]">list_findings</code> /{' '}
              <code className="text-[var(--ink)]">get_fix_prompt</code> → apply patches → re-scan until highs
              are gone (or residual items need DNS/human).
            </li>
            <li>
              Paste the recursive fix prompt into the agent (or AGENTS.md). Optional: headless Claude in CI
              after the webhook.
            </li>
          </ol>
          <pre className="mono mt-3 overflow-x-auto rounded-lg border border-[var(--edge)] bg-black/40 p-3 text-[11px] text-[var(--ink)]">{`push → prod deploy → POST deploy webhook
   → full suite → MCP get_fix_prompt → patch + PR
   → re-scan → repeat until clean (max ~5 rounds)`}</pre>
          <p className="mt-2">
            Full copy-paste setup (webhook, Claude, Codex, recursive prompt):{' '}
            <Link href="/dashboard/mcp" className="text-[var(--lime)] hover:underline">
              Dashboard → MCP / Claude Code · Codex · every commit
            </Link>{' '}
            (after login).
          </p>
        </section>
        <section>
          <h2 className="mono text-lg font-bold text-[var(--ink)]">MCP tools</h2>
          <p className="mt-2">
            See <Link href="/dashboard/mcp" className="text-[var(--lime)]">Dashboard → MCP</Link> after login.
            Tools: list_projects, start_scan, get_scan, list_findings, get_fix_prompt, get_security_review,
            compare_baseline, get_badge_markdown.
          </p>
        </section>
        <section>
          <h2 className="mono text-lg font-bold text-[var(--ink)]">End-of-run security-review + PDF</h2>
          <p className="mt-2">
            When a scan completes, VibeTesting Agent always produces a Claude{' '}
            <code className="text-[var(--ink)]">/security-review</code> markdown (ranked P1→Pn with problem /
            where / fix / verify) and a downloadable PDF report. On the scan detail page: copy, download{' '}
            <code className="text-[var(--ink)]">.md</code>, or <strong className="text-[var(--ink)]">Download PDF
            report</strong>. API:{' '}
            <code className="text-[var(--ink)]">GET /api/v1/scans/:id/security-review</code> ·{' '}
            <code className="text-[var(--ink)]">GET /api/v1/scans/:id/report.pdf</code>.
          </p>
        </section>
        <section>
          <h2 className="mono text-lg font-bold text-[var(--ink)]">GitHub App</h2>
          <p className="mt-2">
            Point the App webhook to <code className="text-[var(--ink)]">/api/webhooks/github</code>. On
            deployment_status success, VibeTesting Agent scans and posts a Check Run. Link projects with{' '}
            <code className="text-[var(--ink)]">githubRepo: owner/name</code>. GitHub linking is for hooks —
            not a substitute for ownership proof.
          </p>
        </section>
      </div>
    </div>
  );
}

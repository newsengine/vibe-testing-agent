'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { PLANS } from '@/lib/plans';

export function CreateProjectForm() {
  const router = useRouter();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setLoading(true);
    setError('');
    const fd = new FormData(e.currentTarget);
    const res = await fetch('/api/v1/projects', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: fd.get('name'),
        url: fd.get('url'),
        policy: fd.get('policy'),
      }),
    });
    const data = await res.json();
    setLoading(false);
    if (!res.ok) {
      setError(data.error || 'Failed');
      return;
    }
    router.push(`/dashboard/projects/${data.project.id}`);
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit} className="panel max-w-lg space-y-4 p-6">
      <div>
        <label className="label">Name</label>
        <input name="name" className="input" placeholder="My SaaS" required />
      </div>
      <div>
        <label className="label">Production URL</label>
        <input name="url" className="input" placeholder="https://app.example.com" required />
      </div>
      <div>
        <label className="label">Policy</label>
        <select name="policy" className="input" defaultValue="ship">
          <option value="chill">Chill — notify only</option>
          <option value="ship">Ship — block new highs</option>
          <option value="client">Client — block high+medium</option>
          <option value="launch">Launch day — prefer crawl</option>
        </select>
      </div>
      {error && <p className="text-sm text-[var(--hi)]">{error}</p>}
      <button className="btn-primary" disabled={loading}>
        {loading ? 'Creating…' : 'Create project'}
      </button>
    </form>
  );
}

type OwnershipInfo = {
  email: {
    address: string;
    domain: string | null;
    eligible: boolean;
    inboxVerified: boolean;
    reason: string;
  };
  dns: {
    host: string;
    altHost: string;
    record: string;
  };
  file: {
    url: string;
    content: string;
    instructions: string;
  };
  meta: {
    tag: string;
    instructions: string;
  };
};

/** Dual ownership: domain email + inbox click, or DNS TXT */
export function OwnershipVerifyPanel({
  projectId,
  hostname,
  verifyToken,
  userEmail,
  emailVerified,
}: {
  projectId: string;
  hostname: string;
  verifyToken: string;
  userEmail: string;
  emailVerified: boolean;
}) {
  const router = useRouter();
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState<'dns' | 'email' | 'file' | 'meta' | 'send' | null>(null);
  const [inboxVerified, setInboxVerified] = useState(emailVerified);
  const [devLink, setDevLink] = useState('');
  const [info, setInfo] = useState<OwnershipInfo | null>(null);

  useEffect(() => {
    fetch(`/api/v1/projects/${projectId}/verify`)
      .then((r) => r.json())
      .then((d) => {
        if (d.ownership) setInfo(d.ownership);
        if (d.ownership?.email?.inboxVerified) setInboxVerified(true);
      })
      .catch(() => {});
  }, [projectId]);

  const emailDomain = (userEmail.split('@')[1] || '').toLowerCase();
  const emailEligible =
    info?.email.eligible ??
    (Boolean(emailDomain) &&
      (hostname === emailDomain ||
        hostname.endsWith(`.${emailDomain}`) ||
        userEmail.toLowerCase().endsWith(`@${hostname}`)));

  async function sendInboxMail() {
    setLoading('send');
    setErr('');
    setMsg('');
    setDevLink('');
    const res = await fetch('/api/v1/auth/email/send-verification', { method: 'POST' });
    const data = await res.json();
    setLoading(null);
    if (!res.ok) {
      setErr(data.error || 'Could not send email');
      return;
    }
    if (data.alreadyVerified) {
      setInboxVerified(true);
      setMsg('Inbox already verified.');
      return;
    }
    setMsg(data.message || 'Check your inbox and click the link.');
    if (data.devVerifyUrl) setDevLink(data.devVerifyUrl);
  }

  async function verify(method: 'dns' | 'email' | 'file' | 'meta') {
    setLoading(method);
    setErr('');
    setMsg('');
    const res = await fetch(`/api/v1/projects/${projectId}/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ method }),
    });
    const data = await res.json();
    setLoading(null);
    if (!res.ok) {
      setErr(data.error || 'Verification failed');
      return;
    }
    const messages: Record<'dns' | 'email' | 'file' | 'meta', string> = {
      email: 'Verified via domain email!',
      dns: 'Verified via DNS!',
      file: 'Verified via well-known file!',
      meta: 'Verified via homepage meta tag!',
    };
    setMsg(messages[method]);
    router.refresh();
  }

  return (
    <div className="space-y-5">
      <p className="text-sm text-[var(--mut)]">
        Full scans only run after you prove control of <code className="text-[var(--ink)]">{hostname}</code>.
        Choose one method:
      </p>

      {/* Method 1: domain email */}
      <div className="rounded-lg border border-[var(--edge)] bg-black/20 p-4">
        <div className="mono text-xs uppercase tracking-wider text-[var(--lime)]">Option 1 · Domain email</div>
        <p className="mt-2 text-sm text-[var(--mut)]">
          Sign in with an email on this domain (e.g.{' '}
          <code className="text-[var(--ink)]">you@{hostname.replace(/^www\./, '')}</code>
          ), then click a link we send to prove you control that inbox.
        </p>
        <div className="mt-3 space-y-1 text-sm">
          <div>
            Signed in as{' '}
            <code className="text-[var(--ink)]">{info?.email.address || userEmail}</code>
          </div>
          <div className="text-[var(--mut)]">
            {info?.email.reason ||
              (emailEligible
                ? inboxVerified
                  ? 'Inbox verified — ready to claim ownership'
                  : 'Eligible domain — verify the inbox next'
                : 'This address is not on the app domain — use DNS or re-sign-in with a domain mailbox')}
          </div>
          <div className="mono text-xs">
            Inbox:{' '}
            <span className={inboxVerified ? 'text-[var(--lime)]' : 'text-[var(--md)]'}>
              {inboxVerified ? 'verified' : 'not verified yet'}
            </span>
          </div>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {!inboxVerified && (
            <button
              type="button"
              className="btn-ghost text-xs"
              onClick={sendInboxMail}
              disabled={loading !== null}
            >
              {loading === 'send' ? 'Sending…' : 'Send inbox verify email'}
            </button>
          )}
          <button
            type="button"
            className="btn-primary text-xs"
            onClick={() => verify('email')}
            disabled={loading !== null || !(info?.email.eligible ?? emailEligible)}
          >
            {loading === 'email' ? 'Checking…' : 'Verify with domain email'}
          </button>
        </div>
        {devLink && (
          <p className="mt-2 break-all text-xs text-[var(--md)]">
            Dev mode (no Resend):{' '}
            <a className="text-[var(--lime)] underline" href={devLink}>
              {devLink}
            </a>
          </p>
        )}
      </div>

      {/* Method 2: DNS */}
      <div className="rounded-lg border border-[var(--edge)] bg-black/20 p-4">
        <div className="mono text-xs uppercase tracking-wider text-[var(--lime)]">Option 2 · DNS TXT</div>
        <p className="mt-2 text-sm text-[var(--mut)]">
          In your DNS control panel, add a TXT record on{' '}
          <code className="text-[var(--ink)]">{hostname}</code> or{' '}
          <code className="text-[var(--ink)]">_vta.{hostname}</code>:
        </p>
        <code className="mono mt-2 block break-all rounded bg-black/40 p-2 text-xs text-[var(--lime)]">
          {info?.dns.record || `vibetesting-verify=${verifyToken}`}
        </code>
        <button
          type="button"
          className="btn-primary mt-3 text-xs"
          onClick={() => verify('dns')}
          disabled={loading !== null}
        >
          {loading === 'dns' ? 'Checking DNS…' : 'Check DNS & verify'}
        </button>
      </div>

      {/* Method 3: Well-known file */}
      <div className="rounded-lg border border-[var(--edge)] bg-black/20 p-4">
        <div className="mono text-xs uppercase tracking-wider text-[var(--lime)]">Option 3 · Well-known file</div>
        <p className="mt-2 text-sm text-[var(--mut)]">
          Create a file at{' '}
          <code className="text-[var(--ink)]">/.well-known/vibetesting-verify.txt</code>{' '}
          containing exactly:
        </p>
        <code className="mono mt-2 block break-all rounded bg-black/40 p-2 text-xs text-[var(--lime)]">
          {info?.file?.content || verifyToken}
        </code>
        <p className="mt-2 text-xs text-[var(--mut)]">
          File URL:{' '}
          <code className="text-[var(--ink)]">{info?.file?.url || `https://${hostname}/.well-known/vibetesting-verify.txt`}</code>
        </p>
        <button
          type="button"
          className="btn-primary mt-3 text-xs"
          onClick={() => verify('file')}
          disabled={loading !== null}
        >
          {loading === 'file' ? 'Checking file…' : 'Check file & verify'}
        </button>
      </div>

      {/* Method 4: Meta tag */}
      <div className="rounded-lg border border-[var(--edge)] bg-black/20 p-4">
        <div className="mono text-xs uppercase tracking-wider text-[var(--lime)]">Option 4 · Meta tag</div>
        <p className="mt-2 text-sm text-[var(--mut)]">
          Add this meta tag to your homepage <code className="text-[var(--ink)]">&lt;head&gt;</code>:
        </p>
        <code className="mono mt-2 block break-all rounded bg-black/40 p-2 text-xs text-[var(--lime)]">
          {info?.meta?.tag || `<meta name="vibetesting-verify" content="${verifyToken}">`}
        </code>
        <button
          type="button"
          className="btn-primary mt-3 text-xs"
          onClick={() => verify('meta')}
          disabled={loading !== null}
        >
          {loading === 'meta' ? 'Checking homepage…' : 'Check meta tag & verify'}
        </button>
      </div>

      {msg && <p className="text-sm text-[var(--lime)]">{msg}</p>}
      {err && <p className="text-sm text-[var(--hi)]">{err}</p>}
    </div>
  );
}

/** @deprecated use OwnershipVerifyPanel */
export function VerifyButton({ projectId }: { projectId: string }) {
  return (
    <OwnershipVerifyPanel
      projectId={projectId}
      hostname="…"
      verifyToken=""
      userEmail=""
      emailVerified={false}
    />
  );
}

export function RunScanForm({
  projectId,
  defaultUrl,
  authReady = false,
}: {
  projectId?: string;
  defaultUrl?: string;
  /** Project has verified authenticated test session */
  authReady?: boolean;
}) {
  const router = useRouter();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setLoading(true);
    setError('');
    const fd = new FormData(e.currentTarget);
    const res = await fetch('/api/v1/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        projectId: projectId || undefined,
        url: projectId ? undefined : fd.get('url'),
        mode: fd.get('mode'),
        authorized: fd.get('authorized') === 'on',
        trigger: 'manual',
      }),
    });
    const data = await res.json();
    setLoading(false);
    if (!res.ok) {
      setError(data.error || 'Scan failed');
      return;
    }
    router.push(`/dashboard/scans/${data.scan.id}`);
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit} className="panel max-w-lg space-y-4 p-6">
      {!projectId && (
        <div>
          <label className="label" htmlFor="scan-url">
            URL
          </label>
          <input
            id="scan-url"
            name="url"
            className="input"
            defaultValue={defaultUrl}
            placeholder="https://…"
            required
          />
        </div>
      )}
      <div>
        <label className="label" htmlFor="scan-mode">
          Mode
        </label>
        <select id="scan-mode" name="mode" className="input" defaultValue="full">
          <option value="fast">Fast (secrets, exposure, security, DNS…)</option>
          <option value="full">Full black-box</option>
          <option value="crawl">Crawl (paid quota)</option>
        </select>
      </div>
      {projectId && (
        <p className="text-xs text-[var(--mut)]">
          {authReady ? (
            <span className="text-[var(--lime)]">
              Authenticated session attached — scan includes same-origin logged-in requests.
            </span>
          ) : (
            <>
              External only right now. Enable <strong className="text-[var(--ink)]">Authenticated testing</strong>{' '}
              above to scan behind login.
            </>
          )}
        </p>
      )}
      <label className="flex items-start gap-2 text-sm text-[var(--mut)]">
        <input name="authorized" type="checkbox" required className="mt-1" />
        <span>
          I own this system or have explicit written authorization to test it. Unauthorized scanning may
          be illegal.
        </span>
      </label>
      {error && <p className="text-sm text-[var(--hi)]">{error}</p>}
      <button className="btn-primary" disabled={loading}>
        {loading ? 'Scanning… (may take ~30s)' : 'Run scan'}
      </button>
    </form>
  );
}

/** Opt-in authenticated / internal testing with a dedicated test account session */
export function AuthAccessPanel({
  projectId,
  projectUrl,
  initial,
}: {
  projectId: string;
  projectUrl: string;
  initial?: {
    enabled: boolean;
    mode: string | null;
    email: string | null;
    loginUrl: string | null;
    hasSecret: boolean;
    verifiedAt: string | null;
    ready: boolean;
  };
}) {
  const router = useRouter();
  const [enabled, setEnabled] = useState(initial?.enabled ?? false);
  const [mode, setMode] = useState<'cookie' | 'bearer' | 'password'>(
    (initial?.mode as 'cookie' | 'bearer' | 'password') || 'cookie',
  );
  const [email, setEmail] = useState(initial?.email || '');
  const [secret, setSecret] = useState('');
  const [loginUrl, setLoginUrl] = useState(initial?.loginUrl || '');
  const [hasSecret, setHasSecret] = useState(initial?.hasSecret ?? false);
  const [ready, setReady] = useState(initial?.ready ?? false);
  const [verifiedAt, setVerifiedAt] = useState(initial?.verifiedAt || '');
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState<'save' | 'verify' | 'delete' | null>(null);

  function applyAuth(auth: {
    enabled: boolean;
    mode: string | null;
    email: string | null;
    loginUrl: string | null;
    hasSecret: boolean;
    verifiedAt: string | null;
    ready: boolean;
  }) {
    setEnabled(auth.enabled);
    if (auth.mode === 'cookie' || auth.mode === 'bearer' || auth.mode === 'password') {
      setMode(auth.mode);
    }
    setEmail(auth.email || '');
    setLoginUrl(auth.loginUrl || '');
    setHasSecret(auth.hasSecret);
    setReady(auth.ready);
    setVerifiedAt(auth.verifiedAt || '');
  }

  async function save() {
    setLoading('save');
    setErr('');
    setMsg('');
    try {
      const res = await fetch(`/api/v1/projects/${projectId}/auth`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          enabled,
          mode,
          email: email || null,
          secret: secret || null,
          loginUrl: loginUrl || null,
          keepExistingSecret: !secret,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErr(data.error || 'Save failed');
        return;
      }
      applyAuth(data.auth);
      setSecret('');
      setMsg('Saved. Click “Verify session” before relying on authenticated scans.');
      router.refresh();
    } catch {
      setErr('Network error');
    } finally {
      setLoading(null);
    }
  }

  async function verify() {
    setLoading('verify');
    setErr('');
    setMsg('');
    try {
      const res = await fetch(`/api/v1/projects/${projectId}/auth`, { method: 'POST' });
      const data = await res.json();
      if (data.auth) applyAuth(data.auth);
      if (!data.ok) {
        setErr(data.detail || 'Verification failed');
        return;
      }
      setMsg(data.detail || 'Verified');
      router.refresh();
    } catch {
      setErr('Network error');
    } finally {
      setLoading(null);
    }
  }

  async function optOut() {
    if (!confirm('Disable authenticated testing and permanently delete stored test credentials?')) {
      return;
    }
    setLoading('delete');
    setErr('');
    setMsg('');
    try {
      const res = await fetch(`/api/v1/projects/${projectId}/auth`, { method: 'DELETE' });
      const data = await res.json();
      if (!res.ok) {
        setErr(data.error || 'Delete failed');
        return;
      }
      applyAuth(data.auth);
      setSecret('');
      setMsg(data.detail || 'Authenticated testing disabled.');
      router.refresh();
    } catch {
      setErr('Network error');
    } finally {
      setLoading(null);
    }
  }

  return (
    <div className="panel space-y-4 p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-xs uppercase text-[var(--mut)]">Authenticated testing (optional)</div>
          <h2 className="mono mt-1 text-lg font-bold">Unlock internal scans</h2>
          <p className="mt-1 max-w-2xl text-sm text-[var(--mut)]">
            External scans only see anonymous traffic. To test your dashboard and logged-in APIs, create a{' '}
            <strong className="text-[var(--ink)]">dedicated test user</strong> on your app, confirm its email,
            log in, then save a session cookie or API token here. Opt out anytime — we delete credentials.
          </p>
        </div>
        <span
          className={`mono rounded border px-2 py-1 text-[10px] uppercase ${
            ready
              ? 'border-[var(--lime)]/40 text-[var(--lime)]'
              : enabled
                ? 'border-[var(--md)]/40 text-[var(--md)]'
                : 'border-[var(--edge)] text-[var(--mut)]'
          }`}
        >
          {ready ? 'ready' : enabled ? 'needs verify' : 'off'}
        </span>
      </div>

      <ol className="list-decimal space-y-1 pl-5 text-sm text-[var(--mut)]">
        <li>
          On <span className="mono text-[var(--ink)]">{projectUrl}</span>, register a non-production user
          (e.g. <code className="text-[var(--ink)]">vta-scanner@yourdomain.com</code>).
        </li>
        <li>Confirm the email link for that user.</li>
        <li>Log in as that user, then copy the session cookie or a test API bearer token.</li>
        <li>Enable below, paste the secret, save, then verify.</li>
      </ol>

      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => setEnabled(e.target.checked)}
        />
        <span>
          I opt in to authenticated scans using a <strong>test account I control</strong>. I can disable and
          delete credentials anytime.
        </span>
      </label>

      {enabled && (
        <div className="space-y-3 border-t border-[var(--edge)] pt-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className="label" htmlFor="auth-mode">
                Session type
              </label>
              <select
                id="auth-mode"
                className="input"
                value={mode}
                onChange={(e) => setMode(e.target.value as 'cookie' | 'bearer' | 'password')}
              >
                <option value="cookie">Session cookie (recommended)</option>
                <option value="bearer">API bearer token</option>
                <option value="password">Test email + password (+ optional cookie)</option>
              </select>
            </div>
            <div>
              <label className="label" htmlFor="auth-email">
                Test user email (label)
              </label>
              <input
                id="auth-email"
                type="email"
                className="input"
                placeholder="vta-scanner@yourdomain.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
          </div>

          <div>
            <label className="label" htmlFor="auth-secret">
              {mode === 'cookie'
                ? 'Session cookie'
                : mode === 'bearer'
                  ? 'Bearer token'
                  : 'Password (or JSON {"email","password","cookie"})'}
              {hasSecret && !secret ? ' · saved (leave blank to keep)' : ''}
            </label>
            <input
              id="auth-secret"
              type="password"
              className="input mono"
              autoComplete="off"
              placeholder={
                mode === 'cookie'
                  ? 'session=…; other=…'
                  : mode === 'bearer'
                    ? 'sk_test_… or JWT'
                    : 'test-account-password'
              }
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
            <p className="mt-1 text-[11px] text-[var(--mut)]">
              Chrome: DevTools → Application → Cookies → copy values for your app host. Prefer a throwaway
              test account — never production admin.
            </p>
          </div>

          <div>
            <label className="label" htmlFor="auth-login-url">
              Verify URL (optional)
            </label>
            <input
              id="auth-login-url"
              className="input mono"
              placeholder={`${projectUrl.replace(/\/$/, '')}/dashboard`}
              value={loginUrl}
              onChange={(e) => setLoginUrl(e.target.value)}
            />
            <p className="mt-1 text-[11px] text-[var(--mut)]">
              Page that should return 200 only when logged in (defaults to project URL).
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              className="btn-primary text-xs"
              disabled={loading !== null}
              onClick={save}
            >
              {loading === 'save' ? 'Saving…' : 'Save'}
            </button>
            <button
              type="button"
              className="btn-ghost text-xs"
              disabled={loading !== null || !hasSecret}
              onClick={verify}
            >
              {loading === 'verify' ? 'Checking…' : 'Verify session'}
            </button>
            <button
              type="button"
              className="btn-ghost text-xs text-[var(--hi)]"
              disabled={loading !== null}
              onClick={optOut}
            >
              {loading === 'delete' ? 'Removing…' : 'Opt out & delete credentials'}
            </button>
          </div>

          {verifiedAt && (
            <p className="mono text-[11px] text-[var(--lime)]">
              Last verified {new Date(verifiedAt).toLocaleString()}
            </p>
          )}
        </div>
      )}

      {msg && <p className="text-sm text-[var(--lime)]">{msg}</p>}
      {err && <p className="text-sm text-[var(--hi)]">{err}</p>}
    </div>
  );
}

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn-ghost text-xs"
      onClick={async () => {
        await navigator.clipboard.writeText(text);
        setDone(true);
        setTimeout(() => setDone(false), 1500);
      }}
    >
      {done ? 'Copied' : label}
    </button>
  );
}

export function CreateKeyForm() {
  const router = useRouter();
  const [secret, setSecret] = useState<string | null>(null);
  const [error, setError] = useState('');

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError('');
    const fd = new FormData(e.currentTarget);
    const res = await fetch('/api/v1/keys', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: fd.get('name') }),
    });
    const data = await res.json();
    if (!res.ok) {
      setError(data.error || 'Failed');
      return;
    }
    setSecret(data.secret);
    router.refresh();
  }

  return (
    <div className="space-y-4">
      <form onSubmit={onSubmit} className="flex flex-wrap items-end gap-3">
        <div>
          <label className="label">Key name</label>
          <input name="name" className="input w-56" defaultValue="MCP / CI" required />
        </div>
        <button className="btn-primary">Create API key</button>
      </form>
      {error && <p className="text-sm text-[var(--hi)]">{error}</p>}
      {secret && (
        <div className="panel border-[var(--lime)] p-4">
          <p className="text-sm text-[var(--mut)]">Copy now — shown once:</p>
          <code className="mono mt-2 block break-all text-[var(--lime)]">{secret}</code>
          <div className="mt-2">
            <CopyButton text={secret} />
          </div>
        </div>
      )}
    </div>
  );
}

/** Plan cards with CTA under each plan — primary billing UI. */
export function BillingPlanCards({
  stripeEnabled,
  currentPlan = 'free',
}: {
  stripeEnabled: boolean;
  currentPlan?: string;
}) {
  const router = useRouter();
  const [error, setError] = useState('');
  const [msg, setMsg] = useState('');
  const [loading, setLoading] = useState<'weekly' | 'daily' | 'commit' | 'portal' | 'sync' | null>(
    null,
  );

  async function checkout(plan: 'weekly' | 'daily' | 'commit') {
    setError('');
    setMsg('');
    setLoading(plan);
    try {
      const res = await fetch('/api/v1/billing/checkout', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ plan }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || `Checkout failed (${res.status})`);
        return;
      }
      if (!data.url) {
        setError('Checkout did not return a Stripe URL');
        return;
      }
      window.location.assign(data.url);
    } catch {
      setError('Network error starting checkout');
    } finally {
      setLoading(null);
    }
  }

  async function portal() {
    setError('');
    setMsg('');
    setLoading('portal');
    try {
      const res = await fetch('/api/v1/billing/portal', { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || `Portal failed (${res.status})`);
        return;
      }
      if (!data.url) {
        setError('Billing portal did not return a URL');
        return;
      }
      window.location.assign(data.url);
    } catch {
      setError('Network error opening billing portal');
    } finally {
      setLoading(null);
    }
  }

  async function syncPlan() {
    setError('');
    setMsg('');
    setLoading('sync');
    try {
      const params = new URLSearchParams(window.location.search);
      const sessionId = params.get('session_id') || undefined;
      const res = await fetch('/api/v1/billing/sync', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(sessionId ? { session_id: sessionId } : {}),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || data.detail || `Sync failed (${res.status})`);
        return;
      }
      setMsg(data.detail || `Plan: ${data.plan}`);
      router.refresh();
    } catch {
      setError('Network error syncing plan');
    } finally {
      setLoading(null);
    }
  }

  const cards: {
    id: 'weekly' | 'daily' | 'commit';
    badge?: string;
    features: string[];
    ctaClass: string;
  }[] = [
    {
      id: 'weekly',
      features: [
        '1 project',
        'Weekly full suite',
        'MCP + fix prompts',
        'Share links + badge',
        'Ownership verification',
      ],
      ctaClass: 'btn-ghost w-full justify-center',
    },
    {
      id: 'daily',
      features: [
        '3 projects',
        'Daily full suite',
        'Deploy webhooks',
        'GitHub App checks',
        'Crawl mode',
      ],
      ctaClass: 'btn-ghost w-full justify-center',
    },
    {
      id: 'commit',
      badge: 'Recommended',
      features: [
        '10 projects',
        'Every production deploy',
        'Claude / Codex fix loop',
        'Highest scan cap',
        'Mission-critical cadence',
      ],
      ctaClass: 'btn-primary w-full justify-center',
    },
  ];

  return (
    <div className="space-y-6">
      {!stripeEnabled && (
        <p className="rounded-lg border border-[var(--md)]/40 bg-[var(--md)]/10 px-3 py-2 text-sm text-[var(--md)]">
          Stripe may not be fully configured. Checkout will report the exact error if keys/prices are
          missing.
        </p>
      )}

      <div className="grid gap-5 lg:grid-cols-3">
        {cards.map((card) => {
          const plan = PLANS[card.id];
          const isCurrent = currentPlan === card.id;
          const isRecommended = card.id === 'commit' && !isCurrent;
          return (
            <div
              key={card.id}
              className={[
                'relative flex flex-col rounded-2xl border p-6 transition',
                isCurrent
                  ? 'border-[var(--lime)] bg-[var(--lime)]/5 shadow-[0_0_0_1px_var(--lime)]'
                  : isRecommended
                    ? 'border-[var(--lime)]/50 bg-gradient-to-b from-[var(--lime)]/10 to-transparent shadow-lg shadow-black/40'
                    : 'border-[var(--edge)] bg-[var(--panel)] hover:border-[var(--ink)]/20',
              ].join(' ')}
            >
              {card.badge && (
                <span className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full bg-[var(--lime)] px-3 py-0.5 text-[10px] font-bold uppercase tracking-wide text-black">
                  {card.badge}
                </span>
              )}
              <div className="mono text-xs font-semibold uppercase tracking-wider text-[var(--mut)]">
                {plan.name}
              </div>
              <div className="mt-3 flex items-baseline gap-1">
                <span className="mono text-4xl font-extrabold tracking-tight text-[var(--ink)]">
                  ${plan.priceMonthlyUsd}
                </span>
                <span className="text-sm text-[var(--mut)]">/mo</span>
              </div>
              <p className="mt-3 min-h-[2.75rem] text-sm leading-snug text-[var(--mut)]">{plan.tagline}</p>
              <ul className="mt-5 flex-1 space-y-2 text-sm text-[var(--ink)]">
                {card.features.map((f) => (
                  <li key={f} className="flex gap-2">
                    <span className="text-[var(--lime)]">✓</span>
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
              <div className="mt-6">
                <button
                  type="button"
                  className={card.ctaClass}
                  disabled={loading !== null || isCurrent}
                  onClick={() => checkout(card.id)}
                >
                  {loading === card.id
                    ? 'Starting checkout…'
                    : isCurrent
                      ? 'Current plan'
                      : `Upgrade — $${plan.priceMonthlyUsd}/mo`}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      <div className="flex flex-wrap items-center gap-3 border-t border-[var(--edge)] pt-5">
        <button type="button" className="btn-ghost" disabled={loading !== null} onClick={portal}>
          {loading === 'portal' ? 'Opening portal…' : 'Billing portal'}
        </button>
        <button type="button" className="btn-ghost" disabled={loading !== null} onClick={syncPlan}>
          {loading === 'sync' ? 'Syncing…' : 'Refresh plan from Stripe'}
        </button>
        <p className="text-xs text-[var(--mut)]">
          Live Checkout · VibeTesting Agent. After payment, use Refresh if the plan lags.
        </p>
      </div>

      {error && <p className="text-sm text-[var(--hi)]">{error}</p>}
      {msg && <p className="text-sm text-[var(--lime)]">{msg}</p>}
      <DevUpgradeButtons />
    </div>
  );
}

/** @deprecated use BillingPlanCards — kept as alias for any old imports */
export function BillingButtons(props: {
  stripeEnabled: boolean;
  currentPlan?: string;
}) {
  return <BillingPlanCards {...props} />;
}

function DevUpgradeButtons() {
  const router = useRouter();
  if (process.env.NODE_ENV === 'production') return null;
  return (
    <div className="flex flex-wrap gap-2">
      {(['weekly', 'daily', 'commit'] as const).map((plan) => (
        <button
          key={plan}
          type="button"
          className="btn-ghost text-xs"
          onClick={async () => {
            await fetch('/api/v1/billing/dev-upgrade', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ plan }),
            });
            router.refresh();
          }}
        >
          Dev: {plan}
        </button>
      ))}
    </div>
  );
}

export function SettingsForm({
  notifyEmail,
  slackWebhookUrl,
}: {
  notifyEmail: boolean;
  slackWebhookUrl: string | null;
}) {
  const [msg, setMsg] = useState('');
  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const res = await fetch('/api/v1/settings', {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        notifyEmail: fd.get('notifyEmail') === 'on',
        slackWebhookUrl: String(fd.get('slackWebhookUrl') || '') || null,
      }),
    });
    const data = await res.json();
    setMsg(res.ok ? 'Saved' : data.error || 'Failed');
  }
  return (
    <form onSubmit={onSubmit} className="panel max-w-lg space-y-4 p-6">
      <label className="flex items-center gap-2 text-sm">
        <input name="notifyEmail" type="checkbox" defaultChecked={notifyEmail} />
        Email me on new high findings
      </label>
      <div>
        <label className="label">Slack webhook URL</label>
        <input
          name="slackWebhookUrl"
          className="input"
          defaultValue={slackWebhookUrl || ''}
          placeholder="https://hooks.slack.com/…"
        />
      </div>
      <button className="btn-primary">Save</button>
      {msg && <p className="text-sm text-[var(--mut)]">{msg}</p>}
    </form>
  );
}

export function DevUpgradeButton() {
  return <DevUpgradeButtons />;
}

type LiteScanResult = {
  grade?: string;
  score?: number;
  url?: string;
  summary?: { checked?: number; failed: number; high: number; medium: number };
  findings?: { severity: string; title: string; category: string; fix?: string; pass?: boolean }[];
  agentPrompt?: string;
  agentPromptPreview?: string;
  issueCount?: number;
  upgrade?: {
    message: string;
    headline?: string;
    cta?: string;
    ctaLabel?: string;
  };
};

type LogLine = {
  id: number;
  kind: 'info' | 'phase' | 'pass' | 'fail' | 'error' | 'done';
  text: string;
};

const LITE_PROMPT_KEY = 'vta_lite_agent_prompt';

/** Homepage public lite scanner */
export function LiteScanBox() {
  const [url, setUrl] = useState('');
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [result, setResult] = useState<LiteScanResult | null>(null);
  const [loggedIn, setLoggedIn] = useState(false);
  const [unlocked, setUnlocked] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const logId = useRef(0);

  useEffect(() => {
    const el = logRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [logs]);

  useEffect(() => {
    fetch('/api/v1/me')
      .then((r) => setLoggedIn(r.ok))
      .catch(() => setLoggedIn(false));
  }, []);

  function pushLog(kind: LogLine['kind'], text: string) {
    logId.current += 1;
    setLogs((prev) => [...prev, { id: logId.current, kind, text }]);
  }

  async function run(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError('');
    setResult(null);
    setLogs([]);
    logId.current = 0;
    pushLog('info', `$ vibetesting lite ${url.trim()}`);
    pushLog('info', 'Connecting to edge scanner…');

    try {
      const res = await fetch('/api/v1/lite-scan', {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/x-ndjson' },
        body: JSON.stringify({ url, authorized: true, stream: true }),
      });

      const ctype = res.headers.get('content-type') || '';

      // Fallback for non-streaming responses (errors / older deploys)
      if (!res.ok || !ctype.includes('ndjson') || !res.body) {
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          setError(data.error || 'Scan failed');
          pushLog('error', data.error || `HTTP ${res.status}`);
        } else {
          setResult(data);
          pushLog('done', `Complete — grade ${data.grade} · ${data.score}/100`);
        }
        return;
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop() || '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          let evt: Record<string, unknown>;
          try {
            evt = JSON.parse(trimmed);
          } catch {
            continue;
          }

          const type = String(evt.type || '');
          if (type === 'meta') {
            const suite = Array.isArray(evt.suite) ? evt.suite.join(', ') : 'lite';
            pushLog('info', String(evt.message || 'Stream open'));
            pushLog('phase', `Suite: ${suite}`);
          } else if (type === 'start') {
            pushLog('info', String(evt.message || 'Start'));
          } else if (type === 'phase') {
            pushLog('phase', `› ${String(evt.message || '…')}`);
          } else if (type === 'check') {
            const pass = Boolean(evt.pass);
            pushLog(pass ? 'pass' : 'fail', String(evt.message || evt.title || 'check'));
          } else if (type === 'done') {
            pushLog('done', String(evt.message || 'Done'));
          } else if (type === 'result') {
            const { type: _t, ...payload } = evt;
            const lite = payload as LiteScanResult;
            setResult(lite);
            setUnlocked(false);
            // Persist full prompt so post-signup dashboard can surface it
            if (lite.agentPrompt && typeof sessionStorage !== 'undefined') {
              try {
                sessionStorage.setItem(
                  LITE_PROMPT_KEY,
                  JSON.stringify({
                    url: lite.url,
                    grade: lite.grade,
                    score: lite.score,
                    agentPrompt: lite.agentPrompt,
                    at: Date.now(),
                  }),
                );
              } catch {
                /* ignore quota */
              }
            }
            pushLog(
              'done',
              `Result ready — grade ${String(evt.grade ?? '?')} · ${String(evt.score ?? '?')}/100`,
            );
          } else if (type === 'error') {
            const msg = String(evt.error || 'Scan failed');
            setError(msg);
            pushLog('error', msg);
          }
        }
      }
    } catch {
      setError('Network error');
      pushLog('error', 'Network error — could not reach scanner');
    } finally {
      setLoading(false);
    }
  }

  const showLog = loading || logs.length > 0;

  return (
    <div className="panel p-6 sm:p-8">
      <div className="mono text-xs uppercase tracking-[0.16em] text-[var(--lime)]">Free lite scan</div>
      <h2 className="mono mt-2 text-xl font-bold sm:text-2xl">Point it at your deploy. No signup.</h2>
      <p className="mt-2 text-sm text-[var(--mut)]">
        Instant check for leaked secrets, exposed config, core security headers & DNS. Full suite unlocks after
        domain-email inbox proof or DNS TXT.
      </p>
      <form onSubmit={run} className="mt-5 space-y-3">
        <div>
          <label className="label" htmlFor="lite-scan-url">
            Deploy URL
          </label>
          <input
            id="lite-scan-url"
            name="url"
            type="url"
            className="input mono text-base"
            placeholder="https://your-vibe-app.vercel.app"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            required
            autoComplete="url"
          />
        </div>
        <label className="flex items-start gap-2 text-xs text-[var(--mut)]" htmlFor="lite-scan-auth">
          <input
            id="lite-scan-auth"
            name="authorized"
            type="checkbox"
            className="mt-0.5"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            required
          />
          <span>
            I own this system or have written authorization to test it. Unauthorized scanning may be illegal.
          </span>
        </label>
        <button className="btn-primary w-full sm:w-auto" disabled={loading || !authorized}>
          {loading ? 'Scanning… watch the log' : 'Run free lite scan'}
        </button>
      </form>
      {error && <p className="mt-3 text-sm text-[var(--hi)]">{error}</p>}

      {showLog && (
        <div className="mt-5 overflow-hidden rounded-xl border border-[var(--edge)] bg-[#050806] shadow-inner">
          <div className="flex items-center justify-between border-b border-[var(--edge)] bg-black/40 px-3 py-2">
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-[#ff5f56]" />
              <span className="h-2.5 w-2.5 rounded-full bg-[#ffb638]" />
              <span className="h-2.5 w-2.5 rounded-full bg-[#a9ef4f]" />
              <span className="mono ml-2 text-[11px] uppercase tracking-wider text-[var(--mut)]">
                lite scan log
              </span>
            </div>
            <span className="mono text-[11px] text-[var(--mut)]">
              {loading ? (
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[var(--lime)]" />
                  running
                </span>
              ) : (
                'idle'
              )}
            </span>
          </div>
          <div
            ref={logRef}
            className="scan-log mono max-h-72 overflow-y-auto px-3 py-3 text-[12px] leading-5 sm:max-h-80 sm:text-[13px]"
            role="log"
            aria-live="polite"
            aria-relevant="additions"
          >
            {logs.map((line) => (
              <div
                key={line.id}
                className={
                  line.kind === 'pass'
                    ? 'text-[var(--lime)]'
                    : line.kind === 'fail'
                      ? 'text-[var(--hi)]'
                      : line.kind === 'error'
                        ? 'text-[var(--hi)]'
                        : line.kind === 'phase'
                          ? 'text-[var(--md)]'
                          : line.kind === 'done'
                            ? 'text-[var(--lime)]'
                            : 'text-[var(--mut)]'
                }
              >
                {line.text}
              </div>
            ))}
            {loading && (
              <div className="mt-0.5 text-[var(--mut)]">
                <span className="animate-pulse">▌</span>
              </div>
            )}
          </div>
        </div>
      )}

      {result && (
        <div className="mt-6 space-y-4 border-t border-[var(--edge)] pt-5">
          <div className="flex flex-wrap items-end gap-6">
            <div>
              <div className="text-xs uppercase text-[var(--mut)]">Grade</div>
              <div className="mono text-5xl font-extrabold text-[var(--lime)]">{result.grade}</div>
            </div>
            <div>
              <div className="text-xs uppercase text-[var(--mut)]">Score</div>
              <div className="mono text-3xl font-bold">{result.score}/100</div>
            </div>
            <div className="text-sm text-[var(--mut)]">
              {result.summary?.failed ?? 0} issues · 🟥 {result.summary?.high ?? 0} · 🟧{' '}
              {result.summary?.medium ?? 0}
            </div>
          </div>
          <ul className="space-y-2">
            {(result.findings || []).map((f, i) => (
              <li key={i} className="rounded-lg border border-[var(--edge)] bg-black/20 px-3 py-2 text-sm">
                <span className="mono text-xs uppercase text-[var(--md)]">{f.severity}</span>{' '}
                <span className="font-medium">{f.title}</span>
                <span className="text-[var(--mut)]"> · {f.category}</span>
                {f.fix && (
                  <div className="mt-1 text-xs text-[var(--mut)]">Fix: {f.fix}</div>
                )}
              </li>
            ))}
          </ul>

          {/* Claude / Codex fix prompt CTA */}
          {(result.summary?.failed ?? 0) > 0 && result.agentPrompt && (
            <div className="rounded-xl border border-[var(--lime)]/35 bg-[var(--lime)]/5 p-5">
              <div className="mono text-xs uppercase tracking-[0.14em] text-[var(--lime)]">
                {result.upgrade?.headline || 'Claude / Codex fix prompt'}
              </div>
              <h3 className="mono mt-2 text-lg font-bold">
                Fix all {result.issueCount ?? result.summary?.failed} issues for this website
              </h3>
              <p className="mt-2 text-sm text-[var(--mut)]">
                {result.upgrade?.message ||
                  'Create a free account to unlock a ranked P1→Pn prompt you can paste into Claude, Codex, or Cursor.'}
              </p>

              {loggedIn || unlocked ? (
                <div className="mt-4 space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <CopyButton text={result.agentPrompt} label="Copy full Claude/Codex prompt" />
                    <span className="text-xs text-[var(--mut)]">
                      Paste into Claude · Codex · Cursor · Copilot Chat
                    </span>
                  </div>
                  <pre className="mono max-h-64 overflow-auto rounded-lg border border-[var(--edge)] bg-black/40 p-3 text-[11px] leading-relaxed text-[var(--ink)] whitespace-pre-wrap">
                    {result.agentPrompt}
                  </pre>
                </div>
              ) : (
                <div className="mt-4 space-y-3">
                  <pre className="mono max-h-40 overflow-hidden rounded-lg border border-[var(--edge)] bg-black/40 p-3 text-[11px] leading-relaxed text-[var(--mut)] whitespace-pre-wrap">
                    {result.agentPromptPreview || result.agentPrompt.slice(0, 600)}
                  </pre>
                  <div className="relative">
                    <div className="pointer-events-none absolute inset-x-0 -top-10 h-10 bg-gradient-to-t from-[var(--panel)] to-transparent" />
                    <div className="flex flex-wrap gap-3">
                      <a
                        href="/login"
                        className="btn-primary"
                        onClick={() => {
                          try {
                            if (result.agentPrompt) {
                              sessionStorage.setItem(
                                LITE_PROMPT_KEY,
                                JSON.stringify({
                                  url: result.url,
                                  grade: result.grade,
                                  score: result.score,
                                  agentPrompt: result.agentPrompt,
                                  at: Date.now(),
                                }),
                              );
                            }
                          } catch {
                            /* ignore */
                          }
                        }}
                      >
                        {result.upgrade?.ctaLabel || 'Create free account'} — unlock full prompt
                      </a>
                      <button
                        type="button"
                        className="btn-ghost text-xs"
                        onClick={() => setUnlocked(true)}
                      >
                        I already have an account — show prompt
                      </button>
                    </div>
                    <p className="mt-2 text-[11px] text-[var(--mut)]">
                      Free account also unlocks ownership verification, saved scans, and the full suite on our
                      fleet.
                    </p>
                  </div>
                </div>
              )}
            </div>
          )}

          {(result.summary?.failed ?? 0) === 0 && (
            <div className="rounded-xl border border-[var(--edge)] bg-black/20 p-4 text-sm text-[var(--mut)]">
              Clean lite scan. Create a free account to save history and unlock full continuous scans.
              <div className="mt-3">
                <a href="/login" className="btn-primary">
                  Create free account
                </a>
              </div>
            </div>
          )}

          <div className="flex flex-wrap gap-3">
            <a href="/login" className="btn-ghost">
              Dashboard · full suite →
            </a>
            <a href="/docs/coverage" className="btn-ghost text-xs">
              What we cover (WSTG)
            </a>
          </div>
        </div>
      )}
    </div>
  );
}

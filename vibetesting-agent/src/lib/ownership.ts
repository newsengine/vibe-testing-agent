/**
 * Project ownership proof:
 * 1) Domain email — signed-in address is on the app's domain + inbox click verified
 * 2) DNS TXT — vibetesting-verify=<token> on host or _vta.<host>
 * 3) Well-known file — https://<host>/.well-known/vibetesting-verify.txt containing the token
 * 4) Meta tag — <meta name="vibetesting-verify" content="<token>"> on the homepage
 */
import { eq } from 'drizzle-orm';
import { getDb, schema } from './db';
import { token } from './ids';
import { config } from './config';
import { sendEmail } from './email';
import { verifyDomainOwnership, verifyFileOwnership, verifyMetaOwnership, hostnameFromUrl } from './dns-verify';
import { audit } from './audit';
import type { User, Project } from './db/schema';
import { parseVerifyMethod, parseVerifyRequest, OWNERSHIP_METHODS, type OwnershipMethod } from './verify-method';

export { parseVerifyMethod, parseVerifyRequest, OWNERSHIP_METHODS, type OwnershipMethod };

/** Consumer / free-mail hosts cannot prove ownership of an app domain via email alone. */
const PUBLIC_EMAIL_DOMAINS = new Set(
  [
    'gmail.com',
    'googlemail.com',
    'yahoo.com',
    'yahoo.co.uk',
    'hotmail.com',
    'outlook.com',
    'live.com',
    'msn.com',
    'icloud.com',
    'me.com',
    'mac.com',
    'aol.com',
    'protonmail.com',
    'proton.me',
    'pm.me',
    'mail.com',
    'gmx.com',
    'gmx.net',
    'yandex.com',
    'yandex.ru',
    'qq.com',
    '163.com',
    '126.com',
    'hey.com',
    'fastmail.com',
    'tutanota.com',
    'zoho.com',
    'users.noreply.github.com',
  ].map((d) => d.toLowerCase()),
);

export function emailLocalDomain(email: string): string | null {
  const at = email.lastIndexOf('@');
  if (at < 1) return null;
  return email.slice(at + 1).toLowerCase().trim();
}

/**
 * True if the sign-in email's domain owns the target hostname
 * (exact match or hostname is a subdomain of the email domain).
 */
export function emailMatchesProjectHost(email: string, hostname: string): boolean {
  const domain = emailLocalDomain(email);
  if (!domain) return false;
  if (PUBLIC_EMAIL_DOMAINS.has(domain)) return false;

  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host === domain) return true;
  if (host.endsWith(`.${domain}`)) return true;
  return false;
}

export function isEmailInboxVerified(user: User): boolean {
  return Boolean(user.emailVerifiedAt);
}

export function describeOwnershipOptions(user: User, project: Project) {
  const domain = emailLocalDomain(user.email);
  const emailEligible = emailMatchesProjectHost(user.email, project.hostname);
  return {
    email: {
      address: user.email,
      domain,
      eligible: emailEligible,
      inboxVerified: isEmailInboxVerified(user),
      reason: emailEligible
        ? isEmailInboxVerified(user)
          ? 'Inbox verified — you can prove ownership with this address'
          : 'Click the link we email you to prove you control this inbox'
        : domain && PUBLIC_EMAIL_DOMAINS.has(domain)
          ? 'Free/public email addresses cannot prove ownership of an app domain — use DNS TXT or sign in with an address @ your domain'
          : `Sign in with an email at @${project.hostname} (or its parent domain), then verify the inbox`,
    },
    dns: {
      host: project.hostname,
      altHost: `_vta.${project.hostname}`,
      record: `vibetesting-verify=${project.verifyToken}`,
    },
    file: {
      url: `https://${project.hostname}/.well-known/vibetesting-verify.txt`,
      content: project.verifyToken,
      instructions: `Create a file at /.well-known/vibetesting-verify.txt containing exactly: ${project.verifyToken}`,
    },
    meta: {
      tag: `<meta name="vibetesting-verify" content="${project.verifyToken}">`,
      instructions: `Add this meta tag to your homepage <head>: <meta name="vibetesting-verify" content="${project.verifyToken}">`,
    },
  };
}

/** Issue (or re-issue) inbox verification email. */
export async function sendInboxVerification(user: User): Promise<{
  sent: boolean;
  expiresAt: Date;
  devVerifyUrl?: string;
}> {
  const db = await getDb();
  const verifyToken = token(24);
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1h
  await db
    .update(schema.users)
    .set({
      emailVerifyToken: verifyToken,
      emailVerifyExpiresAt: expiresAt,
      updatedAt: new Date(),
    })
    .where(eq(schema.users.id, user.id));

  const verifyUrl = `${config.appUrl}/api/auth/verify-email?token=${encodeURIComponent(verifyToken)}`;
  const subject = 'Verify your email for VibeTesting Agent ownership';
  const text = [
    `Prove you control ${user.email} to unlock domain ownership for full scans.`,
    ``,
    `Click this link (expires in 1 hour):`,
    verifyUrl,
    ``,
    `If you did not request this, ignore this email.`,
  ].join('\n');

  const result = await sendEmail(user.email, subject, text, {
    html: `
      <p>Prove you control <strong>${escapeHtml(user.email)}</strong> to unlock domain ownership for full scans.</p>
      <p><a href="${verifyUrl}">Click to verify this inbox</a> (expires in 1 hour).</p>
      <p style="color:#666;font-size:12px">If you did not request this, ignore this email.</p>
    `,
  });

  await audit('email.verify_sent', { userId: user.id, detail: { email: user.email, ok: result.ok } });

  return {
    sent: result.ok,
    expiresAt,
    devVerifyUrl: result.devLogged ? verifyUrl : undefined,
  };
}

export async function confirmInboxVerification(rawToken: string): Promise<User | null> {
  if (!rawToken || rawToken.length < 8) return null;
  const db = await getDb();
  const rows = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.emailVerifyToken, rawToken))
    .limit(1);
  const user = rows[0];
  if (!user) return null;
  if (user.emailVerifyExpiresAt && new Date(user.emailVerifyExpiresAt).getTime() < Date.now()) {
    return null;
  }
  const now = new Date();
  await db
    .update(schema.users)
    .set({
      emailVerifiedAt: now,
      emailVerifyToken: null,
      emailVerifyExpiresAt: null,
      updatedAt: now,
    })
    .where(eq(schema.users.id, user.id));
  await audit('email.verified', { userId: user.id, detail: { email: user.email } });
  const refreshed = await db.select().from(schema.users).where(eq(schema.users.id, user.id)).limit(1);
  return refreshed[0] ?? null;
}

/** Mark inbox verified from trusted IdP (WorkOS emailVerified). */
export async function markEmailVerifiedFromIdp(userId: string): Promise<void> {
  const db = await getDb();
  await db
    .update(schema.users)
    .set({
      emailVerifiedAt: new Date(),
      emailVerifyToken: null,
      emailVerifyExpiresAt: null,
      updatedAt: new Date(),
    })
    .where(eq(schema.users.id, userId));
}

export async function verifyProjectOwnership(
  user: User,
  project: Project,
  method: OwnershipMethod,
): Promise<{ project: Project; method: OwnershipMethod; detail: string }> {
  if (project.verified) {
    return { project, method: (project.verifyMethod as OwnershipMethod) || method, detail: 'Already verified' };
  }

  if (method === 'email') {
    if (!emailMatchesProjectHost(user.email, project.hostname)) {
      throw new Error(
        `Email ownership requires signing in with an address on the same domain as ${project.hostname} (not a free mail provider). Or use DNS TXT instead.`,
      );
    }
    // Re-read user in case verification just completed
    const db = await getDb();
    const fresh = (
      await db.select().from(schema.users).where(eq(schema.users.id, user.id)).limit(1)
    )[0];
    if (!fresh?.emailVerifiedAt) {
      throw new Error(
        'Inbox not verified yet. We email a one-click link — open it to prove you control that mailbox, then try again.',
      );
    }
    await db
      .update(schema.projects)
      .set({
        verified: true,
        verifiedAt: new Date(),
        verifyMethod: 'email',
        updatedAt: new Date(),
      })
      .where(eq(schema.projects.id, project.id));
    await audit('project.verified', {
      userId: user.id,
      target: project.id,
      detail: { method: 'email', email: user.email, hostname: project.hostname },
    });
    const updated = (
      await db.select().from(schema.projects).where(eq(schema.projects.id, project.id)).limit(1)
    )[0]!;
    return {
      project: updated,
      method: 'email',
      detail: `Verified via domain email ${user.email} (inbox confirmed)`,
    };
  }

  // DNS
  if (method === 'dns') {
    const result = await verifyDomainOwnership(project.hostname, project.verifyToken);
    if (!result.ok) throw new Error(result.detail);
    const db = await getDb();
    await db
      .update(schema.projects)
      .set({
        verified: true,
        verifiedAt: new Date(),
        verifyMethod: 'dns',
        updatedAt: new Date(),
      })
      .where(eq(schema.projects.id, project.id));
    await audit('project.verified', {
      userId: user.id,
      target: project.id,
      detail: { method: 'dns', ...result },
    });
    const updated = (
      await db.select().from(schema.projects).where(eq(schema.projects.id, project.id)).limit(1)
    )[0]!;
    return { project: updated, method: 'dns', detail: result.detail };
  }

  // Well-known file
  if (method === 'file') {
    const result = await verifyFileOwnership(project.hostname, project.verifyToken);
    if (!result.ok) throw new Error(result.detail);
    const db = await getDb();
    await db
      .update(schema.projects)
      .set({
        verified: true,
        verifiedAt: new Date(),
        verifyMethod: 'file',
        updatedAt: new Date(),
      })
      .where(eq(schema.projects.id, project.id));
    await audit('project.verified', {
      userId: user.id,
      target: project.id,
      detail: { method: 'file', ...result },
    });
    const updated = (
      await db.select().from(schema.projects).where(eq(schema.projects.id, project.id)).limit(1)
    )[0]!;
    return { project: updated, method: 'file', detail: result.detail };
  }

  // Meta tag
  if (method === 'meta') {
    const result = await verifyMetaOwnership(project.hostname, project.verifyToken);
    if (!result.ok) throw new Error(result.detail);
    const db = await getDb();
    await db
      .update(schema.projects)
      .set({
        verified: true,
        verifiedAt: new Date(),
        verifyMethod: 'meta',
        updatedAt: new Date(),
      })
      .where(eq(schema.projects.id, project.id));
    await audit('project.verified', {
      userId: user.id,
      target: project.id,
      detail: { method: 'meta', ...result },
    });
    const updated = (
      await db.select().from(schema.projects).where(eq(schema.projects.id, project.id)).limit(1)
    )[0]!;
    return { project: updated, method: 'meta', detail: result.detail };
  }

  const _exhaustive: never = method;
  throw new Error(`Unknown verification method: ${String(_exhaustive)}`);
}

export { hostnameFromUrl };

function escapeHtml(s: string) {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!,
  );
}

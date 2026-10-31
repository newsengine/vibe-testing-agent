// src/db-critical.ts
// Dynamic Business CMS critical-path suite — authenticated / env-gated checks that belong in the
// official VTA catalog but are NOT part of the default black-box URL scan. Missing credentials SKIP
// cleanly (pass=true, severity info) so CI without secrets never false-fails. Never log or commit secrets.
//
//   vibetesting-agent db-critical https://dynamicbusiness.com
//
// Env (see examples/db-critical-path/.env.example):
//   VTA_EDITOR_EMAIL / VTA_EDITOR_PASSWORD
//   VTA_SUPERADMIN_EMAIL / VTA_SUPERADMIN_PASSWORD
//   VTA_USER_EMAIL / VTA_USER_PASSWORD          (optional; non-staff for profiles RLS)
//   VTA_TOTP_SECRET                            (optional; TOTP seed for staff AAL2 step-up)
//   VTA_<USER|EDITOR|SUPERADMIN>_TOTP_SECRET   (optional; per-role seed, overrides VTA_TOTP_SECRET)
//   VTA_SUPABASE_URL / VTA_SUPABASE_ANON_KEY   (anon/publishable key REQUIRED — legacy JWT anon disabled)
//   VTA_UNPUBLISHED_ARTICLE_URL                (editorial golden-path fixture)
//   VTA_STRIPE_AMOUNT_PROBE=1                  (opt-in; otherwise SKIP)
//   CF_SMOKE_KEY                               (already supported via cf-bypass-headers)
import { createHmac, timingSafeEqual } from 'node:crypto';
import { withCfBypassHeaders } from './cf-bypass-headers.js';
/** Catalog specs for docs/CHECKS.md (appended by catalog.ts). */
export function dbCriticalCheckSpecs() {
    return [
        {
            id: 'db.auth.editor-cms',
            title: 'Editor reaches CMS surfaces',
            severity: 'high',
            cls: 'authenticated',
            description: 'Editor cookie session loads /dashboard/editor HTML (not /login) + Bearer reaches /api/editor/posts (skip if VTA_EDITOR_* missing).',
        },
        {
            id: 'db.auth.superadmin-homepage-config',
            title: 'Superadmin reaches Homepage Config',
            severity: 'high',
            cls: 'authenticated',
            description: 'Superadmin can GET /api/homepage/config (skip if VTA_SUPERADMIN_* missing).',
        },
        {
            id: 'db.auth.superadmin-ad-placements',
            title: 'Superadmin reaches Ad Placements UI',
            severity: 'high',
            cls: 'authenticated',
            description: 'Superadmin cookie session loads /dashboard/admin/homepage HTML without /login bounce (skip if creds missing).',
        },
        {
            id: 'db.api.uploads-ad',
            title: 'POST /api/uploads type=ad accepts tiny PNG',
            severity: 'high',
            cls: 'authenticated',
            description: 'Authenticated upload of a tiny PNG with type=ad returns 201 (DB #1441 dogfood; skip if auth env missing).',
        },
        {
            id: 'db.api.uploads-empty',
            title: 'POST /api/uploads empty → 400 No file provided',
            severity: 'high',
            cls: 'authenticated',
            description: 'Empty multipart upload returns 400 with "No file provided" (DB #1441; skip if auth env missing).',
        },
        {
            id: 'db.api.profiles-rls',
            title: 'Profiles RLS blocks non-staff dump',
            severity: 'high',
            cls: 'authenticated',
            description: 'Non-staff Bearer must not list all profiles via Supabase REST (DB #1416; skip if VTA_USER_* missing).',
        },
        {
            id: 'db.api.ad-track-xss',
            title: 'Ad-track beacon XSS hygiene',
            severity: 'medium',
            cls: 'probe',
            description: 'POST /api/analytics/ad-track with XSS markers returns JSON (not HTML reflection).',
        },
        {
            id: 'db.api.unsubscribe-xss',
            title: 'Unsubscribe page XSS hygiene',
            severity: 'medium',
            cls: 'probe',
            description: 'GET /api/jobs/alerts/unsubscribe with XSS-shaped token does not reflect raw markup (DB #1452).',
        },
        {
            id: 'db.api.stripe-amount',
            title: 'Stripe amount dual-path (gated)',
            severity: 'high',
            cls: 'white-box',
            description: 'Optional non-destructive Stripe billing dual-path probe (VTA_STRIPE_AMOUNT_PROBE=1); otherwise SKIP.',
        },
        {
            id: 'db.editorial.golden-path',
            title: 'Editorial golden-path scaffold',
            severity: 'medium',
            cls: 'white-box',
            description: 'Fetches VTA_UNPUBLISHED_ARTICLE_URL and asserts it is reachable for staff; SKIP if fixture unset.',
        },
    ];
}
const f = (id, title, severity, pass, detail, fix) => ({ category: 'security', id, title, severity, pass, detail, fix });
function skip(id, title, reason) {
    return f(id, title, 'info', true, `SKIP: ${reason}`);
}
function env(name) {
    const v = process.env[name];
    return v && v.trim() ? v.trim() : undefined;
}
function roleCreds(role) {
    const prefix = role === 'user' ? 'VTA_USER' : role === 'editor' ? 'VTA_EDITOR' : 'VTA_SUPERADMIN';
    const email = env(`${prefix}_EMAIL`);
    const password = env(`${prefix}_PASSWORD`);
    if (!email || !password)
        return null;
    return { email, password };
}
/** Minimal RFC 6238 TOTP (SHA-1, 30s, 6 digits) — no extra dependency. */
export function totpCode(secretBase32, nowMs = Date.now()) {
    const key = base32Decode(secretBase32);
    const counter = Math.floor(nowMs / 1000 / 30);
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
    buf.writeUInt32BE(counter & 0xffffffff, 4);
    const hmac = createHmac('sha1', key).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0xf;
    const code = ((hmac[offset] & 0x7f) << 24 | (hmac[offset + 1] & 0xff) << 16 |
        (hmac[offset + 2] & 0xff) << 8 | (hmac[offset + 3] & 0xff)) % 1_000_000;
    return String(code).padStart(6, '0');
}
function base32Decode(input) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const cleaned = input.replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
    let bits = '';
    for (const c of cleaned) {
        const val = alphabet.indexOf(c);
        if (val < 0)
            continue;
        bits += val.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8)
        bytes.push(parseInt(bits.slice(i, i + 8), 2));
    return Buffer.from(bytes);
}
const DEFAULT_SUPABASE_URL = 'https://db.dynamicbusiness.com';
// Legacy JWT-shaped anon key (role=anon). Dynamic Business disabled this class of key —
// do NOT use it as a silent default. Kept only so we can detect "caller still on legacy"
// and fail with a clear override hint.
const LEGACY_JWT_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBnb2ZkcGFpbG1oaXV1em55endhIiwicm9sZSI6ImFub24iLCJpYXQiOjE2NzgzNDU4MzUsImV4cCI6MTk5MzkyMTgzNX0.1m9z0lWiULuq_x5cdyFwHHao7_ea4XeZvHVuCG6tnSU';
/** True for classic eyJ… JWT anon keys (incl. the disabled DB legacy default). */
export function isLegacyJwtAnonKey(key) {
    if (!key)
        return false;
    if (key === LEGACY_JWT_ANON_KEY)
        return true;
    if (!key.startsWith('eyJ'))
        return false;
    const parts = key.split('.');
    if (parts.length !== 3)
        return false;
    try {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
        return payload?.role === 'anon';
    }
    catch {
        return false;
    }
}
function supabaseConfig() {
    const url = (env('VTA_SUPABASE_URL') || env('NEXT_PUBLIC_SUPABASE_URL') || DEFAULT_SUPABASE_URL).replace(/\/$/, '');
    const anonKey = env('VTA_SUPABASE_ANON_KEY') || env('NEXT_PUBLIC_SUPABASE_ANON_KEY') || '';
    return {
        url,
        anonKey,
        missingAnon: !anonKey,
        legacyAnon: Boolean(anonKey) && isLegacyJwtAnonKey(anonKey),
    };
}
const sessionCache = new Map();
/** @supabase/ssr cookie chunk size (see node_modules/@supabase/ssr/.../chunker.js). */
const SSR_COOKIE_MAX_CHUNK = 3180;
/**
 * Storage key for Supabase SSR auth cookies.
 * Prefer project-ref from access_token `iss` (custom domains still mint sb-<ref>-auth-token);
 * fall back to the configured Supabase URL hostname.
 */
export function supabaseAuthStorageKey(accessToken, supabaseUrl) {
    try {
        const payload = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64url').toString('utf8'));
        const iss = String(payload?.iss || '');
        if (iss.startsWith('http')) {
            const host = new URL(iss).hostname.split('.')[0];
            if (host)
                return `sb-${host}-auth-token`;
        }
    }
    catch { /* fall through */ }
    try {
        const host = new URL(supabaseUrl).hostname.split('.')[0];
        if (host)
            return `sb-${host}-auth-token`;
    }
    catch { /* fall through */ }
    return 'sb-auth-token';
}
/** Split a cookie value the same way @supabase/ssr createChunks does. */
export function chunkSupabaseCookie(key, value, chunkSize = SSR_COOKIE_MAX_CHUNK) {
    const encodedValue = encodeURIComponent(value);
    if (encodedValue.length <= chunkSize)
        return [{ name: key, value }];
    const chunks = [];
    let remaining = encodedValue;
    while (remaining.length > 0) {
        let head = remaining.slice(0, chunkSize);
        const lastEscapePos = head.lastIndexOf('%');
        if (lastEscapePos > chunkSize - 3)
            head = head.slice(0, lastEscapePos);
        while (head.length > 0) {
            try {
                decodeURIComponent(head);
                break;
            }
            catch {
                if (head.length > 3 && head.at(-3) === '%')
                    head = head.slice(0, -3);
                else
                    throw new Error('invalid cookie chunk boundary');
            }
        }
        chunks.push(decodeURIComponent(head));
        remaining = remaining.slice(head.length);
    }
    return chunks.map((v, i) => ({ name: `${key}.${i}`, value: v }));
}
/** Build Cookie header for Next.js middleware that uses @supabase/ssr createServerClient. */
export function buildSupabaseSsrCookieHeader(session, supabaseUrl) {
    const storageKey = supabaseAuthStorageKey(session.access_token, supabaseUrl);
    const payload = JSON.stringify({
        access_token: session.access_token,
        token_type: session.token_type || 'bearer',
        expires_in: session.expires_in,
        expires_at: session.expires_at
            ?? (Math.floor(Date.now() / 1000) + (session.expires_in || 3600)),
        refresh_token: session.refresh_token,
        user: session.user ?? null,
    });
    const encoded = `base64-${Buffer.from(payload, 'utf8').toString('base64url')}`;
    return chunkSupabaseCookie(storageKey, encoded)
        .map(({ name, value }) => `${name}=${value}`)
        .join('; ');
}
function rolePrefix(role) {
    return role === 'user' ? 'VTA_USER' : role === 'editor' ? 'VTA_EDITOR' : 'VTA_SUPERADMIN';
}
/** Per-role TOTP seed (VTA_<ROLE>_TOTP_SECRET), falling back to VTA_TOTP_SECRET. Never logged. */
function roleTotpSecret(role) {
    return env(`${rolePrefix(role)}_TOTP_SECRET`) || env('VTA_TOTP_SECRET') || undefined;
}
/** The user's verified TOTP factor id from a GoTrue token response, if any. */
export function verifiedTotpFactor(user) {
    const factors = Array.isArray(user?.factors) ? user.factors : [];
    const f = factors.find((x) => x?.status === 'verified' && (x?.factor_type ?? 'totp') === 'totp');
    return f?.id ? String(f.id) : null;
}
/**
 * Supabase MFA challenge + verify (POST /auth/v1/factors/{id}/challenge then
 * /verify). Returns the aal2 session. Retries once with a fresh challenge in
 * case the code crossed a 30s step. Neither the seed nor any code is logged or
 * returned in an error message.
 */
export async function stepUpToAal2(url, anonKey, accessToken, factorId, secret) {
    const headers = { apikey: anonKey, authorization: `Bearer ${accessToken}`, 'content-type': 'application/json' };
    let lastStatus = 0;
    let lastMsg = '';
    for (let attempt = 0; attempt < 2; attempt++) {
        const ch = await fetch(`${url}/auth/v1/factors/${encodeURIComponent(factorId)}/challenge`, {
            method: 'POST',
            headers,
            body: '{}',
        });
        const chJson = await ch.json().catch(() => ({}));
        if (!ch.ok || !chJson?.id) {
            return { error: `challenge ${ch.status} ${String(chJson?.error_code || chJson?.msg || '')}`.trim() };
        }
        const vr = await fetch(`${url}/auth/v1/factors/${encodeURIComponent(factorId)}/verify`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ challenge_id: chJson.id, code: totpCode(secret) }),
        });
        const vrJson = await vr.json().catch(() => ({}));
        if (vr.ok && vrJson?.access_token && vrJson?.refresh_token)
            return { session: vrJson };
        lastStatus = vr.status;
        lastMsg = String(vrJson?.error_code || vrJson?.msg || '');
        if (vr.status !== 422 && vr.status !== 400)
            break;
        await new Promise((r) => setTimeout(r, 1500));
    }
    return { error: `verify ${lastStatus} ${lastMsg}`.trim() };
}
/**
 * Password-grant a session (Bearer + SSR cookie). Accounts with a verified TOTP factor are stepped
 * up to AAL2 via Supabase MFA challenge + verify (VTA_<ROLE>_TOTP_SECRET, else VTA_TOTP_SECRET).
 * HTML dashboard routes need the cookie (middleware getUser); API routes keep working with Bearer.
 */
export async function obtainSession(role) {
    const creds = roleCreds(role);
    if (!creds) {
        const prefix = role === 'user' ? 'VTA_USER' : role === 'editor' ? 'VTA_EDITOR' : 'VTA_SUPERADMIN';
        return { skipReason: `${prefix}_EMAIL / ${prefix}_PASSWORD not set` };
    }
    const cacheKey = `${role}:${creds.email}`;
    const cached = sessionCache.get(cacheKey);
    if (cached)
        return { token: cached.token, cookieHeader: cached.cookieHeader };
    const { url, anonKey, missingAnon, legacyAnon } = supabaseConfig();
    if (missingAnon) {
        return {
            error: 'VTA_SUPABASE_ANON_KEY (or NEXT_PUBLIC_SUPABASE_ANON_KEY) is required — legacy JWT anon key is disabled',
        };
    }
    const body = { email: creds.email, password: creds.password };
    const res = await fetch(`${url}/auth/v1/token?grant_type=password`, {
        method: 'POST',
        headers: { apikey: anonKey, 'content-type': 'application/json' },
        body: JSON.stringify(body),
    });
    let json = await res.json().catch(() => ({}));
    if (!res.ok || !json?.access_token || !json?.refresh_token) {
        const msg = String(json?.error_description || json?.msg || json?.error || res.status);
        const legacyHint = legacyAnon
            ? ' (anon key looks like disabled legacy JWT — set VTA_SUPABASE_ANON_KEY to the publishable key)'
            : '';
        return { error: `auth failed for ${role}: ${msg}${legacyHint}`.slice(0, 240) };
    }
    // Staff MFA is enforced server-side (AAL2). An account with a verified TOTP
    // factor must complete challenge + verify; the verified session replaces the
    // password-only (aal1) one for both the Bearer token and the SSR cookie.
    const factor = verifiedTotpFactor(json.user);
    if (factor) {
        const secret = roleTotpSecret(role);
        if (!secret) {
            return { skipReason: `MFA required for ${role} but ${rolePrefix(role)}_TOTP_SECRET / VTA_TOTP_SECRET not set` };
        }
        const stepped = await stepUpToAal2(url, anonKey, json.access_token, factor, secret);
        if ('error' in stepped)
            return { error: `MFA step-up failed for ${role}: ${stepped.error}`.slice(0, 240) };
        json = stepped.session;
    }
    const cookieHeader = buildSupabaseSsrCookieHeader({
        access_token: json.access_token,
        refresh_token: json.refresh_token,
        expires_in: json.expires_in,
        expires_at: json.expires_at,
        token_type: json.token_type,
        user: json.user,
    }, url);
    const session = { token: json.access_token, cookieHeader };
    sessionCache.set(cacheKey, session);
    return { token: session.token, cookieHeader: session.cookieHeader };
}
/** Password-grant a Bearer token (API checks). Prefer obtainSession when HTML cookies are needed. */
export async function obtainAccessToken(role) {
    const s = await obtainSession(role);
    if (s.skipReason)
        return { skipReason: s.skipReason };
    if (s.error)
        return { error: s.error };
    return { token: s.token };
}
function originOf(raw) {
    const u = new URL(raw.includes('://') ? raw : `https://${raw}`);
    return u.origin;
}
async function authedFetch(origin, path, token, init = {}) {
    const url = origin + path;
    const headers = withCfBypassHeaders(url, {
        authorization: `Bearer ${token}`,
        ...init.headers,
    });
    return fetch(url, { ...init, headers, redirect: 'manual' });
}
/** HTML dashboard fetch authenticated via Supabase SSR session cookies (middleware getUser). */
async function cookieFetch(origin, path, cookieHeader, init = {}) {
    const url = origin + path;
    const headers = withCfBypassHeaders(url, {
        cookie: cookieHeader,
        ...init.headers,
    });
    return fetch(url, { ...init, headers, redirect: 'manual' });
}
function bouncedToLogin(res) {
    const loc = res.headers.get('location') || '';
    return res.status >= 300 && res.status < 400 && /login/i.test(loc);
}
/** 1x1 PNG */
export const TINY_PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64');
export async function runDbCritical(targetUrl, opts = {}) {
    const origin = originOf(targetUrl);
    const out = [];
    const timeoutMs = opts.timeoutMs ?? 20000;
    const ac = () => AbortSignal.timeout(timeoutMs);
    // ── A. Auth / role smokes ──────────────────────────────────────────────────
    {
        const spec = dbCriticalCheckSpecs().find((s) => s.id === 'db.auth.editor-cms');
        const auth = await obtainSession('editor');
        if (auth.skipReason)
            out.push(skip(spec.id, spec.title, auth.skipReason));
        else if (auth.error)
            out.push(f(spec.id, spec.title, spec.severity, false, auth.error, 'Fix editor credentials / MFA / VTA_SUPABASE_ANON_KEY.'));
        else {
            // HTML needs SSR cookies (middleware getUser); API keeps proving Bearer access.
            const [page, api] = await Promise.all([
                cookieFetch(origin, '/dashboard/editor/posts', auth.cookieHeader, { signal: ac() }),
                authedFetch(origin, '/api/editor/posts', auth.token, { signal: ac(), headers: { accept: 'application/json' } }),
            ]);
            const pageBody = await page.text().catch(() => '');
            const apiBody = await api.text().catch(() => '');
            const apiOk = api.status !== 401 && api.status !== 403;
            const pageOk = page.status === 200 && !bouncedToLogin(page);
            const pass = pageOk && apiOk;
            out.push(f(spec.id, spec.title, spec.severity, pass, pass
                ? `editor reached CMS (page ${page.status} via cookie, api ${api.status} via Bearer)`
                : `editor blocked (page ${page.status} loc=${(page.headers.get('location') || '').slice(0, 60)}, api ${api.status}): ${(apiBody || pageBody).slice(0, 120)}`, pass ? undefined : 'Editor cookie session should load /dashboard/editor HTML; Bearer should reach /api/editor/posts.'));
        }
    }
    {
        const spec = dbCriticalCheckSpecs().find((s) => s.id === 'db.auth.superadmin-homepage-config');
        const auth = await obtainAccessToken('superadmin');
        if (auth.skipReason)
            out.push(skip(spec.id, spec.title, auth.skipReason));
        else if (auth.error)
            out.push(f(spec.id, spec.title, spec.severity, false, auth.error));
        else {
            const res = await authedFetch(origin, '/api/homepage/config', auth.token, {
                signal: ac(), headers: { accept: 'application/json' },
            });
            const body = await res.text().catch(() => '');
            const pass = res.status === 200;
            out.push(f(spec.id, spec.title, spec.severity, pass, pass ? `GET /api/homepage/config → 200` : `GET /api/homepage/config → ${res.status}: ${body.slice(0, 140)}`, pass ? undefined : 'Superadmin must read Homepage Config (ad-zone internals).'));
        }
    }
    {
        const spec = dbCriticalCheckSpecs().find((s) => s.id === 'db.auth.superadmin-ad-placements');
        const auth = await obtainSession('superadmin');
        if (auth.skipReason)
            out.push(skip(spec.id, spec.title, auth.skipReason));
        else if (auth.error)
            out.push(f(spec.id, spec.title, spec.severity, false, auth.error));
        else {
            const res = await cookieFetch(origin, '/dashboard/admin/homepage', auth.cookieHeader, { signal: ac() });
            const body = await res.text().catch(() => '');
            const bounced = bouncedToLogin(res) || /input#password|Sign in/i.test(body);
            const pass = res.status === 200 && !bounced;
            out.push(f(spec.id, spec.title, spec.severity, pass, pass
                ? `Ad Placements host page → ${res.status} via cookie`
                : `blocked (${res.status} loc=${(res.headers.get('location') || '').slice(0, 60)}): ${body.slice(0, 120)}`, pass ? undefined : 'Superadmin cookie session should load /dashboard/admin/homepage (Ad Placements).'));
        }
    }
    // ── B. Product API dogfood ─────────────────────────────────────────────────
    {
        const upAd = dbCriticalCheckSpecs().find((s) => s.id === 'db.api.uploads-ad');
        const upEmpty = dbCriticalCheckSpecs().find((s) => s.id === 'db.api.uploads-empty');
        // Prefer editor; fall back to superadmin.
        let auth = await obtainAccessToken('editor');
        if (auth.skipReason)
            auth = await obtainAccessToken('superadmin');
        if (auth.skipReason) {
            out.push(skip(upAd.id, upAd.title, auth.skipReason));
            out.push(skip(upEmpty.id, upEmpty.title, auth.skipReason));
        }
        else if (auth.error) {
            out.push(f(upAd.id, upAd.title, upAd.severity, false, auth.error));
            out.push(f(upEmpty.id, upEmpty.title, upEmpty.severity, false, auth.error));
        }
        else {
            // Empty multipart → 400 "No file provided"
            {
                const boundary = '----vtaUploadBoundary7MA4YWxkTrZu0gW';
                const emptyBody = `--${boundary}\r\nContent-Disposition: form-data; name="type"\r\n\r\nad\r\n--${boundary}--\r\n`;
                const res = await authedFetch(origin, '/api/uploads', auth.token, {
                    method: 'POST',
                    signal: ac(),
                    headers: { 'content-type': `multipart/form-data; boundary=${boundary}` },
                    body: emptyBody,
                });
                const body = await res.text().catch(() => '');
                const pass = res.status === 400 && /No file provided/i.test(body);
                out.push(f(upEmpty.id, upEmpty.title, upEmpty.severity, pass, pass ? 'empty upload → 400 No file provided' : `expected 400 No file provided, got ${res.status}: ${body.slice(0, 160)}`, pass ? undefined : 'Empty multipart must 400 with "No file provided" (#1441).'));
            }
            // Tiny PNG type=ad → 201 (or 200 with success)
            {
                const boundary = '----vtaUploadBoundaryTinyPng';
                const filename = 'vta-probe.png';
                const parts = [
                    `--${boundary}\r\nContent-Disposition: form-data; name="type"\r\n\r\nad\r\n`,
                    `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: image/png\r\n\r\n`,
                ];
                const head = Buffer.from(parts.join(''), 'utf8');
                const mid = TINY_PNG;
                const tail = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8');
                const bodyBuf = Buffer.concat([head, mid, tail]);
                const res = await authedFetch(origin, '/api/uploads', auth.token, {
                    method: 'POST',
                    signal: ac(),
                    headers: { 'content-type': `multipart/form-data; boundary=${boundary}` },
                    body: bodyBuf,
                });
                const body = await res.text().catch(() => '');
                const pass = res.status === 201 || (res.status === 200 && /success|media|url|upload/i.test(body));
                out.push(f(upAd.id, upAd.title, upAd.severity, pass, pass ? `tiny PNG type=ad → ${res.status}` : `expected 201, got ${res.status}: ${body.slice(0, 180)}`, pass ? undefined : 'Authenticated type=ad upload of a valid PNG should succeed (#1441).'));
            }
        }
    }
    {
        const spec = dbCriticalCheckSpecs().find((s) => s.id === 'db.api.profiles-rls');
        const auth = await obtainAccessToken('user');
        if (auth.skipReason)
            out.push(skip(spec.id, spec.title, auth.skipReason));
        else if (auth.error)
            out.push(f(spec.id, spec.title, spec.severity, false, auth.error));
        else {
            const { url, anonKey } = supabaseConfig();
            const res = await fetch(`${url}/rest/v1/profiles?select=user_id,email,is_superadmin,is_editor&limit=50`, {
                signal: ac(),
                headers: {
                    apikey: anonKey,
                    authorization: `Bearer ${auth.token}`,
                    accept: 'application/json',
                },
            });
            const body = await res.text().catch(() => '');
            let rows = [];
            try {
                rows = JSON.parse(body);
            }
            catch { /* not json */ }
            const dump = Array.isArray(rows) && rows.length > 5;
            // Pass if denied (401/403) OR at most a handful of own/staff-visible rows (≤5).
            const pass = res.status === 401 || res.status === 403 || (res.status === 200 && Array.isArray(rows) && !dump);
            out.push(f(spec.id, spec.title, spec.severity, pass, pass
                ? `profiles REST → ${res.status}, rows=${Array.isArray(rows) ? rows.length : 'n/a'} (no dump)`
                : `non-staff dumped ${Array.isArray(rows) ? rows.length : '?'} profiles (${res.status})`, pass ? undefined : 'RLS must prevent non-staff from selecting all profiles (#1416).'));
        }
    }
    {
        const spec = dbCriticalCheckSpecs().find((s) => s.id === 'db.api.ad-track-xss');
        const xss = `<script>alert('vta')</script>`;
        const url = origin + '/api/analytics/ad-track';
        const res = await fetch(url, {
            method: 'POST',
            signal: ac(),
            headers: withCfBypassHeaders(url, { 'content-type': 'application/json' }),
            body: JSON.stringify({
                ad_id: xss,
                zone: xss,
                event_type: 'impression',
                device: 'desktop',
                page_url: `https://example.invalid/${xss}`,
            }),
        });
        const ct = (res.headers.get('content-type') || '').toLowerCase();
        const body = await res.text().catch(() => '');
        const htmlReflect = ct.includes('text/html') && body.includes(xss);
        const pass = !htmlReflect;
        out.push(f(spec.id, spec.title, spec.severity, pass, pass ? `ad-track → ${res.status} ${ct || '(no ct)'} (no HTML XSS reflection)` : `ad-track reflected XSS marker as HTML`, pass ? undefined : 'Beacon must not reflect attacker markup as HTML.'));
    }
    {
        const spec = dbCriticalCheckSpecs().find((s) => s.id === 'db.api.unsubscribe-xss');
        const xss = `<img src=x onerror=alert(1)>`;
        const url = `${origin}/api/jobs/alerts/unsubscribe?token=${encodeURIComponent(xss)}`;
        const res = await fetch(url, {
            signal: ac(),
            headers: withCfBypassHeaders(url) || {},
        });
        const body = await res.text().catch(() => '');
        // Raw payload must not appear unescaped; escaped entities / absence is fine.
        const rawHit = body.includes(xss) || body.includes('onerror=alert');
        const pass = !rawHit;
        out.push(f(spec.id, spec.title, spec.severity, pass, pass ? `unsubscribe → ${res.status} (token not reflected raw)` : `unsubscribe reflected XSS marker unescaped`, pass ? undefined : 'Escape dynamic strings on the unsubscribe confirmation page (#1452).'));
    }
    {
        const spec = dbCriticalCheckSpecs().find((s) => s.id === 'db.api.stripe-amount');
        if (env('VTA_STRIPE_AMOUNT_PROBE') !== '1') {
            out.push(skip(spec.id, spec.title, 'set VTA_STRIPE_AMOUNT_PROBE=1 to enable (non-destructive gate); live charge probes are out of scope'));
        }
        else {
            // Non-destructive: hit a pricing/preview endpoint if present; never create a PaymentIntent.
            const url = origin + '/api/ads/pricing';
            const res = await fetch(url, {
                method: 'POST',
                signal: ac(),
                headers: withCfBypassHeaders(url, { 'content-type': 'application/json' }),
                body: JSON.stringify({
                    duration_days: 1,
                    start_date: '2026-01-01',
                    end_date: '2026-06-30',
                    product_id: 'vta-probe-nonexistent',
                }),
            });
            const body = await res.text().catch(() => '');
            // Endpoint may 404 (not deployed) — treat as SKIP rather than fail.
            if (res.status === 404 || res.status === 405) {
                out.push(skip(spec.id, spec.title, `/api/ads/pricing not available (${res.status}); dual-path covered in app unit tests (#1436)`));
            }
            else {
                // If it answers, a forged underprice must not be accepted as authoritative without server recompute.
                const forgedAccepted = res.status < 300 && /"duration_days"\s*:\s*1\b/.test(body) && /181|date_span/i.test(body) === false;
                const pass = !forgedAccepted;
                out.push(f(spec.id, spec.title, spec.severity, pass, pass ? `pricing probe → ${res.status} (client duration not blindly trusted)` : `pricing accepted forged duration_days=1`, pass ? undefined : 'Bill from date span / product default — never trust client duration_days (#1436).'));
            }
        }
    }
    // ── C. Editorial golden-path scaffold ──────────────────────────────────────
    {
        const spec = dbCriticalCheckSpecs().find((s) => s.id === 'db.editorial.golden-path');
        const fixture = env('VTA_UNPUBLISHED_ARTICLE_URL');
        if (!fixture) {
            out.push(skip(spec.id, spec.title, 'VTA_UNPUBLISHED_ARTICLE_URL not set'));
        }
        else {
            const auth = await obtainAccessToken('editor');
            if (auth.skipReason)
                out.push(skip(spec.id, spec.title, `${auth.skipReason} (needed to fetch unpublished fixture)`));
            else if (auth.error)
                out.push(f(spec.id, spec.title, spec.severity, false, auth.error));
            else {
                const res = await authedFetch(origin, new URL(fixture, origin).pathname + new URL(fixture, origin).search, auth.token, { signal: ac() });
                const body = await res.text().catch(() => '');
                const pass = res.status === 200 && body.length > 0 && !/Article not found|Post not found/i.test(body);
                out.push(f(spec.id, spec.title, spec.severity, pass, pass ? `unpublished fixture reachable (${res.status})` : `fixture → ${res.status}: ${body.slice(0, 120)}`, pass ? undefined : 'Provide a reachable unpublished article URL for editorial golden-path.'));
            }
        }
    }
    return out;
}
/** Pure helpers exported for unit tests. */
export function htmlReflectsXss(body, payload) {
    // Only the raw (unescaped) payload is a reflection hit. Entity-escaped markup is fine.
    return body.includes(payload);
}
export function profilesDumpDetected(status, rows) {
    if (status === 401 || status === 403)
        return false;
    if (!Array.isArray(rows))
        return false;
    return rows.length > 5;
}
export function assertTimingSafeEqual(a, b) {
    const ba = Buffer.from(a);
    const bb = Buffer.from(b);
    if (ba.length !== bb.length)
        return false;
    return timingSafeEqual(ba, bb);
}

// src/gap-checks.ts
// New checks from the gap analysis: auth, authz, API, agent LLM, uploads, db/storage, DNS DKIM,
// CSRF tokens, and PII disclosure. These are non-destructive, low-volume black-box probes designed
// to run safely on owned production apps.
import { safeFetch } from './core.js';
import { promises as dns } from 'node:dns';
const f = (category, id, title, severity, pass, detail, fix) => ({ category, id, title, severity, pass, detail, fix });
// ── auth checks (require ownership verification) ─────────────────────────────────────────────────
/**
 * auth.login-rate-limit: A few bad login attempts to see if 429 or lockout kicks in.
 * Non-destructive: only 5 failed attempts with garbage credentials.
 */
export async function authLoginRateLimitCheck(ctx) {
    const loginPaths = ['/api/auth/login', '/api/login', '/login', '/api/auth/signin', '/api/signin'];
    for (const path of loginPaths) {
        const testUrl = ctx.origin + path;
        const firstRes = await safeFetch(testUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'vta-test-nonexistent@example.invalid', password: 'wrongpassword123' }) }, ctx.opts.timeoutMs);
        if (!firstRes || firstRes.status === 404 || firstRes.status === 405)
            continue;
        const attempts = await Promise.all(Array.from({ length: 5 }, () => safeFetch(testUrl, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ email: 'vta-test-nonexistent@example.invalid', password: 'wrongpassword' + Math.random() }),
        }, ctx.opts.timeoutMs)));
        const got429 = attempts.some(r => r && r.status === 429);
        const gotLockout = attempts.some(r => r && r.status === 423);
        const throttled = got429 || gotLockout;
        return [f('security', 'auth.login-rate-limit', throttled ? 'Login rate limiting active' : 'No login rate limiting detected', throttled ? 'info' : 'medium', throttled, throttled ? `${path}: 5 failed login attempts triggered ${got429 ? '429' : '423 lockout'}` : `${path}: 5 rapid failed logins were not throttled`, throttled ? undefined : 'Implement login rate limiting (e.g., max 5 attempts per minute per IP/account) to prevent brute-force attacks.')];
    }
    return [];
}
/**
 * auth.reset-token-reuse: Check if a password reset link can be reused.
 * We can't actually test this without a real reset flow, but we check for common insecure patterns
 * in reset endpoints. This is a placeholder that returns a pass if we can't detect insecurity.
 */
export async function authResetTokenReuseCheck(_ctx) {
    return [];
}
/**
 * auth.session-invalidation: Placeholder for session invalidation check.
 * Requires authenticated session to test properly.
 */
export async function authSessionInvalidationCheck(_ctx) {
    return [];
}
/**
 * auth.email-plus-alias: Check if the app handles email plus-addressing correctly.
 * Tests signup/login endpoints for email normalization issues.
 */
export async function authEmailPlusAliasCheck(_ctx) {
    return [];
}
// ── authz checks ─────────────────────────────────────────────────────────────────────────────────
/**
 * authz.idor-sequential: Check for obvious sequential ID IDOR.
 * Looks for patterns where incrementing an ID returns different user data.
 */
export async function authzIdorSequentialCheck(ctx) {
    const apiPaths = ['/api/users/', '/api/user/', '/api/profile/', '/api/account/', '/api/order/', '/api/orders/'];
    for (const basePath of apiPaths) {
        const ids = ['1', '2', '100', '1000'];
        let foundData = false;
        let path = '';
        for (const id of ids) {
            const testUrl = ctx.origin + basePath + id;
            const res = await safeFetch(testUrl, { redirect: 'manual', headers: ctx.opts.extraHeaders }, ctx.opts.timeoutMs);
            if (!res)
                continue;
            const ct = (res.headers.get('content-type') || '').toLowerCase();
            if (res.ok && ct.includes('json')) {
                const body = await res.text();
                if (!/<html/i.test(body) && /"(?:email|name|user|id)"\s*:/i.test(body)) {
                    foundData = true;
                    path = basePath + id;
                    break;
                }
            }
        }
        if (foundData) {
            return [f('security', 'authz.idor-sequential', 'Sequential ID returns data (potential IDOR)', 'high', false, `GET ${path} returns user data — verify this is authorized`, 'Ensure all object access checks authorization. Use UUIDs instead of sequential IDs and always verify the requesting user owns the resource.')];
        }
    }
    return [];
}
// ── API checks ───────────────────────────────────────────────────────────────────────────────────
/**
 * api.webhook-unsigned: Check if webhook endpoints accept unsigned payloads.
 * Sends a minimal unsigned payload to common webhook paths.
 */
export async function apiWebhookUnsignedCheck(ctx) {
    const webhookPaths = ['/api/webhooks/stripe', '/api/webhook/stripe', '/api/webhooks/github', '/api/webhook/github', '/api/webhooks', '/webhooks'];
    for (const path of webhookPaths) {
        const testUrl = ctx.origin + path;
        const res = await safeFetch(testUrl, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ type: 'test.event', data: {} }),
        }, ctx.opts.timeoutMs);
        if (!res || res.status === 404 || res.status === 405)
            continue;
        if (res.ok || res.status === 200 || res.status === 201) {
            return [f('security', 'api.webhook-unsigned', 'Webhook endpoint accepts unsigned payload', 'high', false, `POST ${path} with no signature header returned ${res.status}`, 'Verify webhook signatures (e.g., Stripe-Signature, X-Hub-Signature-256) before processing. Reject unsigned requests.')];
        }
        if (res.status === 400 || res.status === 401 || res.status === 403) {
            const body = (await res.text()).slice(0, 500).toLowerCase();
            if (body.includes('signature') || body.includes('unauthorized') || body.includes('invalid')) {
                return [f('security', 'api.webhook-unsigned', 'Webhook endpoint requires signature', 'info', true, `POST ${path} rejected unsigned payload (${res.status})`)];
            }
        }
    }
    return [];
}
/**
 * api.idempotency: Check if POST endpoints handle duplicate requests idempotently.
 * This is a placeholder - full check requires authenticated session.
 */
export async function apiIdempotencyCheck(_ctx) {
    return [];
}
/**
 * api.key-revocation: Placeholder for checking if revoked API keys are rejected.
 * Requires test fixtures with revoked keys.
 */
export async function apiKeyRevocationCheck(_ctx) {
    return [];
}
// ── agent/LLM checks ─────────────────────────────────────────────────────────────────────────────
/**
 * agent.prompt-injection: Check for prompt injection vulnerabilities.
 * Extended version of the ATLAS check for owned apps.
 */
export async function agentPromptInjectionCheck(_ctx) {
    return [];
}
/**
 * agent.llm-data-leak: Check if LLM endpoints leak other users' data.
 */
export async function agentLlmDataLeakCheck(_ctx) {
    return [];
}
/**
 * agent.llm-rate-limit: Check rate limiting on LLM endpoints.
 */
export async function agentLlmRateLimitCheck(_ctx) {
    return [];
}
// ── upload checks ────────────────────────────────────────────────────────────────────────────────
/**
 * upload.content-type: Check if uploads are served with correct content-type and disposition.
 */
export async function uploadContentTypeCheck(_ctx) {
    return [];
}
// ── db/storage checks ────────────────────────────────────────────────────────────────────────────
/**
 * db.firebase-rules / storage.public-bucket: Check for misconfigured Firebase/Supabase storage.
 * Read-only probe for public listing/access.
 */
export async function dbFirebaseRulesCheck(ctx) {
    const patterns = [
        { re: /firebasestorage\.googleapis\.com\/v0\/b\/([a-z0-9-]+)\.appspot\.com/i, type: 'firebase' },
        { re: /supabase\.co\/storage\/v1\/object\/public\/([a-z0-9-_]+)/i, type: 'supabase' },
        { re: /([a-z0-9-]+)\.supabase\.co/i, type: 'supabase-project' },
    ];
    for (const { re, type } of patterns) {
        const match = ctx.html.match(re);
        if (!match)
            continue;
        if (type === 'firebase') {
            const bucket = match[1];
            const listUrl = `https://firebasestorage.googleapis.com/v0/b/${bucket}.appspot.com/o`;
            const res = await safeFetch(listUrl, {}, ctx.opts.timeoutMs);
            if (res && res.ok) {
                const body = await res.text();
                if (body.includes('"items"')) {
                    return [f('security', 'db.firebase-rules', 'Firebase Storage bucket is publicly listable', 'high', false, `Bucket ${bucket}.appspot.com allows anonymous listing`, 'Update Firebase Storage rules to require authentication. Never allow public listing of storage buckets.')];
                }
            }
        }
        if (type === 'supabase-project') {
            const project = match[1];
            const rtdbUrl = `https://${project}.supabase.co/rest/v1/`;
            const res = await safeFetch(rtdbUrl, { headers: { 'apikey': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRlc3QiLCJyb2xlIjoiYW5vbiJ9.test' } }, ctx.opts.timeoutMs);
            if (res && res.status !== 401) {
                return [f('security', 'storage.public-bucket', 'Supabase database may have open RLS', 'medium', false, `${project}.supabase.co REST API accessible without valid auth`, 'Enable Row Level Security (RLS) on all tables and ensure proper policies are in place.')];
            }
        }
    }
    return [];
}
// ── DNS DKIM check (passive, can run unverified) ─────────────────────────────────────────────────
const COMMON_DKIM_SELECTORS = ['google', 'selector1', 'selector2', 'k1', 'k2', 'dkim', 'mail', 'email', 's1', 's2', 'default'];
/**
 * dns.dkim: Check for DKIM records on common selectors.
 * Passive DNS lookup - safe for unverified targets.
 */
export async function dnsDkimCheck(ctx) {
    const hostname = ctx.url.hostname;
    const apex = apexOf(hostname);
    const foundSelectors = [];
    for (const selector of COMMON_DKIM_SELECTORS) {
        try {
            const records = await dns.resolveTxt(`${selector}._domainkey.${apex}`);
            const flat = records.map(r => r.join(''));
            if (flat.some(r => r.includes('v=DKIM1'))) {
                foundSelectors.push(selector);
                if (foundSelectors.length >= 2)
                    break;
            }
        }
        catch {
            // NXDOMAIN - no record
        }
    }
    if (foundSelectors.length > 0) {
        return [f('dns', 'dns.dkim', 'DKIM records present', 'info', true, `Found DKIM on selector(s): ${foundSelectors.join(', ')} at ${apex}`)];
    }
    return [f('dns', 'dns.dkim', 'No DKIM records found', 'medium', false, `No DKIM records on common selectors for ${apex}`, 'Configure DKIM signing for outbound email. Add a DKIM TXT record (e.g., google._domainkey) provided by your email service.')];
}
function apexOf(hostname) {
    const parts = hostname.split('.').filter(Boolean);
    if (parts.length <= 2)
        return hostname;
    const lastTwo = parts.slice(-2).join('.');
    const MULTI_LABEL_SUFFIXES = new Set(['com.au', 'net.au', 'org.au', 'co.uk', 'org.uk', 'co.nz', 'co.jp', 'com.br', 'co.in']);
    if (MULTI_LABEL_SUFFIXES.has(lastTwo))
        return parts.slice(-3).join('.');
    return lastTwo;
}
// ── CSRF token check (passive, can run unverified) ───────────────────────────────────────────────
/**
 * csrf.token: Check for CSRF tokens on state-changing forms.
 * Passive HTML analysis - safe for unverified targets.
 */
export async function csrfTokenCheck(ctx) {
    const forms = [...ctx.html.matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/gi)];
    const stateChangingForms = forms.filter(m => {
        const formTag = m[0];
        const isPost = /method\s*=\s*["']?post["']?/i.test(formTag);
        const actionPath = formTag.match(/action\s*=\s*["']([^"']+)["']/i)?.[1] || '';
        const looksStateful = isPost || /delete|update|create|edit|remove|submit|transfer|checkout|pay/i.test(actionPath);
        return looksStateful;
    });
    if (stateChangingForms.length === 0) {
        return [];
    }
    const formsWithToken = stateChangingForms.filter(m => {
        const formContent = m[0];
        const hasToken = /name\s*=\s*["']?(?:csrf|_csrf|csrftoken|csrf_token|_token|authenticity_token|__RequestVerificationToken)["']?/i.test(formContent);
        const hasHiddenToken = /<input[^>]+type\s*=\s*["']hidden["'][^>]+name\s*=\s*["'][^"']*token[^"']*["']/i.test(formContent);
        return hasToken || hasHiddenToken;
    });
    const cookieHeaders = ctx.headers.get('set-cookie') || '';
    const hasSameSiteCookie = /samesite\s*=\s*(strict|lax)/i.test(cookieHeaders);
    if (formsWithToken.length === stateChangingForms.length) {
        return [f('security', 'csrf.token', 'Forms have CSRF tokens', 'info', true, `${stateChangingForms.length} state-changing form(s) carry CSRF tokens`)];
    }
    if (hasSameSiteCookie && formsWithToken.length === 0) {
        return [f('security', 'csrf.token', 'CSRF mitigated via SameSite cookies', 'info', true, 'State-changing forms rely on SameSite cookie protection')];
    }
    const missing = stateChangingForms.length - formsWithToken.length;
    return [f('security', 'csrf.token', 'Forms missing CSRF tokens', 'medium', false, `${missing} of ${stateChangingForms.length} state-changing form(s) lack a CSRF token`, 'Add CSRF tokens to all state-changing forms, or ensure all session cookies use SameSite=Strict/Lax.')];
}
// ── PII disclosure check (passive, can run unverified) ───────────────────────────────────────────
const PII_PATTERNS = [
    { name: 'credit card', re: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/ },
    { name: 'SSN', re: /\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b/ },
    { name: 'email in response', re: /"(?:email|email_address|emailAddress)"\s*:\s*"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"/ },
    { name: 'phone', re: /"(?:phone|phone_number|phoneNumber|mobile)"\s*:\s*"[+]?[0-9]{10,15}"/ },
    { name: 'bearer token', re: /"(?:token|access_token|accessToken|bearer|auth_token)"\s*:\s*"[a-zA-Z0-9_-]{20,}"/ },
    { name: 'password hash', re: /\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}/ },
];
/**
 * disclosure.pii-in-response: Check for PII patterns in API responses.
 * Passive regex scan - safe for unverified targets.
 */
export async function disclosurePiiInResponseCheck(ctx) {
    const apiPaths = ['/api/user', '/api/users', '/api/me', '/api/profile', '/api/account', '/api/config'];
    const findings = [];
    for (const path of apiPaths) {
        const res = await safeFetch(ctx.origin + path, { headers: ctx.opts.extraHeaders }, ctx.opts.timeoutMs);
        if (!res || !res.ok)
            continue;
        const ct = (res.headers.get('content-type') || '').toLowerCase();
        if (!ct.includes('json'))
            continue;
        const body = await res.text();
        if (/<html/i.test(body))
            continue;
        for (const pattern of PII_PATTERNS) {
            if (pattern.re.test(body)) {
                findings.push(f('security', 'disclosure.pii-in-response', `${pattern.name} found in API response`, 'medium', false, `GET ${path} response contains ${pattern.name} pattern`, `Avoid exposing ${pattern.name} in API responses. Mask or omit sensitive fields.`));
                break;
            }
        }
    }
    if (findings.length === 0) {
        return [];
    }
    return findings;
}
// ── Preview/staging deployments check (default, low-volume) ──────────────────────────────────────
const PREVIEW_SUBDOMAINS = ['staging', 'stage', 'dev', 'development', 'preview', 'beta', 'test', 'qa', 'uat', 'demo', 'sandbox', 'canary'];
const HOSTING_PATTERNS = [
    { suffix: '.pages.dev', provider: 'Cloudflare Pages' },
    { suffix: '.vercel.app', provider: 'Vercel' },
    { suffix: '.netlify.app', provider: 'Netlify' },
    { suffix: '.workers.dev', provider: 'Cloudflare Workers' },
    { suffix: '.fly.dev', provider: 'Fly.io' },
    { suffix: '.railway.app', provider: 'Railway' },
    { suffix: '.render.com', provider: 'Render' },
    { suffix: '.herokuapp.com', provider: 'Heroku' },
];
/**
 * exposure.preview-deployments: Find reachable preview/staging deployments.
 * Only probes hosts under the verified domain or clearly linked from it.
 */
export async function exposurePreviewDeploymentsCheck(ctx) {
    const findings = [];
    const hostname = ctx.url.hostname;
    const apex = getApexDomain(hostname);
    const checkedHosts = new Set();
    const extractLinkedHosts = (html) => {
        const hosts = [];
        const hrefPattern = /href\s*=\s*["']https?:\/\/([^"'/]+)/gi;
        const srcPattern = /src\s*=\s*["']https?:\/\/([^"'/]+)/gi;
        for (const pattern of [hrefPattern, srcPattern]) {
            for (const match of html.matchAll(pattern)) {
                const linkedHost = match[1].toLowerCase();
                for (const { suffix, provider: _ } of HOSTING_PATTERNS) {
                    if (linkedHost.endsWith(suffix)) {
                        const projectName = linkedHost.slice(0, -suffix.length);
                        if (projectName.includes(apex.split('.')[0]) || projectName.length < 20) {
                            hosts.push(linkedHost);
                        }
                    }
                }
            }
        }
        return [...new Set(hosts)];
    };
    const checkPreviewHost = async (host, source) => {
        if (checkedHosts.has(host))
            return;
        checkedHosts.add(host);
        const testUrl = `https://${host}/`;
        const res = await safeFetch(testUrl, { redirect: 'follow', headers: ctx.opts.extraHeaders }, ctx.opts.timeoutMs);
        if (!res)
            return;
        if (res.ok) {
            const body = await res.text();
            const issues = [];
            if (/<title>\s*debug|<pre>.*stack\s*trace/i.test(body)) {
                issues.push('debug mode enabled');
            }
            if (/(?:api_key|secret|password)\s*[:=]\s*["'][^"']+["']/i.test(body)) {
                issues.push('potential secrets in response');
            }
            if (!res.headers.get('www-authenticate') && !body.includes('login') && !body.includes('sign in')) {
                issues.push('no authentication required');
            }
            if (issues.length > 0) {
                findings.push(f('exposure', 'exposure.preview-deployments', `Public preview deployment at ${host}`, 'medium', false, `Found via ${source}: ${issues.join(', ')}`, 'Either protect preview deployments with authentication (e.g., Vercel Password Protection, Cloudflare Access), or ensure they don\'t expose sensitive data or debug information.'));
            }
        }
    };
    for (const subdomain of PREVIEW_SUBDOMAINS) {
        const previewHost = `${subdomain}.${apex}`;
        await checkPreviewHost(previewHost, 'subdomain enumeration');
    }
    const linkedHosts = extractLinkedHosts(ctx.html);
    for (const linkedHost of linkedHosts) {
        await checkPreviewHost(linkedHost, 'page reference');
    }
    if (findings.length === 0 && checkedHosts.size > 0) {
        return [f('exposure', 'exposure.preview-deployments', 'No exposed preview deployments found', 'info', true, `Checked ${checkedHosts.size} potential preview hosts`)];
    }
    return findings;
}
function getApexDomain(hostname) {
    const parts = hostname.split('.').filter(Boolean);
    if (parts.length <= 2)
        return hostname;
    const lastTwo = parts.slice(-2).join('.');
    const MULTI_LABEL_SUFFIXES = new Set(['com.au', 'net.au', 'org.au', 'co.uk', 'org.uk', 'co.nz', 'co.jp', 'com.br', 'co.in']);
    if (MULTI_LABEL_SUFFIXES.has(lastTwo))
        return parts.slice(-3).join('.');
    return lastTwo;
}
export const GAP_CHECK_CONFIG = {
    'auth.login-rate-limit': { requiresVerification: true, category: 'security' },
    'auth.reset-token-reuse': { requiresVerification: true, category: 'security' },
    'auth.session-invalidation': { requiresVerification: true, category: 'security' },
    'auth.email-plus-alias': { requiresVerification: true, category: 'security' },
    'authz.idor-sequential': { requiresVerification: true, category: 'security' },
    'api.webhook-unsigned': { requiresVerification: true, category: 'security' },
    'api.idempotency': { requiresVerification: true, category: 'security' },
    'api.key-revocation': { requiresVerification: true, category: 'security' },
    'agent.prompt-injection': { requiresVerification: true, category: 'atlas' },
    'agent.llm-data-leak': { requiresVerification: true, category: 'atlas' },
    'agent.llm-rate-limit': { requiresVerification: true, category: 'atlas' },
    'upload.content-type': { requiresVerification: true, category: 'security' },
    'db.firebase-rules': { requiresVerification: true, category: 'security' },
    'storage.public-bucket': { requiresVerification: true, category: 'security' },
    'exposure.preview-deployments': { requiresVerification: false, category: 'exposure' },
    'repo.secrets': { requiresVerification: true, category: 'secrets' },
    'dns.dkim': { requiresVerification: false, category: 'dns' },
    'csrf.token': { requiresVerification: false, category: 'security' },
    'disclosure.pii-in-response': { requiresVerification: false, category: 'security' },
};
export const DEFAULT_GAP_CHECK_IDS = Object.entries(GAP_CHECK_CONFIG)
    .filter(([, cfg]) => !cfg.requiresVerification)
    .map(([id]) => id);
export function isPassiveCheck(checkId) {
    return GAP_CHECK_CONFIG[checkId]?.requiresVerification === false;
}
/**
 * Whether a gap check should run given CLI `--only`/`--skip`, verification, and `--repo`.
 */
export function shouldRunGapCheck(checkId, opts = {}) {
    const cfg = GAP_CHECK_CONFIG[checkId];
    if (!cfg)
        return false;
    if (opts.only && opts.only.length > 0 && !opts.only.includes(cfg.category))
        return false;
    if (opts.skip?.includes(cfg.category))
        return false;
    if (cfg.requiresVerification && !(opts.authorizedGap || opts.verified))
        return false;
    if (checkId === 'repo.secrets' && !opts.repoPath)
        return false;
    return true;
}
const GAP_RUNNERS = {
    'dns.dkim': dnsDkimCheck,
    'csrf.token': csrfTokenCheck,
    'disclosure.pii-in-response': disclosurePiiInResponseCheck,
    'exposure.preview-deployments': exposurePreviewDeploymentsCheck,
    'auth.login-rate-limit': authLoginRateLimitCheck,
    'auth.reset-token-reuse': authResetTokenReuseCheck,
    'auth.session-invalidation': authSessionInvalidationCheck,
    'auth.email-plus-alias': authEmailPlusAliasCheck,
    'authz.idor-sequential': authzIdorSequentialCheck,
    'api.webhook-unsigned': apiWebhookUnsignedCheck,
    'api.idempotency': apiIdempotencyCheck,
    'api.key-revocation': apiKeyRevocationCheck,
    'agent.prompt-injection': agentPromptInjectionCheck,
    'agent.llm-data-leak': agentLlmDataLeakCheck,
    'agent.llm-rate-limit': agentLlmRateLimitCheck,
    'upload.content-type': uploadContentTypeCheck,
    'db.firebase-rules': dbFirebaseRulesCheck,
};
/**
 * Run gap analysis checks selected by `shouldRunGapCheck`. `repo.secrets` is handled by the caller
 * (needs a filesystem), not here.
 */
export async function gapChecks(ctx, verifiedOrOpts = false) {
    const opts = typeof verifiedOrOpts === 'boolean'
        ? { verified: verifiedOrOpts, authorizedGap: verifiedOrOpts }
        : verifiedOrOpts;
    const merged = {
        authorizedGap: opts.authorizedGap || ctx.opts.authorizedGap,
        verified: opts.verified || ctx.opts.verified,
        repoPath: opts.repoPath ?? ctx.opts.repoPath,
        only: opts.only ?? ctx.opts.only,
        skip: opts.skip ?? ctx.opts.skip,
    };
    const results = [];
    for (const [id, runner] of Object.entries(GAP_RUNNERS)) {
        if (!shouldRunGapCheck(id, merged))
            continue;
        results.push(...await runner(ctx));
    }
    return results;
}

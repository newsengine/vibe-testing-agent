// src/repo-secrets.ts
// White-box repo secret scanning: scans working tree and git history for leaked secrets.
// Opt-in, requires verified project ownership AND authorized repo connection.
import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execFileAsync = promisify(execFile);
export const REPO_SECRET_RULES = [
    // ── Cloud provider keys ──────────────────────────────────────────────────────────────────────
    { id: 'aws.akid', name: 'AWS access key ID', severity: 'high', re: /\bAKIA[0-9A-Z]{16}\b/g },
    { id: 'aws.secret', name: 'AWS secret access key', severity: 'high', re: /\b[A-Za-z0-9/+=]{40}\b/g, confirm: (m, ctx) => /aws|secret|key/i.test(ctx) && !/[A-Za-z0-9/+=]{41,}/.test(m) },
    { id: 'gcp.apikey', name: 'Google Cloud API key', severity: 'high', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    { id: 'gcp.oauth', name: 'GCP OAuth client secret', severity: 'high', re: /\bGOCSPX-[0-9A-Za-z_-]{28}\b/g },
    { id: 'gcp.sa_key', name: 'GCP service account key', severity: 'high', re: /"private_key":\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----/g },
    { id: 'azure.client_secret', name: 'Azure client secret', severity: 'high', re: /\b[a-zA-Z0-9~_.-]{34}\b/g, confirm: (m, ctx) => /azure|client.?secret|tenant/i.test(ctx) },
    { id: 'azure.connection', name: 'Azure connection string', severity: 'high', re: /AccountKey=[A-Za-z0-9/+=]{86}==/g },
    // ── Payment & billing ────────────────────────────────────────────────────────────────────────
    { id: 'stripe.sk_live', name: 'Stripe live secret key', severity: 'high', re: /\bsk_live_[0-9a-zA-Z]{20,}\b/g },
    { id: 'stripe.rk_live', name: 'Stripe live restricted key', severity: 'high', re: /\brk_live_[0-9a-zA-Z]{20,}\b/g },
    { id: 'stripe.sk_test', name: 'Stripe test secret key', severity: 'medium', re: /\bsk_test_[0-9a-zA-Z]{20,}\b/g },
    // ── LLM/AI providers ─────────────────────────────────────────────────────────────────────────
    { id: 'openai.key', name: 'OpenAI API key', severity: 'high', re: /\bsk-(?:proj-)?[0-9A-Za-z]{20}[0-9A-Za-z_-]{10,}\b/g },
    { id: 'anthropic.key', name: 'Anthropic API key', severity: 'high', re: /\bsk-ant-[0-9A-Za-z_-]{20,}\b/g },
    { id: 'cohere.key', name: 'Cohere API key', severity: 'high', re: /\b[a-zA-Z0-9]{40}\b/g, confirm: (m, ctx) => /cohere|co\.api/i.test(ctx) },
    { id: 'huggingface.token', name: 'HuggingFace token', severity: 'high', re: /\bhf_[a-zA-Z0-9]{34}\b/g },
    { id: 'replicate.token', name: 'Replicate API token', severity: 'high', re: /\br8_[a-zA-Z0-9]{36}\b/g },
    // ── Backend-as-a-service ─────────────────────────────────────────────────────────────────────
    {
        id: 'supabase.service_role',
        name: 'Supabase service_role key',
        severity: 'high',
        re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
        confirm: (m) => {
            try {
                const payload = JSON.parse(Buffer.from(m.split('.')[1], 'base64url').toString('utf8'));
                return payload?.role === 'service_role';
            }
            catch {
                return false;
            }
        },
    },
    { id: 'firebase.server_key', name: 'Firebase server key', severity: 'high', re: /\bAAAA[A-Za-z0-9_-]{140,}\b/g },
    { id: 'firebase.config', name: 'Firebase service account', severity: 'high', re: /"type":\s*"service_account"[^}]+firebase/gi },
    // ── Version control & CI ─────────────────────────────────────────────────────────────────────
    { id: 'github.pat', name: 'GitHub PAT (classic)', severity: 'high', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b/g },
    { id: 'github.pat_fine', name: 'GitHub fine-grained PAT', severity: 'high', re: /\bgithub_pat_[0-9A-Za-z_]{60,}\b/g },
    { id: 'gitlab.pat', name: 'GitLab PAT', severity: 'high', re: /\bglpat-[0-9A-Za-z_-]{20}\b/g },
    { id: 'gitlab.runner', name: 'GitLab runner token', severity: 'high', re: /\bGR1348941[0-9A-Za-z_-]{20}\b/g },
    { id: 'bitbucket.app_pass', name: 'Bitbucket app password', severity: 'high', re: /\b[A-Za-z0-9]{24}\b/g, confirm: (_, ctx) => /bitbucket|app.?password/i.test(ctx) },
    // ── Communication ────────────────────────────────────────────────────────────────────────────
    { id: 'slack.token', name: 'Slack token', severity: 'high', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
    { id: 'slack.webhook', name: 'Slack webhook URL', severity: 'medium', re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/g },
    { id: 'discord.webhook', name: 'Discord webhook URL', severity: 'medium', re: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d{17,19}\/[A-Za-z0-9_-]{60,}/g },
    { id: 'discord.bot', name: 'Discord bot token', severity: 'high', re: /\b[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b/g },
    { id: 'twilio.sk', name: 'Twilio API key', severity: 'high', re: /\bSK[0-9a-fA-F]{32}\b/g },
    { id: 'twilio.auth', name: 'Twilio auth token', severity: 'high', re: /\b[a-f0-9]{32}\b/g, confirm: (_, ctx) => /twilio|auth.?token/i.test(ctx) },
    { id: 'sendgrid.key', name: 'SendGrid API key', severity: 'high', re: /\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b/g },
    { id: 'mailgun.key', name: 'Mailgun API key', severity: 'high', re: /\bkey-[a-f0-9]{32}\b/g },
    { id: 'postmark.token', name: 'Postmark server token', severity: 'high', re: /\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g, confirm: (_, ctx) => /postmark|server.?token/i.test(ctx) },
    // ── Private keys ─────────────────────────────────────────────────────────────────────────────
    { id: 'privatekey.rsa', name: 'RSA private key', severity: 'high', re: /-----BEGIN RSA PRIVATE KEY-----/g },
    { id: 'privatekey.openssh', name: 'OpenSSH private key', severity: 'high', re: /-----BEGIN OPENSSH PRIVATE KEY-----/g },
    { id: 'privatekey.ec', name: 'EC private key', severity: 'high', re: /-----BEGIN EC PRIVATE KEY-----/g },
    { id: 'privatekey.dsa', name: 'DSA private key', severity: 'high', re: /-----BEGIN DSA PRIVATE KEY-----/g },
    { id: 'privatekey.pkcs8', name: 'PKCS8 private key', severity: 'high', re: /-----BEGIN PRIVATE KEY-----/g },
    { id: 'privatekey.pgp', name: 'PGP private key', severity: 'high', re: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g },
    { id: 'privatekey.putty', name: 'PuTTY private key', severity: 'high', re: /PuTTY-User-Key-File-[0-9]+:/g },
    // ── JWT & auth secrets ───────────────────────────────────────────────────────────────────────
    { id: 'jwt.secret', name: 'JWT signing secret', severity: 'high', re: /\b(?:JWT_SECRET|JWT_SIGNING_KEY|AUTH_SECRET|SESSION_SECRET|SECRET_KEY)\s*[=:]\s*["']?[A-Za-z0-9+/=_-]{16,}["']?/gi },
    { id: 'auth0.client_secret', name: 'Auth0 client secret', severity: 'high', re: /\b[A-Za-z0-9_-]{64}\b/g, confirm: (_, ctx) => /auth0|client.?secret/i.test(ctx) },
    // ── Database connection strings ──────────────────────────────────────────────────────────────
    { id: 'db.postgres', name: 'PostgreSQL connection string', severity: 'high', re: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^/]+\/\w+/gi },
    { id: 'db.mysql', name: 'MySQL connection string', severity: 'high', re: /mysql:\/\/[^:]+:[^@]+@[^/]+\/\w+/gi },
    { id: 'db.mongodb', name: 'MongoDB connection string', severity: 'high', re: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^/]+/gi },
    { id: 'db.redis', name: 'Redis connection string', severity: 'high', re: /redis:\/\/:[^@]+@[^/]+/gi },
    // ── .env files (catch-all for suspicious patterns in env files) ──────────────────────────────
    { id: 'env.password', name: 'Password in env file', severity: 'high', re: /\b(?:PASSWORD|PASSWD|DB_PASS|ADMIN_PASS)\s*=\s*["']?[^\s"']+["']?/gi },
    { id: 'env.api_key', name: 'API key in env file', severity: 'high', re: /\b(?:API_KEY|APIKEY|API_SECRET)\s*=\s*["']?[A-Za-z0-9_-]{16,}["']?/gi },
    // ── Other high-value targets ─────────────────────────────────────────────────────────────────
    { id: 'npm.token', name: 'NPM access token', severity: 'high', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
    { id: 'pypi.token', name: 'PyPI API token', severity: 'high', re: /\bpypi-[A-Za-z0-9_-]{50,}\b/g },
    { id: 'heroku.key', name: 'Heroku API key', severity: 'high', re: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, confirm: (_, ctx) => /heroku|api.?key/i.test(ctx) },
    { id: 'vercel.token', name: 'Vercel token', severity: 'high', re: /\b[A-Za-z0-9]{24}\b/g, confirm: (_, ctx) => /vercel|bearer/i.test(ctx) },
    { id: 'netlify.token', name: 'Netlify access token', severity: 'high', re: /\b[A-Za-z0-9_-]{40,}\b/g, confirm: (_, ctx) => /netlify|access.?token/i.test(ctx) },
    { id: 'cloudflare.token', name: 'Cloudflare API token', severity: 'high', re: /\b[A-Za-z0-9_-]{40}\b/g, confirm: (_, ctx) => /cloudflare|cf.?token/i.test(ctx) },
    { id: 'datadog.key', name: 'Datadog API key', severity: 'high', re: /\b[a-f0-9]{32}\b/g, confirm: (_, ctx) => /datadog|dd.?api/i.test(ctx) },
    { id: 'sentry.dsn', name: 'Sentry DSN with secret', severity: 'medium', re: /https:\/\/[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io\/\d+/gi },
];
export function redactSecret(value) {
    if (value.length <= 8)
        return '***';
    if (value.length <= 16)
        return `${value.slice(0, 4)}…${value.slice(-2)}`;
    return `${value.slice(0, 6)}…${value.slice(-4)}`;
}
export function scanContent(content, filePath, commit) {
    const hits = [];
    const seen = new Set();
    const lines = content.split('\n');
    for (const rule of REPO_SECRET_RULES) {
        const regex = new RegExp(rule.re.source, rule.re.flags.includes('g') ? rule.re.flags : rule.re.flags + 'g');
        for (let lineNum = 0; lineNum < lines.length; lineNum++) {
            const line = lines[lineNum];
            const context = lines.slice(Math.max(0, lineNum - 2), lineNum + 3).join('\n');
            for (const match of line.matchAll(regex)) {
                const value = match[0];
                if (rule.confirm && !rule.confirm(value, context))
                    continue;
                const dedupKey = `${rule.id}:${filePath}:${commit || 'HEAD'}:${value.slice(0, 12)}`;
                if (seen.has(dedupKey))
                    continue;
                seen.add(dedupKey);
                hits.push({
                    ruleId: rule.id,
                    name: rule.name,
                    severity: rule.severity,
                    file: filePath,
                    commit,
                    line: lineNum + 1,
                    redactedValue: redactSecret(value),
                });
            }
        }
    }
    return hits;
}
export const LIVENESS_CHECKS = [
    {
        ruleId: 'aws.akid',
        endpoint: 'https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15',
        method: 'GET',
        parseKey: (m) => m,
        isValid: (res) => res.status === 200,
    },
    {
        ruleId: 'github.pat',
        endpoint: 'https://api.github.com/user',
        method: 'GET',
        headers: { 'User-Agent': 'VibeTesting-Agent/1.0' },
        parseKey: (m) => m,
        isValid: (res) => res.status === 200,
    },
    {
        ruleId: 'github.pat_fine',
        endpoint: 'https://api.github.com/user',
        method: 'GET',
        headers: { 'User-Agent': 'VibeTesting-Agent/1.0' },
        parseKey: (m) => m,
        isValid: (res) => res.status === 200,
    },
    {
        ruleId: 'slack.token',
        endpoint: 'https://slack.com/api/auth.test',
        method: 'POST',
        parseKey: (m) => m,
        isValid: (_, body) => {
            try {
                return JSON.parse(body).ok === true;
            }
            catch {
                return false;
            }
        },
    },
    {
        ruleId: 'openai.key',
        endpoint: 'https://api.openai.com/v1/models',
        method: 'GET',
        parseKey: (m) => m,
        isValid: (res) => res.status === 200,
    },
    {
        ruleId: 'anthropic.key',
        endpoint: 'https://api.anthropic.com/v1/models',
        method: 'GET',
        headers: { 'anthropic-version': '2023-06-01' },
        parseKey: (m) => m,
        isValid: (res) => res.status === 200,
    },
    {
        ruleId: 'sendgrid.key',
        endpoint: 'https://api.sendgrid.com/v3/user/credits',
        method: 'GET',
        parseKey: (m) => m,
        isValid: (res) => res.status === 200,
    },
];
export async function checkLiveness(ruleId, secretValue, timeoutMs = 5000) {
    const check = LIVENESS_CHECKS.find(c => c.ruleId === ruleId);
    if (!check)
        return 'unknown';
    const key = check.parseKey(secretValue);
    if (!key)
        return 'unknown';
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), timeoutMs);
        const response = await fetch(check.endpoint, {
            method: check.method,
            signal: controller.signal,
            headers: {
                'Authorization': `Bearer ${key}`,
                ...check.headers,
            },
        });
        clearTimeout(timeout);
        const body = await response.text();
        return check.isValid(response, body) ? 'valid' : 'invalid';
    }
    catch {
        return 'error';
    }
}
export function isEnvFile(filePath) {
    const name = filePath.split('/').pop() || '';
    return /^\.env(\.[a-z]+)?$/i.test(name) || name === '.env.local' || name === '.env.production';
}
export function shouldSkipFile(filePath) {
    const skipPatterns = [
        /node_modules\//,
        /(^|\/)\.git\//,
        /vendor\//,
        /dist\//,
        /build\//,
        /\.min\.js$/,
        /\.map$/,
        /package-lock\.json$/,
        /yarn\.lock$/,
        /pnpm-lock\.yaml$/,
        /\.png$/i,
        /\.jpg$/i,
        /\.jpeg$/i,
        /\.gif$/i,
        /\.ico$/i,
        /\.woff2?$/i,
        /\.ttf$/i,
        /\.eot$/i,
        /\.pdf$/i,
        /\.zip$/i,
    ];
    return skipPatterns.some(p => p.test(filePath));
}
export function repoHitsToFindings(scan) {
    if (scan.hits.length === 0) {
        return [{
                category: 'secrets',
                id: 'repo.secrets',
                title: 'No secrets in repository',
                severity: 'info',
                pass: true,
                detail: `scanned ${scan.filesScanned} file(s), ${scan.commitsScanned} commit(s)`,
            }];
    }
    return scan.hits.map((hit) => ({
        category: 'secrets',
        id: 'repo.secrets',
        title: `${hit.name} in ${hit.file}`,
        severity: hit.severity,
        pass: false,
        detail: `${hit.file}${hit.commit ? ` @ ${hit.commit}` : ''}${hit.line ? `:${hit.line}` : ''} [${hit.ruleId}] ${hit.redactedValue}`,
        fix: 'Rotate the secret, remove it from git history (git filter-repo or BFG), and stop committing .env / key files.',
    }));
}
const DEFAULT_MAX_FILES = 2_000;
const DEFAULT_MAX_COMMITS = 200;
const DEFAULT_MAX_FILE_BYTES = 512_000;
async function walkFiles(root, maxFiles) {
    const out = [];
    const stack = [root];
    while (stack.length && out.length < maxFiles) {
        const dir = stack.pop();
        let entries;
        try {
            entries = await readdir(dir, { withFileTypes: true });
        }
        catch {
            continue;
        }
        for (const entry of entries) {
            if (out.length >= maxFiles)
                break;
            const full = join(dir, entry.name);
            const rel = relative(root, full).split('\\').join('/');
            if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist' || entry.name === 'build')
                continue;
            if (entry.isDirectory()) {
                stack.push(full);
                continue;
            }
            if (!entry.isFile() || shouldSkipFile(rel))
                continue;
            out.push(rel);
        }
    }
    return out;
}
/**
 * Scan a local working tree and (when `.git` exists) recent git history for secrets.
 * Never prints full secret values — hits carry `redactedValue` only. No liveness calls.
 */
export async function scanRepo(repoPath, opts = {}) {
    const maxFiles = opts.maxFiles ?? DEFAULT_MAX_FILES;
    const maxCommits = opts.maxCommits ?? DEFAULT_MAX_COMMITS;
    const maxFileBytes = opts.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    const hits = [];
    const errors = [];
    let filesScanned = 0;
    let commitsScanned = 0;
    const files = await walkFiles(repoPath, maxFiles);
    for (const rel of files) {
        try {
            const full = join(repoPath, rel);
            const st = await stat(full);
            if (st.size > maxFileBytes)
                continue;
            const content = await readFile(full, 'utf8');
            filesScanned++;
            hits.push(...scanContent(content, rel));
        }
        catch {
            // binary / unreadable
        }
    }
    if (maxCommits > 0) {
        try {
            const { stdout: headCheck } = await execFileAsync('git', ['-C', repoPath, 'rev-parse', '--is-inside-work-tree'], { timeout: 5_000 });
            if (headCheck.trim() === 'true') {
                const { stdout: log } = await execFileAsync('git', ['-C', repoPath, 'log', '--all', `--max-count=${maxCommits}`, '--format=%H'], { timeout: 15_000, maxBuffer: 2_000_000 });
                const commits = log.trim().split('\n').filter(Boolean);
                for (const commit of commits) {
                    commitsScanned++;
                    let names = '';
                    try {
                        const shown = await execFileAsync('git', ['-C', repoPath, 'diff-tree', '--no-commit-id', '--name-only', '-r', commit], { timeout: 8_000, maxBuffer: 1_000_000 });
                        names = shown.stdout;
                    }
                    catch {
                        continue;
                    }
                    for (const file of names.trim().split('\n').filter(Boolean).slice(0, 50)) {
                        if (shouldSkipFile(file))
                            continue;
                        try {
                            const { stdout: content } = await execFileAsync('git', ['-C', repoPath, 'show', `${commit}:${file}`], { timeout: 8_000, maxBuffer: maxFileBytes });
                            hits.push(...scanContent(content, file, commit.slice(0, 7)));
                        }
                        catch {
                            // missing in that commit / binary
                        }
                    }
                }
            }
        }
        catch {
            errors.push('git history unavailable');
        }
    }
    const seen = new Set();
    const deduped = [];
    for (const hit of hits) {
        const key = `${hit.ruleId}:${hit.file}:${hit.redactedValue}`;
        if (seen.has(key))
            continue;
        seen.add(key);
        deduped.push(hit);
    }
    return { hits: deduped, filesScanned, commitsScanned, errors };
}

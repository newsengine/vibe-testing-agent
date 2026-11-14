// src/plugins.ts
// A Nuclei-style plugin/template engine so contributors can add checks WITHOUT touching core — but the
// template format is JSON (parsed with the built-in JSON.parse; NEVER a YAML or any other runtime dep,
// zero-dep is absolute). Each template declaratively describes ONE black-box, NON-DESTRUCTIVE probe:
// a single GET/HEAD request plus a set of matchers over the status/headers/body. A match → a failing
// Finding in the `plugins` category. The matching logic is split into pure functions (validateTemplate /
// evaluateTemplate) so it unit-tests without the network, mirroring dns.ts / agent.ts.
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { safeFetch } from './core.js';
const f = (id, title, severity, pass, detail, fix) => ({ category: 'plugins', id, title, severity, pass, detail, fix });
const SEVERITIES = ['high', 'medium', 'low', 'info'];
const MATCHER_TYPES = ['status', 'header', 'body-regex', 'body-contains'];
const ALLOWED_METHODS = ['GET', 'HEAD'];
// Caps: a plugin dir can't blow up the scan. At most this many templates load, one request each.
export const MAX_TEMPLATES = 100;
const MAX_BODY_BYTES = 2_000_000;
// ───────────────────────────── validation (pure) ─────────────────────────────
/**
 * A plugin path must stay on the scan origin, since the request carries the scan's auth headers.
 * "//host/x" and "/\host/x" are protocol-relative, and URL parsing strips tab/newline, so "/<TAB>/host"
 * would collapse to "//host" too.
 */
export function isSameOriginPath(p) {
    if (!p.startsWith('/') || p.startsWith('//') || p.startsWith('/\\'))
        return false;
    // eslint-disable-next-line no-control-regex
    return !/[\s\u0000-\u001f\u007f]/.test(p);
}
const isStr = (v) => typeof v === 'string';
const nonEmpty = (v) => isStr(v) && v.trim().length > 0;
/** Validate an untrusted parsed-JSON object against the template schema. Never throws. */
export function validateTemplate(obj) {
    const errors = [];
    if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
        return { ok: false, errors: ['template must be a JSON object'] };
    }
    const t = obj;
    if (!nonEmpty(t.id))
        errors.push('`id` is required (non-empty string)');
    if (!nonEmpty(t.title))
        errors.push('`title` is required (non-empty string)');
    if (!isStr(t.severity) || !SEVERITIES.includes(t.severity)) {
        errors.push(`\`severity\` must be one of ${SEVERITIES.join('|')}`);
    }
    // request
    const req = t.request;
    if (typeof req !== 'object' || req === null || Array.isArray(req)) {
        errors.push('`request` must be an object with a `path`');
    }
    else {
        if (!nonEmpty(req.path) || !req.path.startsWith('/')) {
            errors.push('`request.path` is required and must start with "/"');
        }
        else if (!isSameOriginPath(req.path)) {
            errors.push('`request.path` must be a same-origin path (no "//", "/\\", whitespace or control characters)');
        }
        if (req.method !== undefined && (!isStr(req.method) || !ALLOWED_METHODS.includes(req.method.toUpperCase()))) {
            errors.push('`request.method` must be GET or HEAD (only non-destructive methods are allowed)');
        }
        if (req.headers !== undefined && (typeof req.headers !== 'object' || req.headers === null || Array.isArray(req.headers))) {
            errors.push('`request.headers` must be an object of string values');
        }
    }
    // matchers-condition
    if (t['matchers-condition'] !== undefined && t['matchers-condition'] !== 'and' && t['matchers-condition'] !== 'or') {
        errors.push('`matchers-condition` must be "and" or "or"');
    }
    // matchers
    if (!Array.isArray(t.matchers) || t.matchers.length === 0) {
        errors.push('`matchers` must be a non-empty array');
    }
    else {
        t.matchers.forEach((mRaw, i) => {
            const where = `matchers[${i}]`;
            if (typeof mRaw !== 'object' || mRaw === null || Array.isArray(mRaw)) {
                errors.push(`${where} must be an object`);
                return;
            }
            const m = mRaw;
            if (!isStr(m.type) || !MATCHER_TYPES.includes(m.type)) {
                errors.push(`${where}.type must be one of ${MATCHER_TYPES.join('|')}`);
                return;
            }
            switch (m.type) {
                case 'status': {
                    const ok = typeof m.status === 'number'
                        || (Array.isArray(m.status) && m.status.length > 0 && m.status.every((s) => typeof s === 'number'));
                    if (!ok)
                        errors.push(`${where}.status must be a number or a non-empty number[]`);
                    break;
                }
                case 'header': {
                    if (!nonEmpty(m.name))
                        errors.push(`${where}.name is required for a header matcher`);
                    if (m.regex !== undefined && !validRegex(m.regex, m.flags))
                        errors.push(`${where}.regex is not a valid regular expression`);
                    if (m.contains !== undefined && !isStr(m.contains))
                        errors.push(`${where}.contains must be a string`);
                    if (m.equals !== undefined && !isStr(m.equals))
                        errors.push(`${where}.equals must be a string`);
                    break;
                }
                case 'body-regex': {
                    if (!nonEmpty(m.regex))
                        errors.push(`${where}.regex is required for a body-regex matcher`);
                    else if (!validRegex(m.regex, m.flags))
                        errors.push(`${where}.regex is not a valid regular expression`);
                    break;
                }
                case 'body-contains': {
                    if (!nonEmpty(m.contains))
                        errors.push(`${where}.contains is required for a body-contains matcher`);
                    break;
                }
            }
        });
    }
    return { ok: errors.length === 0, errors };
}
function validRegex(source, flags) {
    if (!isStr(source))
        return false;
    try {
        new RegExp(source, sanitizeFlags(flags));
        return true;
    }
    catch {
        return false;
    }
}
// Drop 'g'/'y' so a matcher's .test() is stateless (lastIndex can't carry between calls).
function sanitizeFlags(flags) {
    return isStr(flags) ? flags.replace(/[gy]/g, '') : '';
}
// ───────────────────────────── evaluation (pure) ─────────────────────────────
function readHeader(headers, name) {
    if (headers instanceof Headers)
        return headers.get(name);
    const lower = name.toLowerCase();
    for (const k of Object.keys(headers))
        if (k.toLowerCase() === lower)
            return headers[k];
    return null;
}
/** Evaluate ONE matcher against a response view. Pure; never throws. */
export function evaluateMatcher(m, res) {
    let hit = false;
    try {
        switch (m.type) {
            case 'status': {
                const codes = Array.isArray(m.status) ? m.status : [m.status];
                hit = codes.includes(res.status);
                break;
            }
            case 'header': {
                const val = readHeader(res.headers, m.name ?? '');
                if (val === null) {
                    hit = false;
                    break;
                }
                // Present with no further constraint → matched; else all provided constraints must hold.
                let ok = true;
                if (m.equals !== undefined)
                    ok = ok && val.toLowerCase() === m.equals.toLowerCase();
                if (m.contains !== undefined)
                    ok = ok && val.includes(m.contains);
                if (m.regex !== undefined)
                    ok = ok && new RegExp(m.regex, sanitizeFlags(m.flags)).test(val);
                hit = ok;
                break;
            }
            case 'body-regex': {
                hit = new RegExp(m.regex ?? '', sanitizeFlags(m.flags)).test(res.body);
                break;
            }
            case 'body-contains': {
                hit = res.body.includes(m.contains ?? '');
                break;
            }
        }
    }
    catch {
        hit = false;
    }
    return m.negative ? !hit : hit;
}
/** Evaluate a whole template against a response view. Returns true when the template MATCHES (i.e. fails
 *  the target). Combines matchers with `matchers-condition` (default "and"). Pure; never throws. */
export function evaluateTemplate(template, res) {
    const matchers = Array.isArray(template.matchers) ? template.matchers : [];
    if (matchers.length === 0)
        return false;
    const results = matchers.map((m) => evaluateMatcher(m, res));
    const cond = template['matchers-condition'] === 'or' ? 'or' : 'and';
    return cond === 'or' ? results.some(Boolean) : results.every(Boolean);
}
// ───────────────────────────── loading + running (I/O) ─────────────────────────────
const DEFAULT_DIR = './vibetesting-agent-plugins';
async function loadTemplates(dir) {
    let entries;
    try {
        entries = (await fs.readdir(dir)).filter((n) => n.toLowerCase().endsWith('.json')).sort();
    }
    catch {
        return { loaded: [], invalid: [], found: false };
    }
    const loaded = [];
    const invalid = [];
    for (const name of entries.slice(0, MAX_TEMPLATES)) {
        const file = path.join(dir, name);
        let parsed;
        try {
            parsed = JSON.parse(await fs.readFile(file, 'utf8'));
        }
        catch (e) {
            invalid.push({ file: name, errors: [`invalid JSON: ${String(e?.message || e)}`] });
            continue;
        }
        const v = validateTemplate(parsed);
        if (!v.ok) {
            invalid.push({ file: name, errors: v.errors });
            continue;
        }
        loaded.push({ file: name, template: parsed });
    }
    return { loaded, invalid, found: true };
}
/**
 * `plugins` category runner. Loads user JSON templates from `ctx.opts.pluginsDir` (default
 * ./vibetesting-agent-plugins), runs each as one GET/HEAD, and emits a failing Finding per matched template.
 * A malformed template can never break the run: bad files are skipped with an info finding. Emits a
 * `plugins.loaded` info-pass summarizing how many ran, or `plugins.none` when the dir is absent/empty.
 */
export async function pluginChecks(ctx) {
    const dir = ctx.opts.pluginsDir || DEFAULT_DIR;
    const { loaded, invalid, found } = await loadTemplates(dir);
    const out = [];
    // Surface bad templates (non-fatal) so the author knows why they didn't run.
    for (const bad of invalid) {
        out.push(f(`plugins.invalid.${bad.file}`, `Plugin template skipped: ${bad.file}`, 'info', true, `${bad.file} failed schema validation and was ignored: ${bad.errors.join('; ')}`, 'Fix the template JSON to match the schema (see plugins/README.md).'));
    }
    if (!found || loaded.length === 0) {
        out.push(f('plugins.none', 'No custom plugins loaded', 'info', true, found ? `no valid .json templates in ${dir}` : `plugins directory ${dir} not present`, `Drop JSON templates in ${dir} (or pass --plugins <dir>) to add custom checks — see plugins/README.md.`));
        return out;
    }
    for (const { template } of loaded) {
        const method = (template.request.method || 'GET').toUpperCase();
        const target = new URL(template.request.path, ctx.origin);
        if (target.origin !== ctx.origin) {
            out.push(f(`plugins.invalid.${template.id}`, `Plugin template skipped: ${template.id}`, 'info', true, `request.path resolves off the scan origin (${target.origin})`, 'Use a same-origin path such as "/admin".'));
            continue;
        }
        const url = target.toString();
        // Same-origin request: safe to carry the scan's auth headers, plus any the template specifies.
        const headers = { ...(ctx.opts.extraHeaders || {}), ...(template.request.headers || {}) };
        const res = await safeFetch(url, { method, headers }, ctx.opts.timeoutMs);
        if (!res)
            continue; // unreachable path → treat as no match, don't emit noise
        let body = '';
        if (method !== 'HEAD') {
            try {
                body = (await res.text()).slice(0, MAX_BODY_BYTES);
            }
            catch {
                body = '';
            }
        }
        const view = { status: res.status, headers: res.headers, body };
        if (evaluateTemplate(template, view)) {
            const tags = [
                template.owasp ? `OWASP ${template.owasp}` : null,
                template.cwe && template.cwe.length ? template.cwe.join(', ') : null,
            ].filter(Boolean).join(' · ');
            const detail = `matched ${method} ${template.request.path} (HTTP ${res.status})${tags ? ` [${tags}]` : ''}`;
            out.push(f(`plugins.${template.id}`, template.title, template.severity, false, detail, template.fix));
        }
    }
    out.push(f('plugins.loaded', `Ran ${loaded.length} custom plugin(s)`, 'info', true, `${loaded.length} template(s) from ${dir}${invalid.length ? ` (${invalid.length} skipped)` : ''}`));
    return out;
}

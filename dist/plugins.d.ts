import type { Finding, ScanContext, Severity } from './types.js';
export type MatcherType = 'status' | 'header' | 'body-regex' | 'body-contains';
export interface Matcher {
    type: MatcherType;
    /** status: one code or a list of accepted codes. */
    status?: number | number[];
    /** header: the header name to inspect (case-insensitive). */
    name?: string;
    /** header/body-regex: a JS regexp source. */
    regex?: string;
    /** regexp flags (e.g. "i"); 'g' is ignored to keep .test() stateless. */
    flags?: string;
    /** header/body-contains: a case-sensitive substring. */
    contains?: string;
    /** header: exact (case-insensitive) value match. */
    equals?: string;
    /** invert this single matcher (e.g. "header is ABSENT"). */
    negative?: boolean;
    /** tolerated per-matcher hint; the authoritative combiner is the template's matchers-condition. */
    condition?: 'and' | 'or';
}
export interface PluginTemplate {
    id: string;
    title: string;
    severity: Severity;
    request: {
        path: string;
        method?: 'GET' | 'HEAD';
        headers?: Record<string, string>;
    };
    matchers: Matcher[];
    /** how to combine matchers; default "and". */
    'matchers-condition'?: 'and' | 'or';
    fix?: string;
    /** metadata echoed into the finding detail (OWASP Top 10 id + CWE ids). */
    owasp?: string;
    cwe?: string[];
}
export interface ResponseView {
    status: number;
    /** Headers object or a plain (ideally lowercased) map. */
    headers: Headers | Record<string, string>;
    body: string;
}
export declare const MAX_TEMPLATES = 100;
/**
 * A plugin path must stay on the scan origin, since the request carries the scan's auth headers.
 * "//host/x" and "/\host/x" are protocol-relative, and URL parsing strips tab/newline, so "/<TAB>/host"
 * would collapse to "//host" too.
 */
export declare function isSameOriginPath(p: string): boolean;
/** Validate an untrusted parsed-JSON object against the template schema. Never throws. */
export declare function validateTemplate(obj: unknown): {
    ok: boolean;
    errors: string[];
};
/** Evaluate ONE matcher against a response view. Pure; never throws. */
export declare function evaluateMatcher(m: Matcher, res: ResponseView): boolean;
/** Evaluate a whole template against a response view. Returns true when the template MATCHES (i.e. fails
 *  the target). Combines matchers with `matchers-condition` (default "and"). Pure; never throws. */
export declare function evaluateTemplate(template: PluginTemplate, res: ResponseView): boolean;
/**
 * `plugins` category runner. Loads user JSON templates from `ctx.opts.pluginsDir` (default
 * ./vibetesting-agent-plugins), runs each as one GET/HEAD, and emits a failing Finding per matched template.
 * A malformed template can never break the run: bad files are skipped with an info finding. Emits a
 * `plugins.loaded` info-pass summarizing how many ran, or `plugins.none` when the dir is absent/empty.
 */
export declare function pluginChecks(ctx: ScanContext): Promise<Finding[]>;

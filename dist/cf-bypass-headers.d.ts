/**
 * Cloudflare bot-exception headers for probes against your own origins.
 *
 * Host gates (never attach secrets to third-party origins). Both allowlists are
 * empty by default, so nothing is sent until you name your hosts:
 * - `x-smoke-key` from `CF_SMOKE_KEY` | `X_SMOKE_KEY` (legacy: `SMOKE_KEY`) only
 *   when the request host matches `VTA_SMOKE_KEY_HOSTS`.
 * - Cloudflare Access service-token headers from `CF_ACCESS_CLIENT_ID` +
 *   `CF_ACCESS_CLIENT_SECRET` only when the host matches `VTA_CF_ACCESS_HOSTS`.
 *
 * Allowlist syntax: comma- or space-separated hostnames. `example.com` matches
 * that exact host; `*.example.com` matches any subdomain (not the apex).
 *
 * For HTTP/fetch callers: use `cfBypassHeaders(url)` / `withCfBypassHeaders` per URL.
 * For Playwright browsers: use `installCfBypassRoute(context)`. Never put these
 * secrets on context-global `extraHTTPHeaders` (leaks to every origin).
 *
 * Secrets must come from env / CI secrets. Never hardcode them.
 */
/** Parse a comma/space separated host allowlist (lower-cased, empty entries dropped). */
export declare function parseHostAllowlist(raw?: string): string[];
/** True when `host` is listed exactly, or is a subdomain of a `*.domain` entry. */
export declare function hostMatchesAllowlist(host: string, allowlist: string[]): boolean;
/** Hosts (from `VTA_SMOKE_KEY_HOSTS`) that may receive `x-smoke-key`. */
export declare function isSmokeKeyHost(host: string): boolean;
/** Hosts (from `VTA_CF_ACCESS_HOSTS`) that may receive Cloudflare Access service-token headers. */
export declare function isCfAccessHost(host: string): boolean;
/** Build CF bypass headers when the matching env vars are set for `targetUrl`. */
export declare function cfBypassHeaders(targetUrl?: string): Record<string, string>;
/** Merge env-derived CF bypass headers under explicit headers (explicit wins). */
export declare function withCfBypassHeaders(targetUrl: string | undefined, explicit?: Record<string, string>): Record<string, string> | undefined;
type RouteLike = {
    request: () => {
        url: () => string;
        headers: () => Record<string, string>;
    };
    continue: (options?: {
        headers?: Record<string, string>;
    }) => Promise<void>;
};
type ContextLike = {
    route: (url: string, handler: (route: RouteLike) => Promise<void>) => Promise<void>;
};
/**
 * Playwright BrowserContext route: inject CF bypass headers only when the
 * request URL hostname matches the smoke / Access gates. Third-party
 * subrequests never receive secrets.
 */
export declare function installCfBypassRoute(context: ContextLike): Promise<void>;
export {};

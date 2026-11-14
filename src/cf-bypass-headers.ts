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

function hostnameOf(raw?: string): string {
  if (!raw) return '';
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
    return new URL(withScheme).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/** Parse a comma/space separated host allowlist (lower-cased, empty entries dropped). */
export function parseHostAllowlist(raw?: string): string[] {
  return (raw || '')
    .split(/[\s,]+/)
    .map((h) => h.trim().toLowerCase().replace(/\.$/, ''))
    .filter(Boolean);
}

/** True when `host` is listed exactly, or is a subdomain of a `*.domain` entry. */
export function hostMatchesAllowlist(host: string, allowlist: string[]): boolean {
  const h = (host || '').toLowerCase().replace(/\.$/, '');
  if (!h) return false;
  return allowlist.some((entry) => {
    if (entry.startsWith('*.')) {
      const base = entry.slice(2);
      return Boolean(base) && h.endsWith(`.${base}`);
    }
    return h === entry;
  });
}

/** Hosts (from `VTA_SMOKE_KEY_HOSTS`) that may receive `x-smoke-key`. */
export function isSmokeKeyHost(host: string): boolean {
  return hostMatchesAllowlist(host, parseHostAllowlist(process.env.VTA_SMOKE_KEY_HOSTS));
}

/** Hosts (from `VTA_CF_ACCESS_HOSTS`) that may receive Cloudflare Access service-token headers. */
export function isCfAccessHost(host: string): boolean {
  return hostMatchesAllowlist(host, parseHostAllowlist(process.env.VTA_CF_ACCESS_HOSTS));
}

/** Build CF bypass headers when the matching env vars are set for `targetUrl`. */
export function cfBypassHeaders(targetUrl?: string): Record<string, string> {
  const headers: Record<string, string> = {};
  const host = hostnameOf(targetUrl);
  if (!host) return headers;

  const smoke = process.env.CF_SMOKE_KEY || process.env.X_SMOKE_KEY || process.env.SMOKE_KEY;
  if (smoke && isSmokeKeyHost(host)) headers['x-smoke-key'] = smoke;

  if (isCfAccessHost(host)) {
    const id = process.env.CF_ACCESS_CLIENT_ID;
    const secret = process.env.CF_ACCESS_CLIENT_SECRET;
    if (id) headers['CF-Access-Client-Id'] = id;
    if (secret) headers['CF-Access-Client-Secret'] = secret;
  }

  return headers;
}

/** Merge env-derived CF bypass headers under explicit headers (explicit wins). */
export function withCfBypassHeaders(
  targetUrl: string | undefined,
  explicit?: Record<string, string>,
): Record<string, string> | undefined {
  const merged = { ...cfBypassHeaders(targetUrl), ...(explicit || {}) };
  return Object.keys(merged).length ? merged : undefined;
}

type RouteLike = {
  request: () => { url: () => string; headers: () => Record<string, string> };
  continue: (options?: { headers?: Record<string, string> }) => Promise<void>;
};

type ContextLike = {
  route: (
    url: string,
    handler: (route: RouteLike) => Promise<void>,
  ) => Promise<void>;
};

/**
 * Playwright BrowserContext route: inject CF bypass headers only when the
 * request URL hostname matches the smoke / Access gates. Third-party
 * subrequests never receive secrets.
 */
export async function installCfBypassRoute(context: ContextLike): Promise<void> {
  await context.route('**/*', async (route) => {
    const req = route.request();
    const bypass = cfBypassHeaders(req.url());
    if (!Object.keys(bypass).length) {
      await route.continue();
      return;
    }
    await route.continue({
      headers: {
        ...req.headers(),
        ...bypass,
      },
    });
  });
}

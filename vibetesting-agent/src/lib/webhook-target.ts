/**
 * Bind deploy / GitHub webhooks to the verified project's exact hostname.
 * Reject mismatches instead of falling back to project.url — a fallback would
 * quietly scan production and report a false pass for an untested preview.
 */

export type WebhookTargetCode =
  | 'host_mismatch'
  | 'invalid_url'
  | 'insecure_url'
  | 'userinfo'
  | 'port';

export type WebhookTargetResult =
  | { ok: true; url: string; hostname: string }
  | { ok: false; error: string; code: WebhookTargetCode };

/** Fail closed: unset NODE_ENV (Cloudflare Workers) is not treated as dev. */
function isDevOrTest(): boolean {
  const env = process.env.VTA_ENV || process.env.NODE_ENV;
  return env === 'development' || env === 'test';
}

function hasScheme(raw: string): boolean {
  return /^[a-z][a-z0-9+.-]*:/i.test(raw);
}

function isLocalhost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
}

function isDefaultPort(url: URL): boolean {
  if (!url.port) return true;
  if (url.protocol === 'https:' && url.port === '443') return true;
  if (url.protocol === 'http:' && url.port === '80') return true;
  return false;
}

function parseUrl(raw: string): URL | null {
  const withScheme = hasScheme(raw) ? raw : `https://${raw}`;
  try {
    return new URL(withScheme);
  } catch {
    return null;
  }
}

export function resolveWebhookTarget(
  project: { url: string },
  candidateUrl?: string | null,
): WebhookTargetResult {
  const projectUrl = parseUrl(typeof project.url === 'string' ? project.url.trim() : '');
  if (!projectUrl?.hostname) {
    return { ok: false, error: 'Project URL is invalid', code: 'invalid_url' };
  }
  const expectedHost = projectUrl.hostname.toLowerCase();

  const trimmed = typeof candidateUrl === 'string' ? candidateUrl.trim() : '';
  const raw = trimmed || project.url;
  const url = parseUrl(raw);
  if (!url) {
    return { ok: false, error: 'Invalid webhook target URL', code: 'invalid_url' };
  }

  if (url.username || url.password) {
    return { ok: false, error: 'Webhook target must not include credentials', code: 'userinfo' };
  }

  const hostname = url.hostname.toLowerCase();
  if (!hostname) {
    return { ok: false, error: 'Invalid webhook target URL', code: 'invalid_url' };
  }

  const allowHttpLocal = isDevOrTest() && isLocalhost(hostname);
  const httpsOk = url.protocol === 'https:';
  const httpLocalOk = url.protocol === 'http:' && allowHttpLocal;
  if (!httpsOk && !httpLocalOk) {
    if (url.protocol === 'http:') {
      return { ok: false, error: 'Webhook target must be https', code: 'insecure_url' };
    }
    return { ok: false, error: 'Webhook target must be an https URL', code: 'invalid_url' };
  }

  if (!isDefaultPort(url)) {
    return { ok: false, error: 'Webhook target must use the default port', code: 'port' };
  }

  if (hostname !== expectedHost) {
    return {
      ok: false,
      error: `URL host ${hostname} does not match verified project host ${expectedHost}`,
      code: 'host_mismatch',
    };
  }

  return { ok: true, url: url.toString(), hostname };
}

export function webhookHostMismatchSummary(project: { url: string; hostname?: string | null }): string {
  let host = project.hostname || '';
  if (!host) {
    try {
      host = new URL(project.url).hostname;
    } catch {
      host = project.url;
    }
  }
  return [
    `The deployment URL host is not the verified project host (${host}).`,
    'The URL was not scanned.',
    'Falling back to production would report a false pass for an untested preview.',
  ].join(' ');
}

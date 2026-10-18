import { resolveTxt } from 'node:dns/promises';

const MAX_FETCH_SIZE = 64 * 1024;
const FETCH_TIMEOUT_MS = 10_000;

/**
 * Check if we're in an explicit development/test environment.
 * Fails closed: returns false (production) unless explicitly set to dev/test.
 * This is safe for Cloudflare Workers where NODE_ENV may not be set.
 */
export function isDevelopment(): boolean {
  const vtaEnv = process.env.VTA_ENV?.toLowerCase();
  if (vtaEnv === 'development' || vtaEnv === 'test') return true;
  const nodeEnv = process.env.NODE_ENV?.toLowerCase();
  if (nodeEnv === 'development' || nodeEnv === 'test') return true;
  return false;
}

/**
 * Check if a hostname is a local development host.
 */
function isLocalHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname.endsWith('.local');
}

/**
 * Check if VTA_SKIP_DNS_VERIFY should be honored.
 * Fails closed: only allow skip in explicit dev/test mode OR for localhost.
 */
export function shouldSkipDnsVerify(hostname: string): boolean {
  if (isLocalHost(hostname)) return true;
  if (!isDevelopment()) return false;
  return process.env.VTA_SKIP_DNS_VERIFY === '1' || process.env.SHIPCHECK_SKIP_DNS_VERIFY === '1';
}

/** Expect TXT: vibetesting-verify=<token> (or legacy shipcheck-verify=) on host or _vta.<host>. */
export async function verifyDomainOwnership(hostname: string, token: string): Promise<{
  ok: boolean;
  detail: string;
}> {
  const expected = [`vibetesting-verify=${token}`, `shipcheck-verify=${token}`];
  const names = [hostname, `_vta.${hostname}`, `_shipcheck.${hostname}`];

  for (const name of names) {
    try {
      const records = await resolveTxt(name);
      const flat = records.map((r) => r.join(''));
      if (flat.some((t) => expected.some((e) => t.includes(e)))) {
        return { ok: true, detail: `Found verification TXT on ${name}` };
      }
    } catch {
      /* NXDOMAIN etc */
    }
  }

  if (shouldSkipDnsVerify(hostname)) {
    return { ok: true, detail: 'Dev skip DNS verify' };
  }

  return {
    ok: false,
    detail: `Add a DNS TXT record on ${hostname} or _vta.${hostname} with value: vibetesting-verify=${token}`,
  };
}

/**
 * Verify ownership via well-known file at https://<host>/.well-known/vibetesting-verify.txt
 * Fetches over HTTPS only, no cross-host redirects, size-limited.
 */
export async function verifyFileOwnership(hostname: string, token: string): Promise<{
  ok: boolean;
  detail: string;
}> {
  const url = `https://${hostname}/.well-known/vibetesting-verify.txt`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    const response = await fetch(url, {
      signal: controller.signal,
      redirect: 'manual',
      headers: { 'User-Agent': 'VibeTesting-Agent/1.0 (ownership-verification)' },
    });

    clearTimeout(timeout);

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (location) {
        try {
          const redirectUrl = new URL(location, url);
          if (redirectUrl.hostname.toLowerCase() !== hostname.toLowerCase()) {
            return { ok: false, detail: 'Verification file redirects to a different host — not allowed for security' };
          }
        } catch {
          return { ok: false, detail: 'Invalid redirect location' };
        }
      }
      return { ok: false, detail: `Verification file returned redirect ${response.status} — follow not supported` };
    }

    if (!response.ok) {
      return { ok: false, detail: `Verification file returned ${response.status}. Create ${url} containing: ${token}` };
    }

    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength, 10) > MAX_FETCH_SIZE) {
      return { ok: false, detail: 'Verification file too large (max 64KB)' };
    }

    const reader = response.body?.getReader();
    if (!reader) {
      return { ok: false, detail: 'Could not read verification file body' };
    }

    let content = '';
    let bytesRead = 0;
    const decoder = new TextDecoder();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytesRead += value.byteLength;
      if (bytesRead > MAX_FETCH_SIZE) {
        await reader.cancel();
        return { ok: false, detail: 'Verification file too large (max 64KB)' };
      }
      content += decoder.decode(value, { stream: true });
    }
    content += decoder.decode();

    const trimmed = content.trim();
    if (trimmed === token) {
      return { ok: true, detail: `Found verification token in ${url}` };
    }

    if (trimmed.includes(token)) {
      return { ok: false, detail: `File contains the token but also other content. The file should contain ONLY: ${token}` };
    }

    return { ok: false, detail: `Token not found in ${url}. The file should contain exactly: ${token}` };
  } catch (err) {
    if ((err as Error).name === 'AbortError') {
      return { ok: false, detail: 'Verification file fetch timed out' };
    }
    return { ok: false, detail: `Could not fetch ${url}: ${(err as Error).message}` };
  }
}

/**
 * Verify ownership via meta tag on the homepage: <meta name="vibetesting-verify" content="<token>">
 * Fetches over HTTPS only, no cross-host redirects, size-limited.
 */
export async function verifyMetaOwnership(hostname: string, token: string): Promise<{
  ok: boolean;
  detail: string;
}> {
  const url = `https://${hostname}/`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    const response = await fetch(url, {
      signal: controller.signal,
      redirect: 'follow',
      headers: {
        'User-Agent': 'VibeTesting-Agent/1.0 (ownership-verification)',
        'Accept': 'text/html',
      },
    });

    clearTimeout(timeout);

    if (!response.ok) {
      return { ok: false, detail: `Homepage returned ${response.status}. Add <meta name="vibetesting-verify" content="${token}"> to your homepage <head>.` };
    }

    const finalUrl = new URL(response.url);
    if (finalUrl.hostname.toLowerCase() !== hostname.toLowerCase()) {
      return { ok: false, detail: `Homepage redirected to different host (${finalUrl.hostname}) — not allowed for security` };
    }

    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('html')) {
      return { ok: false, detail: 'Homepage is not HTML — meta tag verification requires an HTML page' };
    }

    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength, 10) > MAX_FETCH_SIZE * 10) {
      return { ok: false, detail: 'Homepage too large for meta tag scan (max 640KB)' };
    }

    const reader = response.body?.getReader();
    if (!reader) {
      return { ok: false, detail: 'Could not read homepage body' };
    }

    let html = '';
    let bytesRead = 0;
    const decoder = new TextDecoder();
    const maxBytes = MAX_FETCH_SIZE * 10;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytesRead += value.byteLength;
      if (bytesRead > maxBytes) {
        await reader.cancel();
        break;
      }
      html += decoder.decode(value, { stream: true });
    }
    html += decoder.decode();

    const metaPattern = new RegExp(
      `<meta[^>]+name\\s*=\\s*["']vibetesting-verify["'][^>]+content\\s*=\\s*["']${escapeRegex(token)}["'][^>]*>|` +
      `<meta[^>]+content\\s*=\\s*["']${escapeRegex(token)}["'][^>]+name\\s*=\\s*["']vibetesting-verify["'][^>]*>`,
      'i'
    );

    if (metaPattern.test(html)) {
      return { ok: true, detail: `Found <meta name="vibetesting-verify" content="${token}"> on homepage` };
    }

    if (html.includes('vibetesting-verify')) {
      return { ok: false, detail: `Found a vibetesting-verify meta tag but with wrong content. Expected content="${token}"` };
    }

    return { ok: false, detail: `Meta tag not found. Add <meta name="vibetesting-verify" content="${token}"> to your homepage <head>.` };
  } catch (err) {
    if ((err as Error).name === 'AbortError') {
      return { ok: false, detail: 'Homepage fetch timed out' };
    }
    return { ok: false, detail: `Could not fetch ${url}: ${(err as Error).message}` };
  }
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function hostnameFromUrl(url: string): string {
  return new URL(url).hostname.toLowerCase();
}

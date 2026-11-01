/**
 * HTTP ownership proofs for a host the owner claims:
 * - file: GET https://{host}/.well-known/vibetesting-verify.txt contains the token
 * - meta: homepage <meta name="vibetesting-verify" content="{token}">
 *
 * Used to prove a preview parent (e.g. sparkle-forms.pages.dev) when DNS is
 * unavailable on a shared platform subdomain.
 */

export type HttpVerifyMethod = 'file' | 'meta';

const VERIFY_PATH = '/.well-known/vibetesting-verify.txt';

function tokenPresent(body: string, token: string): boolean {
  const expected = [`vibetesting-verify=${token}`, token];
  const trimmed = body.trim();
  return expected.some((e) => trimmed === e || trimmed.includes(e));
}

export function metaTagHasToken(html: string, token: string): boolean {
  const re = /<meta\b[^>]*\bname\s*=\s*["']vibetesting-verify["'][^>]*>/gi;
  for (const m of html.matchAll(re)) {
    const tag = m[0];
    const content = tag.match(/\bcontent\s*=\s*["']([^"']+)["']/i)?.[1];
    if (content && (content === token || content === `vibetesting-verify=${token}`)) return true;
  }
  const reRev = /<meta\b[^>]*\bcontent\s*=\s*["']([^"']+)["'][^>]*\bname\s*=\s*["']vibetesting-verify["'][^>]*>/gi;
  for (const m of html.matchAll(reRev)) {
    const content = m[1];
    if (content && (content === token || content === `vibetesting-verify=${token}`)) return true;
  }
  return false;
}

export async function verifyHostByFile(
  hostname: string,
  token: string,
  fetchImpl: typeof fetch = fetch,
): Promise<{ ok: boolean; detail: string }> {
  const url = `https://${hostname}${VERIFY_PATH}`;
  try {
    const res = await fetchImpl(url, { redirect: 'follow', signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return { ok: false, detail: `${VERIFY_PATH} returned HTTP ${res.status}` };
    const body = (await res.text()).slice(0, 4_000);
    if (tokenPresent(body, token)) return { ok: true, detail: `Found verification file at ${VERIFY_PATH}` };
    return { ok: false, detail: `${VERIFY_PATH} did not contain vibetesting-verify=${token}` };
  } catch (err) {
    return { ok: false, detail: `Could not fetch ${VERIFY_PATH}: ${err instanceof Error ? err.message : String(err)}` };
  }
}

export async function verifyHostByMeta(
  hostname: string,
  token: string,
  fetchImpl: typeof fetch = fetch,
): Promise<{ ok: boolean; detail: string }> {
  const url = `https://${hostname}/`;
  try {
    const res = await fetchImpl(url, { redirect: 'follow', signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return { ok: false, detail: `Homepage returned HTTP ${res.status}` };
    const html = (await res.text()).slice(0, 500_000);
    if (metaTagHasToken(html, token)) return { ok: true, detail: 'Found vibetesting-verify meta tag on the homepage' };
    return { ok: false, detail: 'Homepage is missing <meta name="vibetesting-verify" content="…">' };
  } catch (err) {
    return { ok: false, detail: `Could not fetch homepage: ${err instanceof Error ? err.message : String(err)}` };
  }
}

export async function verifyHostHttp(
  hostname: string,
  token: string,
  method: HttpVerifyMethod,
  fetchImpl: typeof fetch = fetch,
): Promise<{ ok: boolean; detail: string }> {
  if (method === 'file') return verifyHostByFile(hostname, token, fetchImpl);
  return verifyHostByMeta(hostname, token, fetchImpl);
}

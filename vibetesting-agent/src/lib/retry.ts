/**
 * Hosted-scan retry — same classification as OSS `src/retry.ts`.
 * Network reset / timeout / DNS / HTTP 429/502/503/504 only. Never other 4xx.
 */

export const DEFAULT_RETRIES = 2;
export const DEFAULT_RETRY_AFTER_CAP_MS = 10_000;
const BACKOFF_BASE_MS = 200;
const TRANSIENT = new Set([429, 502, 503, 504]);

export function isTransientStatus(status: number): boolean {
  return TRANSIENT.has(status);
}

export function parseRetryAfter(value: string | null | undefined, capMs = DEFAULT_RETRY_AFTER_CAP_MS): number | null {
  if (value == null) return null;
  const trimmed = String(value).trim();
  if (!trimmed) return null;
  const seconds = Number(trimmed);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.min(Math.round(seconds * 1000), capMs);
  const when = Date.parse(trimmed);
  if (!Number.isNaN(when)) return Math.min(Math.max(0, when - Date.now()), capMs);
  return null;
}

export function isTransientError(err: unknown): boolean {
  const anyErr = err as { name?: string; message?: string; code?: string };
  const blob = `${anyErr.name || ''} ${anyErr.code || ''} ${anyErr.message || ''}`.toLowerCase();
  return /aborterror|timeouterror|timeout|aborted|econnreset|econnrefused|enotfound|eai_again|fetch failed|failed to fetch|network|socket|dns/.test(blob);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export async function fetchWithTransientRetry(
  url: string,
  init: RequestInit,
  opts: { retries?: number; timeoutMs?: number } = {},
): Promise<{ response: Response | null; retries: number; exhausted: boolean; error?: unknown }> {
  const max = Math.max(0, Math.floor(opts.retries ?? DEFAULT_RETRIES));
  const timeoutMs = opts.timeoutMs ?? 15_000;
  let lastError: unknown;
  for (let attempt = 0; attempt <= max; attempt++) {
    try {
      const response = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
      if (!isTransientStatus(response.status) || attempt === max) {
        return { response, retries: attempt, exhausted: isTransientStatus(response.status) && attempt === max };
      }
      const wait = parseRetryAfter(response.headers.get('retry-after')) ?? Math.min(BACKOFF_BASE_MS * 2 ** attempt, DEFAULT_RETRY_AFTER_CAP_MS);
      await sleep(wait);
    } catch (err) {
      lastError = err;
      if (!isTransientError(err) || attempt === max) {
        return { response: null, retries: attempt, exhausted: isTransientError(err) && attempt === max, error: err };
      }
      await sleep(Math.min(BACKOFF_BASE_MS * 2 ** attempt, DEFAULT_RETRY_AFTER_CAP_MS));
    }
  }
  return { response: null, retries: max, exhausted: true, error: lastError };
}

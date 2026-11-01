// Transient-error retry for scan HTTP. Reused by CLI fetch helpers and the hosted worker scan.
// Retries only transport blips and 429/502/503/504 — never a real finding or other 4xx.

export const DEFAULT_RETRIES = 2;
export const DEFAULT_RETRY_AFTER_CAP_MS = 10_000;
export const DEFAULT_BACKOFF_BASE_MS = 200;

export const TRANSIENT_STATUS = new Set([429, 502, 503, 504]);

export type TransientKind =
  | 'network'
  | 'timeout'
  | 'dns'
  | 'http_429'
  | 'http_502'
  | 'http_503'
  | 'http_504';

export function isTransientStatus(status: number): boolean {
  return TRANSIENT_STATUS.has(status);
}

/** 4xx other than 429 are real responses (auth, not found, bad request) — never retry. */
export function isNonRetryableClientError(status: number): boolean {
  return status >= 400 && status < 500 && status !== 429;
}

/**
 * Classify a thrown fetch/network error. Returns a kind when the failure is worth retrying,
 * otherwise null (caller should not retry).
 */
export function classifyTransientError(err: unknown): TransientKind | null {
  if (err == null) return null;
  const anyErr = err as { name?: string; message?: string; code?: string; cause?: { code?: string; message?: string } };
  const name = String(anyErr.name || '');
  const code = String(anyErr.code || anyErr.cause?.code || '');
  const message = `${anyErr.message || ''} ${anyErr.cause?.message || ''}`;
  const blob = `${name} ${code} ${message}`.toLowerCase();

  if (
    name === 'AbortError' ||
    name === 'TimeoutError' ||
    code === 'ABORT_ERR' ||
    /timeout|timed out|aborted|err_timed_out/i.test(blob)
  ) {
    return 'timeout';
  }
  if (
    code === 'ENOTFOUND' ||
    code === 'EAI_AGAIN' ||
    code === 'ENODATA' ||
    /enotfound|eai_again|getaddrinfo|dns|nxdomain/i.test(blob)
  ) {
    return 'dns';
  }
  if (
    code === 'ECONNRESET' ||
    code === 'ECONNREFUSED' ||
    code === 'EPIPE' ||
    code === 'UND_ERR_SOCKET' ||
    code === 'UND_ERR_CONNECT_TIMEOUT' ||
    /econnreset|econnrefused|epipe|socket|network|fetch failed|failed to fetch|und_err/i.test(blob)
  ) {
    return 'network';
  }
  return null;
}

export function transientKindForStatus(status: number): TransientKind | null {
  if (status === 429) return 'http_429';
  if (status === 502) return 'http_502';
  if (status === 503) return 'http_503';
  if (status === 504) return 'http_504';
  return null;
}

/** Parse Retry-After (delta-seconds or HTTP-date) and clamp to capMs. */
export function parseRetryAfter(value: string | null | undefined, capMs = DEFAULT_RETRY_AFTER_CAP_MS): number | null {
  if (value == null) return null;
  const trimmed = String(value).trim();
  if (!trimmed) return null;
  const seconds = Number(trimmed);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(Math.round(seconds * 1000), capMs);
  }
  const when = Date.parse(trimmed);
  if (!Number.isNaN(when)) {
    return Math.min(Math.max(0, when - Date.now()), capMs);
  }
  return null;
}

export function backoffMs(
  attempt: number,
  retryAfterMs: number | null = null,
  capMs = DEFAULT_RETRY_AFTER_CAP_MS,
  baseMs = DEFAULT_BACKOFF_BASE_MS,
): number {
  if (retryAfterMs != null) return Math.min(Math.max(0, retryAfterMs), capMs);
  const exp = baseMs * 2 ** Math.max(0, attempt);
  return Math.min(exp, capMs);
}

export interface RetryDecision {
  retry: boolean;
  kind?: TransientKind;
  retryAfterMs?: number | null;
}

export function decideRetry(input: {
  status?: number;
  error?: unknown;
  retryAfter?: string | null;
  capMs?: number;
}): RetryDecision {
  if (input.status != null) {
    if (isNonRetryableClientError(input.status)) return { retry: false };
    const kind = transientKindForStatus(input.status);
    if (kind) {
      return {
        retry: true,
        kind,
        retryAfterMs: parseRetryAfter(input.retryAfter, input.capMs),
      };
    }
    return { retry: false };
  }
  const kind = classifyTransientError(input.error);
  if (kind) return { retry: true, kind };
  return { retry: false };
}

export interface WithRetriesOptions<T> {
  retries: number;
  isRetryable: (result: T) => RetryDecision;
  classifyError?: (err: unknown) => RetryDecision;
  sleep?: (ms: number) => Promise<void>;
  capMs?: number;
  now?: () => number;
}

export interface WithRetriesResult<T> {
  value?: T;
  error?: unknown;
  retries: number;
  exhausted: boolean;
  lastKind?: TransientKind;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Run `fn` up to `retries + 1` times. `retries: 0` disables retries (single attempt).
 * Honour Retry-After when present, clamped to capMs.
 */
export async function withRetries<T>(
  fn: (attempt: number) => Promise<T>,
  opts: WithRetriesOptions<T>,
): Promise<WithRetriesResult<T>> {
  const maxRetries = Math.max(0, Math.floor(opts.retries));
  const sleep = opts.sleep ?? defaultSleep;
  const capMs = opts.capMs ?? DEFAULT_RETRY_AFTER_CAP_MS;
  let lastKind: TransientKind | undefined;
  let lastError: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const value = await fn(attempt);
      const decision = opts.isRetryable(value);
      if (!decision.retry || attempt === maxRetries) {
        return {
          value,
          retries: attempt,
          exhausted: decision.retry && attempt === maxRetries,
          lastKind: decision.kind ?? lastKind,
        };
      }
      lastKind = decision.kind ?? lastKind;
      await sleep(backoffMs(attempt, decision.retryAfterMs ?? null, capMs));
    } catch (err) {
      lastError = err;
      const decision = (opts.classifyError ?? ((e: unknown) => decideRetry({ error: e })))(err);
      if (!decision.retry || attempt === maxRetries) {
        return {
          error: err,
          retries: attempt,
          exhausted: Boolean(decision.retry && attempt === maxRetries),
          lastKind: decision.kind ?? lastKind,
        };
      }
      lastKind = decision.kind ?? lastKind;
      await sleep(backoffMs(attempt, decision.retryAfterMs ?? null, capMs));
    }
  }
  return { error: lastError, retries: maxRetries, exhausted: true, lastKind };
}

/** Inconclusive / error finding — not a security result and must not trip --fail-on. */
export function inconclusiveFinding(partial: {
  id: string;
  category: import('./types.js').Category;
  title: string;
  detail: string;
  retries?: number;
  fix?: string;
}): import('./types.js').Finding {
  return {
    id: partial.id,
    category: partial.category,
    title: partial.title,
    severity: 'info',
    pass: true,
    inconclusive: true,
    detail: partial.detail,
    retries: partial.retries ?? 0,
    ...(partial.fix ? { fix: partial.fix } : {}),
  };
}

/** Findings that may trip a CI gate. Inconclusive errors and quarantined flakes do not. */
export function gateableFindings<T extends { pass: boolean; inconclusive?: boolean; quarantined?: boolean }>(
  findings: T[],
): T[] {
  return findings.filter((f) => !f.pass && !f.inconclusive && !f.quarantined);
}

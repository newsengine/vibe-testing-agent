export declare const DEFAULT_RETRIES = 2;
export declare const DEFAULT_RETRY_AFTER_CAP_MS = 10000;
export declare const DEFAULT_BACKOFF_BASE_MS = 200;
export declare const TRANSIENT_STATUS: Set<number>;
export type TransientKind = 'network' | 'timeout' | 'dns' | 'http_429' | 'http_502' | 'http_503' | 'http_504';
export declare function isTransientStatus(status: number): boolean;
/** 4xx other than 429 are real responses (auth, not found, bad request) — never retry. */
export declare function isNonRetryableClientError(status: number): boolean;
/**
 * Classify a thrown fetch/network error. Returns a kind when the failure is worth retrying,
 * otherwise null (caller should not retry).
 */
export declare function classifyTransientError(err: unknown): TransientKind | null;
export declare function transientKindForStatus(status: number): TransientKind | null;
/** Parse Retry-After (delta-seconds or HTTP-date) and clamp to capMs. */
export declare function parseRetryAfter(value: string | null | undefined, capMs?: number): number | null;
export declare function backoffMs(attempt: number, retryAfterMs?: number | null, capMs?: number, baseMs?: number): number;
export interface RetryDecision {
    retry: boolean;
    kind?: TransientKind;
    retryAfterMs?: number | null;
}
export declare function decideRetry(input: {
    status?: number;
    error?: unknown;
    retryAfter?: string | null;
    capMs?: number;
}): RetryDecision;
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
/**
 * Run `fn` up to `retries + 1` times. `retries: 0` disables retries (single attempt).
 * Honour Retry-After when present, clamped to capMs.
 */
export declare function withRetries<T>(fn: (attempt: number) => Promise<T>, opts: WithRetriesOptions<T>): Promise<WithRetriesResult<T>>;
/** Inconclusive / error finding — not a security result and must not trip --fail-on. */
export declare function inconclusiveFinding(partial: {
    id: string;
    category: import('./types.js').Category;
    title: string;
    detail: string;
    retries?: number;
    fix?: string;
}): import('./types.js').Finding;
/** Findings that may trip a CI gate. Inconclusive errors and quarantined flakes do not. */
export declare function gateableFindings<T extends {
    pass: boolean;
    inconclusive?: boolean;
    quarantined?: boolean;
}>(findings: T[]): T[];

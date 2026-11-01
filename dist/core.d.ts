import { type TransientKind } from './retry.js';
export interface TlsInfo {
    /** Days until the served certificate expires (null if undeterminable). */
    daysRemaining: number | null;
    /** Negotiated protocol, e.g. "TLSv1.3" / "TLSv1.2" / "TLSv1" (null if undeterminable). */
    protocol: string | null;
    /** Negotiated cipher suite name (null if undeterminable). */
    cipher: string | null;
}
/**
 * Probe the served TLS: cert expiry + negotiated protocol + cipher. Uses a raw TLS connection because
 * fetch() exposes none of this. Fails soft to nulls.
 */
export declare function tlsProbe(host: string, port?: number): Promise<TlsInfo>;
/** Back-compat wrapper — days until the served cert expires. */
export declare function tlsCertDaysRemaining(host: string, port?: number): Promise<number | null>;
/** Grade a negotiated TLS protocol. Pure/testable. */
export declare function gradeTlsProtocol(protocol: string | null): {
    ok: boolean;
    severity: 'high' | 'medium' | 'low' | 'info';
    detail: string;
};
/** Flag known-weak cipher suites. Pure/testable. */
export declare function gradeTlsCipher(cipher: string | null): {
    ok: boolean;
    detail: string;
};
export declare const DEFAULT_TIMEOUT_MS = 10000;
export declare function runWithRetryBudget<T>(retries: number, fn: () => Promise<T>): Promise<T>;
export declare function currentRetryBudget(): number;
export interface FetchRetryMeta {
    retries: number;
    exhausted: boolean;
    lastKind?: TransientKind;
}
export interface FetchResult {
    response: Response | null;
    retries: number;
    exhausted: boolean;
    lastKind?: TransientKind;
    error?: unknown;
}
export interface SafeFetchOptions {
    /** Override the scan retry budget. `0` disables retries (rate-limit bursts, attack probes). */
    retries?: number;
}
/**
 * Fetch with bounded backoff on network reset / timeout / DNS / 429/502/503/504.
 * Honour Retry-After within the cap. Never retries other 4xx or a successful response.
 */
export declare function fetchWithRetry(url: string, init: RequestInit | undefined, timeoutMs: number, retries: number): Promise<FetchResult>;
export declare function safeFetch(url: string, init?: RequestInit, timeoutMs?: number, retryOpts?: SafeFetchOptions): Promise<Response | null>;
/**
 * Fetch text with a hard timeout AND a streaming byte cap: we stop reading once maxBytes have arrived,
 * so a gzip bomb / endless stream can't OOM the process (arrayBuffer() would buffer the whole body first).
 * Returns '' on any failure. Binary responses are decoded lossily — callers only regex over them.
 */
export declare function fetchText(url: string, init?: RequestInit, maxBytes?: number, timeoutMs?: number, retryOpts?: SafeFetchOptions): Promise<string>;
export declare function headerGet(h: Headers | Record<string, string>, name: string): string | null;
/** Resolve a possibly-relative href against the page origin; null if it can't be parsed. */
export declare function resolveUrl(base: string, href: string): string | null;
export declare function sameOrigin(a: string, b: string): boolean;
export declare function matchAllGroups(html: string, re: RegExp): string[];
export declare const html: {
    title: (h: string) => string;
    hasLang: (h: string) => boolean;
    metaContent: (h: string, name: string) => string | null;
    hasViewport: (h: string) => boolean;
    canonical: (h: string) => string | null;
    scripts: (h: string) => string[];
    links: (h: string) => string[];
    images: (h: string) => {
        src: string;
        hasAlt: boolean;
    }[];
    h1Count: (h: string) => number;
    inputsNeedingLabel: (h: string) => number;
    labelCount: (h: string) => number;
    insecureRefs: (h: string) => string[];
};
export interface SecretRule {
    id: string;
    name: string;
    severity: 'high' | 'medium' | 'low';
    re: RegExp;
    /** Optional extra confirmation to cut false positives. */
    confirm?: (match: string, blob: string) => boolean;
}
export declare const SECRET_RULES: SecretRule[];
export interface SecretHit {
    ruleId: string;
    name: string;
    severity: 'high' | 'medium' | 'low';
    sample: string;
}
export declare function scanSecrets(blob: string): SecretHit[];

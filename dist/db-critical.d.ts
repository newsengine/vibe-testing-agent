import type { Finding, Severity } from './types.js';
export type DbCriticalRole = 'editor' | 'superadmin' | 'user';
export interface DbCriticalSpec {
    id: string;
    title: string;
    severity: Severity;
    description: string;
    /** authenticated = needs role env; white-box = fixture/gated; probe = black-box safe without auth */
    cls: 'authenticated' | 'white-box' | 'probe';
}
/** Catalog specs for docs/CHECKS.md (appended by catalog.ts). */
export declare function dbCriticalCheckSpecs(): DbCriticalSpec[];
/** Minimal RFC 6238 TOTP (SHA-1, 30s, 6 digits) — no extra dependency. */
export declare function totpCode(secretBase32: string, nowMs?: number): string;
/** True for classic eyJ… JWT anon keys (incl. the disabled DB legacy default). */
export declare function isLegacyJwtAnonKey(key: string): boolean;
export interface DbCriticalSession {
    token: string;
    /** Cookie header value for Next.js middleware (@supabase/ssr base64url chunks). */
    cookieHeader: string;
}
/**
 * Storage key for Supabase SSR auth cookies.
 * Prefer project-ref from access_token `iss` (custom domains still mint sb-<ref>-auth-token);
 * fall back to the configured Supabase URL hostname.
 */
export declare function supabaseAuthStorageKey(accessToken: string, supabaseUrl: string): string;
/** Split a cookie value the same way @supabase/ssr createChunks does. */
export declare function chunkSupabaseCookie(key: string, value: string, chunkSize?: number): {
    name: string;
    value: string;
}[];
/** Build Cookie header for Next.js middleware that uses @supabase/ssr createServerClient. */
export declare function buildSupabaseSsrCookieHeader(session: {
    access_token: string;
    refresh_token: string;
    expires_in?: number;
    expires_at?: number;
    token_type?: string;
    user?: unknown;
}, supabaseUrl: string): string;
/** The user's verified TOTP factor id from a GoTrue token response, if any. */
export declare function verifiedTotpFactor(user: any): string | null;
/**
 * Supabase MFA challenge + verify (POST /auth/v1/factors/{id}/challenge then
 * /verify). Returns the aal2 session. Retries once with a fresh challenge in
 * case the code crossed a 30s step. Neither the seed nor any code is logged or
 * returned in an error message.
 */
export declare function stepUpToAal2(url: string, anonKey: string, accessToken: string, factorId: string, secret: string): Promise<{
    session: any;
} | {
    error: string;
}>;
export type ObtainSessionResult = {
    token: string;
    cookieHeader: string;
    skipReason?: undefined;
    error?: undefined;
} | {
    token?: undefined;
    cookieHeader?: undefined;
    skipReason: string;
    error?: undefined;
} | {
    token?: undefined;
    cookieHeader?: undefined;
    skipReason?: undefined;
    error: string;
};
/**
 * Password-grant a session (Bearer + SSR cookie). Accounts with a verified TOTP factor are stepped
 * up to AAL2 via Supabase MFA challenge + verify (VTA_<ROLE>_TOTP_SECRET, else VTA_TOTP_SECRET).
 * HTML dashboard routes need the cookie (middleware getUser); API routes keep working with Bearer.
 */
export declare function obtainSession(role: DbCriticalRole): Promise<ObtainSessionResult>;
/** Password-grant a Bearer token (API checks). Prefer obtainSession when HTML cookies are needed. */
export declare function obtainAccessToken(role: DbCriticalRole): Promise<{
    token?: string;
    skipReason?: string;
    error?: string;
}>;
/** 1x1 PNG */
export declare const TINY_PNG: Buffer<ArrayBuffer>;
export declare function runDbCritical(targetUrl: string, opts?: {
    timeoutMs?: number;
}): Promise<Finding[]>;
/** Pure helpers exported for unit tests. */
export declare function htmlReflectsXss(body: string, payload: string): boolean;
export declare function profilesDumpDetected(status: number, rows: unknown): boolean;
export declare function assertTimingSafeEqual(a: string, b: string): boolean;

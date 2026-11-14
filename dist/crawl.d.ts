import type { Finding } from './types.js';
export interface CrawlOptions {
    maxPages?: number;
    startPaths?: string[];
    /** Reuse a logged-in Chrome profile (via browser-auth). */
    chromeProfile?: string;
    profilesDir?: string;
    /** Or authenticate with a raw Cookie header. */
    cookie?: string;
    timeoutMs?: number;
}
/**
 * Turn a raw `Cookie:` header ("a=1; b=2") into Playwright cookies bound to `origin` via `url`, so the
 * browser only sends them back to that host (host-only, Secure when the origin is https).
 */
export declare function cookieHeaderToCookies(raw: string, origin: string): {
    name: string;
    value: string;
    url: string;
}[];
export declare function crawlAudit(startUrl: string, opts?: CrawlOptions): Promise<Finding[]>;

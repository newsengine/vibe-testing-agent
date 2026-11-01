import type { Category, Finding, ScanContext, ScanOptions, Severity } from './types.js';
export type { Category, Finding, ScanContext, ScanOptions, Severity };
export type ProbeOptions = ScanOptions;
export declare const ALL_CATEGORIES: Category[];
/** Add https:// when the user typed a bare domain, so `vibetesting-agent example.com` just works. */
export declare function normalizeUrl(input: string): string;
export declare function probe(baseUrl: string, opts?: ScanOptions): Promise<Finding[]>;
/** Alias — reads better for the full-app use case. */
export declare const scan: typeof probe;
/**
 * Discover up to `max` additional same-origin pages linked from the homepage — for a bounded multi-page
 * crawl (`--crawl N`). Returns absolute URLs (excluding the homepage itself). Best-effort; [] on failure.
 */
export declare function discoverPages(baseUrl: string, max: number, opts?: ScanOptions): Promise<string[]>;
export declare function summarize(findings: Finding[]): {
    passed: number;
    failed: number;
    failHigh: number;
    failMedium: number;
    failLow: number;
    byCategory: Record<string, {
        passed: number;
        failed: number;
    }>;
};

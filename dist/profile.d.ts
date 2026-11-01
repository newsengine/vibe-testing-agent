import type { Category, ScanOptions } from './types.js';
export type ScanProfile = 'smoke' | 'full';
/** Passive categories only — no opt-in intrusive / authorized-active checks. */
export declare const SMOKE_CATEGORIES: Category[];
/** Small set of key paths a smoke scan GETs in addition to the homepage. */
export declare const SMOKE_PATHS: string[];
export declare const SMOKE_MAX_CRAWL = 8;
export declare const SMOKE_TIMEOUT_MS = 8000;
export declare function parseProfile(raw: string | undefined | null): ScanProfile | null;
/**
 * Apply a named profile. Explicit ScanOptions (only/skip/timeout/…) win over
 * profile defaults so CI can still narrow a smoke run further.
 */
export declare function applyProfile(profile: ScanProfile, opts?: ScanOptions): ScanOptions;
export declare function smokeCheckIds(): string[];

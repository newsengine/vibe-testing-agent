// Named scan profiles. `smoke` is a fast, passive subset over a small set of
// key paths (target < ~60s). `full` is the default comprehensive suite.

import type { Category, ScanOptions } from './types.js';

export type ScanProfile = 'smoke' | 'full';

/** Passive categories only — no opt-in intrusive / authorized-active checks. */
export const SMOKE_CATEGORIES: Category[] = ['security', 'secrets', 'exposure'];

/** Small set of key paths a smoke scan GETs in addition to the homepage. */
export const SMOKE_PATHS = ['/', '/login', '/signin', '/health', '/api/health', '/robots.txt'];

export const SMOKE_MAX_CRAWL = 8;
export const SMOKE_TIMEOUT_MS = 8_000;

export function parseProfile(raw: string | undefined | null): ScanProfile | null {
  if (raw == null || raw === '') return 'full';
  if (raw === 'smoke' || raw === 'full') return raw;
  return null;
}

/**
 * Apply a named profile. Explicit ScanOptions (only/skip/timeout/…) win over
 * profile defaults so CI can still narrow a smoke run further.
 */
export function applyProfile(profile: ScanProfile, opts: ScanOptions = {}): ScanOptions {
  if (profile === 'full') {
    return { ...opts, profile: 'full' };
  }
  return {
    ...opts,
    profile: 'smoke',
    only: opts.only ?? SMOKE_CATEGORIES,
    maxCrawl: opts.maxCrawl ?? SMOKE_MAX_CRAWL,
    timeoutMs: opts.timeoutMs ?? SMOKE_TIMEOUT_MS,
    smokePaths: opts.smokePaths ?? SMOKE_PATHS,
    // Smoke is passive: never enable opt-in intrusive probes.
    apiWrite: false,
    rateLimitScan: false,
    reflectedXss: false,
    aiProbe: false,
    authorizedActive: false,
  };
}

export function smokeCheckIds(): string[] {
  return [
    ...SMOKE_CATEGORIES.map((c) => `category:${c}`),
    ...SMOKE_PATHS.map((p) => `smoke.path${p === '/' ? '/' : p}`),
  ];
}

// src/config.ts
// Optional .analproberc.json for repeated/CI use: default flags so you don't retype them. CLI flags
// always override the file. Kept intentionally small — it only carries the knobs people repeat.

import { readFileSync } from 'node:fs';

export interface FileConfig {
  only?: string[];
  skip?: string[];
  failOn?: 'high' | 'medium' | 'any';
  corsPath?: string;
  rateLimitPath?: string;
  timeoutMs?: number;
  retries?: number;
  profile?: 'smoke' | 'full';
  maxCrawl?: number;
  crawl?: number;
  allowReportOnlyCsp?: boolean;
  quiet?: boolean;
  pluginsDir?: string;
  apiWrite?: boolean;
  rateLimitScan?: boolean;
  reflectedXss?: boolean;
  aiProbe?: boolean;
}

/**
 * Load config from an explicit path or the default `.analproberc.json` in cwd. A missing DEFAULT file is
 * fine (returns {}); a missing/invalid EXPLICIT path is an error the caller should surface.
 */
export function loadConfig(explicitPath?: string): { config: FileConfig; error?: string } {
  const path = explicitPath || '.analproberc.json';
  let config: FileConfig;
  try {
    config = JSON.parse(readFileSync(path, 'utf8')) as FileConfig;
  } catch (e: any) {
    if (!explicitPath && e?.code === 'ENOENT') return { config: {} }; // no default file — fine
    return { config: {}, error: `could not read config ${path}: ${String(e?.message || e)}` };
  }
  // Validate the values we later trust as numbers/enums, so a bad file fails loudly, not silently.
  for (const k of ['crawl', 'maxCrawl', 'timeoutMs'] as const) {
    const v = config[k];
    if (v !== undefined && (typeof v !== 'number' || !Number.isFinite(v) || v <= 0)) {
      return { config: {}, error: `config "${k}" must be a positive number (got ${JSON.stringify(v)})` };
    }
  }
  if (config.retries !== undefined && (typeof config.retries !== 'number' || !Number.isInteger(config.retries) || config.retries < 0)) {
    return { config: {}, error: `config "retries" must be an integer >= 0 (got ${JSON.stringify(config.retries)})` };
  }
  if (config.profile !== undefined && config.profile !== 'smoke' && config.profile !== 'full') {
    return { config: {}, error: `config "profile" must be smoke|full (got ${JSON.stringify(config.profile)})` };
  }
  if (config.failOn !== undefined && !['high', 'medium', 'any'].includes(config.failOn)) {
    return { config: {}, error: `config "failOn" must be high|medium|any (got ${JSON.stringify(config.failOn)})` };
  }
  return { config };
}

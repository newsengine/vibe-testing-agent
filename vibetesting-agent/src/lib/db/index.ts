/**
 * Database access:
 * - Cloudflare Workers / OpenNext: D1 binding `DB`
 * - Local `next dev`: better-sqlite3 file (optional)
 */
import { drizzle as drizzleD1 } from 'drizzle-orm/d1';
import type { DrizzleD1Database } from 'drizzle-orm/d1';
import * as schema from './schema';

export type AppDb = DrizzleD1Database<typeof schema>;

type SqliteDrizzle = ReturnType<typeof import('drizzle-orm/better-sqlite3').drizzle<typeof schema>>;

let _sqliteDb: SqliteDrizzle | null = null;
let _migratedLocal = false;

const MIGRATION_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT, image TEXT,
  github_id TEXT UNIQUE, github_login TEXT, stripe_customer_id TEXT UNIQUE,
  plan TEXT NOT NULL DEFAULT 'free', plan_status TEXT NOT NULL DEFAULT 'active',
  stripe_subscription_id TEXT, scans_used_month INTEGER NOT NULL DEFAULT 0,
  crawl_used_month INTEGER NOT NULL DEFAULT 0, usage_month TEXT,
  notify_email INTEGER NOT NULL DEFAULT 1, slack_webhook_url TEXT,
  email_verified_at INTEGER, email_verify_token TEXT, email_verify_expires_at INTEGER,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE, key_prefix TEXT NOT NULL,
  last_used_at INTEGER, created_at INTEGER NOT NULL, revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS api_keys_user_idx ON api_keys(user_id);
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, url TEXT NOT NULL,
  hostname TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0, verify_token TEXT NOT NULL,
  verified_at INTEGER, verify_method TEXT, policy TEXT NOT NULL DEFAULT 'ship',
  ship_check_enabled INTEGER NOT NULL DEFAULT 1, deploy_webhook_secret TEXT NOT NULL,
  github_repo TEXT, github_installation_id TEXT, badge_public INTEGER NOT NULL DEFAULT 1,
  share_token TEXT NOT NULL, last_score INTEGER, last_grade TEXT, last_scan_at INTEGER,
  baseline_json TEXT,
  auth_enabled INTEGER NOT NULL DEFAULT 0, auth_mode TEXT, auth_email TEXT,
  auth_secret_enc TEXT, auth_login_url TEXT, auth_verified_at INTEGER, auth_updated_at INTEGER,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS projects_user_idx ON projects(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS projects_user_hostname_idx ON projects(user_id, hostname);
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, project_id TEXT, url TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'fast', trigger TEXT NOT NULL DEFAULT 'manual',
  status TEXT NOT NULL DEFAULT 'queued', authorized INTEGER NOT NULL DEFAULT 0,
  score INTEGER, grade TEXT, summary_json TEXT, findings_json TEXT,
  fix_pack_markdown TEXT, report_html TEXT, baseline_diff_json TEXT, error TEXT,
  started_at INTEGER, finished_at INTEGER, created_at INTEGER NOT NULL, meta_json TEXT
);
CREATE INDEX IF NOT EXISTS scans_user_idx ON scans(user_id);
CREATE INDEX IF NOT EXISTS scans_project_idx ON scans(project_id);
CREATE INDEX IF NOT EXISTS scans_status_idx ON scans(status);
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY, user_id TEXT, action TEXT NOT NULL, target TEXT,
  detail_json TEXT, ip TEXT, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_user_idx ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_log(created_at);
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY, count INTEGER NOT NULL DEFAULT 0, window_start INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS test_runs (
  id TEXT PRIMARY KEY, scan_id TEXT, user_id TEXT NOT NULL, project_id TEXT,
  run_number INTEGER, target TEXT NOT NULL, actor TEXT NOT NULL, trigger TEXT,
  priority TEXT NOT NULL, passed INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0,
  fail_high INTEGER NOT NULL DEFAULT 0, fail_medium INTEGER NOT NULL DEFAULT 0, fail_low INTEGER NOT NULL DEFAULT 0,
  started_at INTEGER, finished_at INTEGER, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS test_runs_user_idx ON test_runs(user_id);
CREATE INDEX IF NOT EXISTS test_runs_target_idx ON test_runs(target, run_number);
CREATE INDEX IF NOT EXISTS test_runs_project_idx ON test_runs(project_id);
CREATE TABLE IF NOT EXISTS test_results (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL, vta_number INTEGER, check_id TEXT NOT NULL,
  category TEXT, severity TEXT, pass INTEGER NOT NULL, detail TEXT, atlas TEXT
);
CREATE INDEX IF NOT EXISTS test_results_run_idx ON test_results(run_id);
CREATE INDEX IF NOT EXISTS test_results_check_idx ON test_results(check_id);
CREATE INDEX IF NOT EXISTS test_results_vta_idx ON test_results(vta_number);
CREATE TABLE IF NOT EXISTS project_preview_patterns (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, pattern TEXT NOT NULL,
  proof_host TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0, verify_method TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS preview_patterns_project_pattern_idx
  ON project_preview_patterns(project_id, pattern);
CREATE INDEX IF NOT EXISTS preview_patterns_project_idx ON project_preview_patterns(project_id);
CREATE TABLE IF NOT EXISTS check_history (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, target TEXT NOT NULL, check_id TEXT NOT NULL,
  pass INTEGER NOT NULL, severity TEXT, scan_id TEXT, deploy_fingerprint TEXT, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS check_history_lookup_idx ON check_history(project_id, target, check_id, created_at);
CREATE TABLE IF NOT EXISTS quarantined_checks (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, target TEXT NOT NULL, check_id TEXT NOT NULL,
  reason TEXT NOT NULL, quarantined_at INTEGER NOT NULL, unquarantined_at INTEGER, auto INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS quarantined_checks_project_idx ON quarantined_checks(project_id);
`;

async function getD1Binding(): Promise<unknown | null> {
  try {
    const { getCloudflareContext } = await import('@opennextjs/cloudflare');
    const ctx = await getCloudflareContext({ async: true });
    const env = ctx?.env as { DB?: unknown } | undefined;
    return env?.DB ?? null;
  } catch {
    return null;
  }
}

async function getLocalSqliteDb(): Promise<SqliteDrizzle> {
  if (_sqliteDb) return _sqliteDb;
  const { default: Database } = await import('better-sqlite3');
  const { drizzle } = await import('drizzle-orm/better-sqlite3');
  const { mkdirSync } = await import('node:fs');
  const { dirname, join } = await import('node:path');
  const dbPath = process.env.DATABASE_PATH || join(process.cwd(), 'data', 'vta.db');
  mkdirSync(dirname(dbPath), { recursive: true });
  const sqlite = new Database(dbPath);
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('foreign_keys = ON');
  if (!_migratedLocal) {
    sqlite.exec(MIGRATION_SQL);
    _migratedLocal = true;
  }
  _sqliteDb = drizzle(sqlite, { schema });
  return _sqliteDb;
}

/** Async DB handle — D1 on Workers, SQLite locally. Typed as D1 drizzle for a single API surface. */
export async function getDb(): Promise<AppDb> {
  const d1 = await getD1Binding();
  if (d1) return drizzleD1(d1 as never, { schema });
  // Local better-sqlite3 is query-compatible for our usage
  return (await getLocalSqliteDb()) as unknown as AppDb;
}

export { schema };

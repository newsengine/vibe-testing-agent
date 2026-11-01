-- D1 schema for VibeTesting Agent
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT,
  image TEXT,
  github_id TEXT UNIQUE,
  github_login TEXT,
  stripe_customer_id TEXT UNIQUE,
  plan TEXT NOT NULL DEFAULT 'free',
  plan_status TEXT NOT NULL DEFAULT 'active',
  stripe_subscription_id TEXT,
  scans_used_month INTEGER NOT NULL DEFAULT 0,
  crawl_used_month INTEGER NOT NULL DEFAULT 0,
  usage_month TEXT,
  notify_email INTEGER NOT NULL DEFAULT 1,
  slack_webhook_url TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  key_prefix TEXT NOT NULL,
  last_used_at INTEGER,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS api_keys_user_idx ON api_keys(user_id);

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  hostname TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  verify_token TEXT NOT NULL,
  verified_at INTEGER,
  policy TEXT NOT NULL DEFAULT 'ship',
  ship_check_enabled INTEGER NOT NULL DEFAULT 1,
  deploy_webhook_secret TEXT NOT NULL,
  github_repo TEXT,
  github_installation_id TEXT,
  badge_public INTEGER NOT NULL DEFAULT 1,
  share_token TEXT NOT NULL,
  last_score INTEGER,
  last_grade TEXT,
  last_scan_at INTEGER,
  baseline_json TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS projects_user_idx ON projects(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS projects_user_hostname_idx ON projects(user_id, hostname);

CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
  url TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'fast',
  trigger TEXT NOT NULL DEFAULT 'manual',
  status TEXT NOT NULL DEFAULT 'queued',
  authorized INTEGER NOT NULL DEFAULT 0,
  score INTEGER,
  grade TEXT,
  summary_json TEXT,
  findings_json TEXT,
  fix_pack_markdown TEXT,
  report_html TEXT,
  baseline_diff_json TEXT,
  error TEXT,
  started_at INTEGER,
  finished_at INTEGER,
  created_at INTEGER NOT NULL,
  meta_json TEXT
);
CREATE INDEX IF NOT EXISTS scans_user_idx ON scans(user_id);
CREATE INDEX IF NOT EXISTS scans_project_idx ON scans(project_id);
CREATE INDEX IF NOT EXISTS scans_status_idx ON scans(status);

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  action TEXT NOT NULL,
  target TEXT,
  detail_json TEXT,
  ip TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_user_idx ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_log(created_at);

CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 0,
  window_start INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS project_preview_patterns (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  pattern TEXT NOT NULL,
  proof_host TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  verify_method TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS preview_patterns_project_pattern_idx
  ON project_preview_patterns(project_id, pattern);
CREATE INDEX IF NOT EXISTS preview_patterns_project_idx
  ON project_preview_patterns(project_id);

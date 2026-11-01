-- Per-check history + quarantine for flaky results.
CREATE TABLE IF NOT EXISTS check_history (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  target TEXT NOT NULL,
  check_id TEXT NOT NULL,
  pass INTEGER NOT NULL,
  severity TEXT,
  scan_id TEXT,
  deploy_fingerprint TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS check_history_lookup_idx
  ON check_history(project_id, target, check_id, created_at);

CREATE TABLE IF NOT EXISTS quarantined_checks (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  target TEXT NOT NULL,
  check_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  quarantined_at INTEGER NOT NULL,
  unquarantined_at INTEGER,
  auto INTEGER NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX IF NOT EXISTS quarantined_checks_active_idx
  ON quarantined_checks(project_id, target, check_id)
  WHERE unquarantined_at IS NULL;
CREATE INDEX IF NOT EXISTS quarantined_checks_project_idx
  ON quarantined_checks(project_id);

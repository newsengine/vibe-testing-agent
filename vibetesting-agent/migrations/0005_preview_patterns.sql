-- Allowed preview / staging host patterns per verified project.
-- A pattern is stored only after the owner proves the proof host (parent domain
-- or the specific preview host) via DNS TXT, file, or meta tag.
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

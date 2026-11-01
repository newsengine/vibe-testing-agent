/**
 * VibeTesting Agent data model — users, projects, scans, billing entitlements, API keys, audit log.
 */
import { sqliteTable, text, integer, real, index, uniqueIndex } from 'drizzle-orm/sqlite-core';

export const users = sqliteTable('users', {
  id: text('id').primaryKey(),
  email: text('email').notNull().unique(),
  name: text('name'),
  image: text('image'),
  githubId: text('github_id').unique(),
  githubLogin: text('github_login'),
  stripeCustomerId: text('stripe_customer_id').unique(),
  plan: text('plan', { enum: ['free', 'weekly', 'daily', 'commit', 'vibe', 'studio'] })
    .notNull()
    .default('free'),
  planStatus: text('plan_status').notNull().default('active'), // active | past_due | canceled
  stripeSubscriptionId: text('stripe_subscription_id'),
  scansUsedMonth: integer('scans_used_month').notNull().default(0),
  crawlUsedMonth: integer('crawl_used_month').notNull().default(0),
  usageMonth: text('usage_month'), // YYYY-MM
  notifyEmail: integer('notify_email', { mode: 'boolean' }).notNull().default(true),
  slackWebhookUrl: text('slack_webhook_url'),
  /** Inbox ownership — set after click-to-verify or trusted IdP emailVerified */
  emailVerifiedAt: integer('email_verified_at', { mode: 'timestamp_ms' }),
  emailVerifyToken: text('email_verify_token'),
  emailVerifyExpiresAt: integer('email_verify_expires_at', { mode: 'timestamp_ms' }),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull(),
});

export const sessions = sqliteTable('sessions', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
});

export const apiKeys = sqliteTable('api_keys', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  keyHash: text('key_hash').notNull().unique(),
  keyPrefix: text('key_prefix').notNull(), // sk_live_xxxx for display
  lastUsedAt: integer('last_used_at', { mode: 'timestamp_ms' }),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  revokedAt: integer('revoked_at', { mode: 'timestamp_ms' }),
}, (t) => [index('api_keys_user_idx').on(t.userId)]);

export const projects = sqliteTable('projects', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  url: text('url').notNull(),
  hostname: text('hostname').notNull(),
  verified: integer('verified', { mode: 'boolean' }).notNull().default(false),
  verifyToken: text('verify_token').notNull(),
  verifiedAt: integer('verified_at', { mode: 'timestamp_ms' }),
  /** How ownership was proven: dns | email */
  verifyMethod: text('verify_method'),
  policy: text('policy', { enum: ['chill', 'ship', 'client', 'launch'] }).notNull().default('ship'),
  shipCheckEnabled: integer('ship_check_enabled', { mode: 'boolean' }).notNull().default(true),
  deployWebhookSecret: text('deploy_webhook_secret').notNull(),
  githubRepo: text('github_repo'), // owner/name
  githubInstallationId: text('github_installation_id'),
  badgePublic: integer('badge_public', { mode: 'boolean' }).notNull().default(true),
  shareToken: text('share_token').notNull(),
  lastScore: integer('last_score'),
  lastGrade: text('last_grade'),
  lastScanAt: integer('last_scan_at', { mode: 'timestamp_ms' }),
  baselineJson: text('baseline_json'), // serialized failing finding ids
  /** Opt-in authenticated scans (test user session) */
  authEnabled: integer('auth_enabled', { mode: 'boolean' }).notNull().default(false),
  /** cookie | bearer | password (password stored for re-login docs; scans prefer cookie/bearer) */
  authMode: text('auth_mode'),
  authEmail: text('auth_email'),
  /** AES-GCM sealed secret (cookie, token, or password JSON) */
  authSecretEnc: text('auth_secret_enc'),
  authLoginUrl: text('auth_login_url'),
  authVerifiedAt: integer('auth_verified_at', { mode: 'timestamp_ms' }),
  authUpdatedAt: integer('auth_updated_at', { mode: 'timestamp_ms' }),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull(),
}, (t) => [
  index('projects_user_idx').on(t.userId),
  uniqueIndex('projects_user_hostname_idx').on(t.userId, t.hostname),
]);

export const projectPreviewPatterns = sqliteTable('project_preview_patterns', {
  id: text('id').primaryKey(),
  projectId: text('project_id').notNull().references(() => projects.id, { onDelete: 'cascade' }),
  pattern: text('pattern').notNull(),
  proofHost: text('proof_host').notNull(),
  verified: integer('verified', { mode: 'boolean' }).notNull().default(false),
  verifyMethod: text('verify_method'),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull(),
}, (t) => [
  uniqueIndex('preview_patterns_project_pattern_idx').on(t.projectId, t.pattern),
  index('preview_patterns_project_idx').on(t.projectId),
]);

export const scans = sqliteTable('scans', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  projectId: text('project_id').references(() => projects.id, { onDelete: 'set null' }),
  url: text('url').notNull(),
  mode: text('mode', { enum: ['lite', 'smoke', 'fast', 'full', 'crawl'] }).notNull().default('fast'),
  trigger: text('trigger', {
    enum: ['manual', 'api', 'mcp', 'deploy', 'github', 'schedule', 'rescan'],
  }).notNull().default('manual'),
  status: text('status', {
    enum: ['queued', 'running', 'completed', 'failed', 'canceled'],
  }).notNull().default('queued'),
  authorized: integer('authorized', { mode: 'boolean' }).notNull().default(false),
  score: integer('score'),
  grade: text('grade'),
  summaryJson: text('summary_json'),
  findingsJson: text('findings_json'),
  fixPackMarkdown: text('fix_pack_markdown'),
  reportHtml: text('report_html'),
  baselineDiffJson: text('baseline_diff_json'),
  error: text('error'),
  startedAt: integer('started_at', { mode: 'timestamp_ms' }),
  finishedAt: integer('finished_at', { mode: 'timestamp_ms' }),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  metaJson: text('meta_json'), // github sha, pr number, etc.
}, (t) => [
  index('scans_user_idx').on(t.userId),
  index('scans_project_idx').on(t.projectId),
  index('scans_status_idx').on(t.status),
]);

export const auditLog = sqliteTable('audit_log', {
  id: text('id').primaryKey(),
  userId: text('user_id'),
  action: text('action').notNull(),
  target: text('target'),
  detailJson: text('detail_json'),
  ip: text('ip'),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
}, (t) => [index('audit_user_idx').on(t.userId), index('audit_created_idx').on(t.createdAt)]);

export const rateLimits = sqliteTable('rate_limits', {
  key: text('key').primaryKey(),
  count: integer('count').notNull().default(0),
  windowStart: integer('window_start', { mode: 'timestamp_ms' }).notNull(),
});

// #32 — the run-ledger: one row per test run, with one test_results row per SUB-TEST (keyed by VTA number)
// so every scan is auditable ("VTA-0008 on site X: pass/fail over time") and drives the daily report.
export const testRuns = sqliteTable('test_runs', {
  id: text('id').primaryKey(),
  scanId: text('scan_id').references(() => scans.id, { onDelete: 'cascade' }),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  projectId: text('project_id').references(() => projects.id, { onDelete: 'set null' }),
  runNumber: integer('run_number'),                 // monotonic per (user, target)
  target: text('target').notNull(),
  actor: text('actor').notNull(),
  trigger: text('trigger'),
  priority: text('priority', { enum: ['critical', 'high', 'medium', 'low', 'clean'] }).notNull(),
  passed: integer('passed').notNull().default(0),
  failed: integer('failed').notNull().default(0),
  failHigh: integer('fail_high').notNull().default(0),
  failMedium: integer('fail_medium').notNull().default(0),
  failLow: integer('fail_low').notNull().default(0),
  startedAt: integer('started_at', { mode: 'timestamp_ms' }),
  finishedAt: integer('finished_at', { mode: 'timestamp_ms' }),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
}, (t) => [
  index('test_runs_user_idx').on(t.userId),
  index('test_runs_target_idx').on(t.target, t.runNumber),
  index('test_runs_project_idx').on(t.projectId),
]);

export const testResults = sqliteTable('test_results', {
  id: text('id').primaryKey(),
  runId: text('run_id').notNull().references(() => testRuns.id, { onDelete: 'cascade' }),
  vtaNumber: integer('vta_number'),                 // stable VTA test number (null if uncatalogued)
  checkId: text('check_id').notNull(),
  category: text('category'),
  severity: text('severity'),
  pass: integer('pass', { mode: 'boolean' }).notNull(),
  detail: text('detail'),
  atlas: text('atlas'),                             // comma-separated ATLAS technique ids, when applicable
}, (t) => [
  index('test_results_run_idx').on(t.runId),
  index('test_results_check_idx').on(t.checkId),
  index('test_results_vta_idx').on(t.vtaNumber),
]);

export const checkHistory = sqliteTable('check_history', {
  id: text('id').primaryKey(),
  projectId: text('project_id').notNull().references(() => projects.id, { onDelete: 'cascade' }),
  target: text('target').notNull(),
  checkId: text('check_id').notNull(),
  pass: integer('pass', { mode: 'boolean' }).notNull(),
  severity: text('severity'),
  scanId: text('scan_id'),
  deployFingerprint: text('deploy_fingerprint'),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
}, (t) => [
  index('check_history_lookup_idx').on(t.projectId, t.target, t.checkId, t.createdAt),
]);

export const quarantinedChecks = sqliteTable('quarantined_checks', {
  id: text('id').primaryKey(),
  projectId: text('project_id').notNull().references(() => projects.id, { onDelete: 'cascade' }),
  target: text('target').notNull(),
  checkId: text('check_id').notNull(),
  reason: text('reason').notNull(),
  quarantinedAt: integer('quarantined_at', { mode: 'timestamp_ms' }).notNull(),
  unquarantinedAt: integer('unquarantined_at', { mode: 'timestamp_ms' }),
  auto: integer('auto', { mode: 'boolean' }).notNull().default(true),
}, (t) => [
  index('quarantined_checks_project_idx').on(t.projectId),
]);

export type User = typeof users.$inferSelect;
export type Project = typeof projects.$inferSelect;
export type ProjectPreviewPattern = typeof projectPreviewPatterns.$inferSelect;
export type Scan = typeof scans.$inferSelect;
export type ApiKey = typeof apiKeys.$inferSelect;
export type TestRun = typeof testRuns.$inferSelect;
export type TestResult = typeof testResults.$inferSelect;
export type CheckHistoryRow = typeof checkHistory.$inferSelect;
export type QuarantinedCheck = typeof quarantinedChecks.$inferSelect;

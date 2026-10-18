/**
 * Tests for the repo secret scanning module.
 * Verifies secret detection rules, redaction, and liveness checks.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  REPO_SECRET_RULES,
  scanContent,
  redactSecret,
  isEnvFile,
  shouldSkipFile,
} from '../dist/repo-secrets.js';

// ── Secret rule coverage ─────────────────────────────────────────────────────

test('repo-secrets: REPO_SECRET_RULES covers major providers', () => {
  const ruleIds = REPO_SECRET_RULES.map(r => r.id);
  
  // Cloud providers
  assert.ok(ruleIds.includes('aws.akid'), 'should have AWS access key rule');
  assert.ok(ruleIds.includes('gcp.apikey'), 'should have GCP API key rule');
  assert.ok(ruleIds.includes('azure.connection'), 'should have Azure connection string rule');
  
  // Payment
  assert.ok(ruleIds.includes('stripe.sk_live'), 'should have Stripe live key rule');
  assert.ok(ruleIds.includes('stripe.sk_test'), 'should have Stripe test key rule');
  
  // LLM providers
  assert.ok(ruleIds.includes('openai.key'), 'should have OpenAI key rule');
  assert.ok(ruleIds.includes('anthropic.key'), 'should have Anthropic key rule');
  
  // Version control
  assert.ok(ruleIds.includes('github.pat'), 'should have GitHub PAT rule');
  assert.ok(ruleIds.includes('gitlab.pat'), 'should have GitLab PAT rule');
  
  // Communication
  assert.ok(ruleIds.includes('slack.token'), 'should have Slack token rule');
  assert.ok(ruleIds.includes('twilio.sk'), 'should have Twilio key rule');
  assert.ok(ruleIds.includes('sendgrid.key'), 'should have SendGrid key rule');
  
  // Private keys
  assert.ok(ruleIds.includes('privatekey.rsa'), 'should have RSA private key rule');
  assert.ok(ruleIds.includes('privatekey.openssh'), 'should have OpenSSH private key rule');
  
  // Database
  assert.ok(ruleIds.includes('db.postgres'), 'should have PostgreSQL connection string rule');
  assert.ok(ruleIds.includes('db.mongodb'), 'should have MongoDB connection string rule');
  
  // BaaS
  assert.ok(ruleIds.includes('supabase.service_role'), 'should have Supabase service_role rule');
  assert.ok(ruleIds.includes('firebase.server_key'), 'should have Firebase server key rule');
});

// ── Secret detection ─────────────────────────────────────────────────────────

test('repo-secrets: scanContent detects AWS access key', () => {
  const content = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE';
  const hits = scanContent(content, 'config.js');
  assert.ok(hits.length > 0, 'should detect AWS key');
  assert.equal(hits[0].ruleId, 'aws.akid');
  assert.equal(hits[0].file, 'config.js');
});

test('repo-secrets: scanContent detects Stripe live secret key', () => {
  const content = 'const stripe = Stripe("sk_live_51234567890abcdefghijklmnop");';
  const hits = scanContent(content, 'payment.ts');
  assert.ok(hits.length > 0, 'should detect Stripe key');
  assert.equal(hits[0].ruleId, 'stripe.sk_live');
});

test('repo-secrets: scanContent detects OpenAI API key', () => {
  const content = 'OPENAI_API_KEY=sk-proj-abcdefghij1234567890ABCDEFGHIJKLMNOPQRS';
  const hits = scanContent(content, '.env');
  assert.ok(hits.length > 0, 'should detect OpenAI key');
  assert.equal(hits[0].ruleId, 'openai.key');
});

test('repo-secrets: scanContent detects GitHub PAT', () => {
  const content = 'const token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";';
  const hits = scanContent(content, 'auth.js');
  assert.ok(hits.length > 0, 'should detect GitHub PAT');
  assert.equal(hits[0].ruleId, 'github.pat');
});

test('repo-secrets: scanContent detects private key block', () => {
  const content = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`;
  const hits = scanContent(content, 'id_rsa');
  assert.ok(hits.length > 0, 'should detect RSA private key');
  assert.equal(hits[0].ruleId, 'privatekey.rsa');
});

test('repo-secrets: scanContent detects PostgreSQL connection string', () => {
  const content = 'DATABASE_URL=postgres://user:password123@localhost:5432/mydb';
  const hits = scanContent(content, '.env.production');
  assert.ok(hits.length > 0, 'should detect PostgreSQL connection');
  assert.equal(hits[0].ruleId, 'db.postgres');
});

test('repo-secrets: scanContent detects Slack token', () => {
  const content = 'SLACK_TOKEN=xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx';
  const hits = scanContent(content, 'config.yaml');
  assert.ok(hits.length > 0, 'should detect Slack token');
  assert.equal(hits[0].ruleId, 'slack.token');
});

test('repo-secrets: scanContent detects SendGrid API key', () => {
  const content = 'SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
  const hits = scanContent(content, '.env');
  assert.ok(hits.length > 0, 'should detect SendGrid key');
  assert.equal(hits[0].ruleId, 'sendgrid.key');
});

test('repo-secrets: scanContent provides line numbers', () => {
  const content = `line 1
line 2
AKIAIOSFODNN7EXAMPLE
line 4`;
  const hits = scanContent(content, 'test.txt');
  assert.ok(hits.length > 0);
  assert.equal(hits[0].line, 3, 'should report correct line number');
});

test('repo-secrets: scanContent includes commit hash when provided', () => {
  const content = 'sk_live_51234567890abcdefghijklmnop';
  const hits = scanContent(content, 'config.js', 'abc123def');
  assert.ok(hits.length > 0);
  assert.equal(hits[0].commit, 'abc123def');
});

// ── Redaction ────────────────────────────────────────────────────────────────

test('repo-secrets: redactSecret hides middle of long secrets', () => {
  const secret = 'sk_live_51234567890abcdefghijklmnop';
  const redacted = redactSecret(secret);
  assert.ok(redacted.includes('…'), 'should contain ellipsis');
  assert.ok(redacted.startsWith('sk_liv'), 'should show prefix');
  assert.ok(redacted.endsWith('mnop'), 'should show suffix');
  assert.ok(redacted.length < secret.length, 'should be shorter than original');
});

test('repo-secrets: redactSecret handles short secrets', () => {
  const secret = 'abc';
  const redacted = redactSecret(secret);
  assert.equal(redacted, '***', 'very short secrets should be fully redacted');
});

test('repo-secrets: redactSecret handles medium secrets', () => {
  const secret = 'abcdefghij';
  const redacted = redactSecret(secret);
  assert.ok(redacted.includes('…'));
  assert.ok(redacted.length < secret.length);
});

// ── File filtering ───────────────────────────────────────────────────────────

test('repo-secrets: isEnvFile identifies .env files', () => {
  assert.equal(isEnvFile('.env'), true);
  assert.equal(isEnvFile('.env.local'), true);
  assert.equal(isEnvFile('.env.production'), true);
  assert.equal(isEnvFile('.env.development'), true);
  assert.equal(isEnvFile('config.js'), false);
  assert.equal(isEnvFile('package.json'), false);
});

test('repo-secrets: shouldSkipFile skips common non-code files', () => {
  assert.equal(shouldSkipFile('node_modules/lodash/index.js'), true);
  assert.equal(shouldSkipFile('.git/objects/abc'), true);
  assert.equal(shouldSkipFile('dist/bundle.min.js'), true);
  assert.equal(shouldSkipFile('package-lock.json'), true);
  assert.equal(shouldSkipFile('yarn.lock'), true);
  assert.equal(shouldSkipFile('image.png'), true);
  assert.equal(shouldSkipFile('font.woff2'), true);
});

test('repo-secrets: shouldSkipFile allows source files', () => {
  assert.equal(shouldSkipFile('src/config.ts'), false);
  assert.equal(shouldSkipFile('lib/auth.js'), false);
  assert.equal(shouldSkipFile('.env'), false);
  assert.equal(shouldSkipFile('config.yaml'), false);
});

// ── Deduplication ────────────────────────────────────────────────────────────

test('repo-secrets: scanContent deduplicates same secret on multiple lines', () => {
  const content = `AKIAIOSFODNN7EXAMPLE
some other line
AKIAIOSFODNN7EXAMPLE`;
  const hits = scanContent(content, 'test.txt');
  // Same secret in same file should be deduplicated
  assert.equal(hits.length, 1, 'should deduplicate identical secrets in same file');
});

test('repo-secrets: scanContent reports different secrets separately', () => {
  const content = `AKIAIOSFODNN7EXAMPLE
sk_live_51234567890abcdefghijklmnop`;
  const hits = scanContent(content, 'test.txt');
  // AWS key and Stripe key should both be detected
  const hasAws = hits.some(h => h.ruleId === 'aws.akid');
  const hasStripe = hits.some(h => h.ruleId === 'stripe.sk_live');
  assert.ok(hasAws && hasStripe, 'should report different secrets separately');
});

// ── Confirm functions ────────────────────────────────────────────────────────

test('repo-secrets: Supabase service_role rule only matches service_role JWTs', () => {
  // This is an anon key (role: anon) - should NOT match
  const anonKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRlc3QiLCJyb2xlIjoiYW5vbiIsImlhdCI6MTYwMDAwMDAwMCwiZXhwIjoxOTAwMDAwMDAwfQ.abc123';
  const anonHits = scanContent(`SUPABASE_KEY=${anonKey}`, 'test.txt');
  const hasServiceRole = anonHits.some(h => h.ruleId === 'supabase.service_role');
  assert.equal(hasServiceRole, false, 'should NOT match anon key');
});

// ── GAP_CHECK_CONFIG includes new checks ─────────────────────────────────────

import { GAP_CHECK_CONFIG } from '../dist/gap-checks.js';

test('repo-secrets: GAP_CHECK_CONFIG includes repo.secrets as verified-only', () => {
  assert.ok('repo.secrets' in GAP_CHECK_CONFIG, 'GAP_CHECK_CONFIG should include repo.secrets');
  assert.equal(GAP_CHECK_CONFIG['repo.secrets'].requiresVerification, true, 'repo.secrets should require verification');
});

test('repo-secrets: GAP_CHECK_CONFIG includes exposure.preview-deployments as default/passive', () => {
  assert.ok('exposure.preview-deployments' in GAP_CHECK_CONFIG, 'GAP_CHECK_CONFIG should include exposure.preview-deployments');
  assert.equal(GAP_CHECK_CONFIG['exposure.preview-deployments'].requiresVerification, false, 'exposure.preview-deployments runs by default');
});

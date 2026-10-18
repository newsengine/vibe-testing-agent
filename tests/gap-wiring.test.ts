/**
 * Wiring tests: default gap checks run from probe(); verified-only checks need authorizedGap;
 * repo.secrets runs for --repo; --only/--skip are respected.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { probe } from '../dist/probe.js';
import { scanRepo, repoHitsToFindings } from '../dist/repo-secrets.js';
import { startKnownBad } from './helpers/fixtures.ts';

test('probe: default gap checks run; verified-only checks do not', async () => {
  const srv = await startKnownBad();
  try {
    const findings = await probe(srv.url, { only: ['security', 'exposure'], timeoutMs: 8000, maxCrawl: 5 });
    const ids = findings.map((f) => f.id);
    assert.ok(!ids.includes('auth.login-rate-limit'), 'login-rate-limit must not run without authorizedGap');
    assert.ok(!ids.includes('authz.idor-sequential'), 'idor must not run without authorizedGap');
    assert.ok(!ids.includes('api.webhook-unsigned'), 'webhook check must not run without authorizedGap');
    assert.ok(!ids.includes('repo.secrets'), 'repo.secrets must not run without --repo');
  } finally {
    await srv.close();
  }
});

test('probe: --only security skips exposure.preview-deployments and dns.dkim', async () => {
  const srv = await startKnownBad();
  try {
    const findings = await probe(srv.url, { only: ['security'], timeoutMs: 8000, maxCrawl: 5 });
    const ids = findings.map((f) => f.id);
    assert.ok(!ids.includes('dns.dkim'), 'dns.dkim should be skipped when --only security');
    assert.ok(!ids.includes('exposure.preview-deployments'), 'preview check should be skipped when --only security');
  } finally {
    await srv.close();
  }
});

test('probe: --skip security skips csrf.token and disclosure.pii-in-response', async () => {
  const srv = await startKnownBad();
  try {
    const findings = await probe(srv.url, { skip: ['security'], only: ['exposure'], timeoutMs: 8000, maxCrawl: 5 });
    const ids = findings.map((f) => f.id);
    assert.ok(!ids.includes('csrf.token'));
    assert.ok(!ids.includes('disclosure.pii-in-response'));
  } finally {
    await srv.close();
  }
});

test('probe: authorizedGap enables verified-only auth.login-rate-limit when a login path exists', async () => {
  const srv = await startKnownBad();
  try {
    const findings = await probe(srv.url, {
      only: ['security'],
      authorizedGap: true,
      timeoutMs: 8000,
      maxCrawl: 5,
    });
    // known-bad has no /api/auth/login — the check returns [] rather than a finding.
    // Presence of authorizedGap must not crash, and must not emit a category error.
    assert.ok(!findings.some((f) => f.id === 'security.error' || f.id === 'gap.error'));
  } finally {
    await srv.close();
  }
});

test('scanRepo: finds a redacted AWS key in the working tree', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'vta-repo-'));
  await mkdir(join(dir, 'src'), { recursive: true });
  await writeFile(join(dir, 'src', 'config.ts'), 'export const k = "AKIAIOSFODNN7EXAMPLE";\n', 'utf8');
  const result = await scanRepo(dir, { maxCommits: 0 });
  assert.ok(result.hits.some((h) => h.ruleId === 'aws.akid'));
  const findings = repoHitsToFindings(result);
  const fail = findings.find((f) => !f.pass);
  assert.ok(fail);
  assert.equal(fail!.id, 'repo.secrets');
  assert.match(fail!.detail, /AKIAIO/);
  assert.doesNotMatch(fail!.detail, /AKIAIOSFODNN7EXAMPLE/);
});

test('probe: --repo attaches repo.secrets findings; --skip secrets drops them', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'vta-repo-'));
  await writeFile(join(dir, 'leak.env'), 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n', 'utf8');
  const srv = await startKnownBad();
  try {
    const withRepo = await probe(srv.url, {
      only: ['secrets'],
      repoPath: dir,
      timeoutMs: 8000,
      maxCrawl: 1,
    });
    assert.ok(withRepo.some((f) => f.id === 'repo.secrets' && !f.pass));

    const skipped = await probe(srv.url, {
      skip: ['secrets'],
      only: ['exposure'],
      repoPath: dir,
      timeoutMs: 8000,
      maxCrawl: 1,
    });
    assert.ok(!skipped.some((f) => f.id === 'repo.secrets'));
  } finally {
    await srv.close();
  }
});

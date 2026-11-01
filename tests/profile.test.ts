import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SMOKE_CATEGORIES,
  SMOKE_PATHS,
  SMOKE_MAX_CRAWL,
  SMOKE_TIMEOUT_MS,
  applyProfile,
  parseProfile,
  smokeCheckIds,
} from '../src/profile.ts';
test('smoke profile is a passive subset of security, secrets, exposure', () => {
  assert.deepEqual(SMOKE_CATEGORIES, ['security', 'secrets', 'exposure']);
  assert.ok(!SMOKE_CATEGORIES.includes('atlas'));
  assert.ok(!SMOKE_CATEGORIES.includes('plugins'));
  assert.ok(!SMOKE_CATEGORIES.includes('appstyle'));
  assert.ok(!SMOKE_CATEGORIES.includes('dns'));
});

test('smoke profile hits a small configurable path set', () => {
  assert.ok(SMOKE_PATHS.includes('/'));
  assert.ok(SMOKE_PATHS.includes('/health') || SMOKE_PATHS.includes('/api/health'));
  assert.ok(SMOKE_PATHS.length <= 8);
  assert.ok(SMOKE_MAX_CRAWL <= 8);
  assert.ok(SMOKE_TIMEOUT_MS <= 8_000);
});

test('applyProfile(smoke) disables intrusive opt-ins and sets only+bounds', () => {
  const opts = applyProfile('smoke', { retries: 1 });
  assert.deepEqual(opts.only, SMOKE_CATEGORIES);
  assert.equal(opts.maxCrawl, SMOKE_MAX_CRAWL);
  assert.equal(opts.timeoutMs, SMOKE_TIMEOUT_MS);
  assert.equal(opts.apiWrite, false);
  assert.equal(opts.rateLimitScan, false);
  assert.equal(opts.reflectedXss, false);
  assert.equal(opts.aiProbe, false);
  assert.equal(opts.authorizedActive, false);
  assert.equal(opts.retries, 1);
  assert.deepEqual(opts.smokePaths, SMOKE_PATHS);
});

test('applyProfile(full) does not restrict categories', () => {
  const opts = applyProfile('full', { only: ['dns'] });
  assert.deepEqual(opts.only, ['dns']);
  assert.equal(opts.profile, 'full');
  assert.equal(opts.authorizedActive, undefined);
});

test('explicit only/skip/timeout override smoke defaults', () => {
  const opts = applyProfile('smoke', { only: ['secrets'], timeoutMs: 3_000, maxCrawl: 2 });
  assert.deepEqual(opts.only, ['secrets']);
  assert.equal(opts.timeoutMs, 3_000);
  assert.equal(opts.maxCrawl, 2);
});

test('parseProfile accepts smoke|full and rejects junk', () => {
  assert.equal(parseProfile(undefined), 'full');
  assert.equal(parseProfile('smoke'), 'smoke');
  assert.equal(parseProfile('full'), 'full');
  assert.equal(parseProfile('lite'), null);
  assert.equal(parseProfile('nope'), null);
});

test('smokeCheckIds enumerates categories and key paths', () => {
  const ids = smokeCheckIds();
  assert.ok(ids.includes('category:security'));
  assert.ok(ids.includes('category:secrets'));
  assert.ok(ids.includes('category:exposure'));
  assert.ok(ids.includes('smoke.path/'));
  assert.ok(ids.includes('smoke.path/robots.txt'));
  assert.ok(!ids.some((id) => id.startsWith('category:atlas')));
});

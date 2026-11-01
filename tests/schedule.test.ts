import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  dueForScheduledCrawl,
  scheduledModeForPlan,
  webhookScanMode,
  NIGHTLY_FLOOR_HOURS,
} from '../vibetesting-agent/src/lib/schedule-policy.ts';

test('scheduledModeForPlan prefers crawl then full', () => {
  assert.equal(scheduledModeForPlan(['lite', 'smoke']), null);
  assert.equal(scheduledModeForPlan(['lite', 'full']), 'full');
  assert.equal(scheduledModeForPlan(['lite', 'full', 'crawl']), 'crawl');
});

test('dueForScheduledCrawl requires verified + cadence plan', () => {
  const base = {
    verified: true,
    planModes: ['lite', 'smoke', 'fast', 'full'] as const,
    minHoursBetweenScans: 20,
    lastScheduledAtMs: null as number | null,
    nowMs: 1_000_000_000_000,
  };
  assert.equal(dueForScheduledCrawl({ ...base }), true);
  assert.equal(dueForScheduledCrawl({ ...base, verified: false }), false);
  assert.equal(dueForScheduledCrawl({ ...base, planModes: ['lite', 'smoke'] }), false);
});

test('dueForScheduledCrawl uses cadence window and 20h floor for commit', () => {
  const now = 1_000_000_000_000;
  const recent = now - 2 * 3_600_000;
  assert.equal(
    dueForScheduledCrawl({
      verified: true,
      planModes: ['full', 'crawl'],
      minHoursBetweenScans: 0,
      lastScheduledAtMs: recent,
      nowMs: now,
    }),
    false,
  );
  const old = now - (NIGHTLY_FLOOR_HOURS + 1) * 3_600_000;
  assert.equal(
    dueForScheduledCrawl({
      verified: true,
      planModes: ['full', 'crawl'],
      minHoursBetweenScans: 0,
      lastScheduledAtMs: old,
      nowMs: now,
    }),
    true,
  );
  const weeklyRecent = now - 30 * 3_600_000;
  assert.equal(
    dueForScheduledCrawl({
      verified: true,
      planModes: ['full'],
      minHoursBetweenScans: 144,
      lastScheduledAtMs: weeklyRecent,
      nowMs: now,
    }),
    false,
  );
});

test('webhookScanMode is smoke on preview hosts, full/crawl on production', () => {
  assert.equal(
    webhookScanMode({ policy: 'ship', projectHostname: 'app.example.com', targetHostname: 'pr-1.preview.example.com' }),
    'smoke',
  );
  assert.equal(
    webhookScanMode({ policy: 'ship', projectHostname: 'app.example.com', targetHostname: 'app.example.com' }),
    'full',
  );
  assert.equal(
    webhookScanMode({ policy: 'launch', projectHostname: 'app.example.com', targetHostname: 'app.example.com' }),
    'crawl',
  );
});

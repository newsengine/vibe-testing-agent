import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  countFlips,
  sameDeployWindow,
  consecutiveHighFails,
  evaluateFlaky,
  applyQuarantine,
  recordScanOutcomes,
  emptyQuarantineFile,
  isQuarantined,
  FLAKY_WINDOW_SCANS,
} from '../src/quarantine.ts';
import { gateableFindings } from '../src/retry.ts';
import type { Finding } from '../src/types.ts';
import type { CheckOutcome } from '../src/quarantine.ts';

function outcome(pass: boolean, extra: Partial<CheckOutcome> = {}): CheckOutcome {
  return {
    checkId: 'header.csp',
    target: 'https://app.example.com',
    pass,
    severity: extra.severity ?? 'medium',
    at: extra.at ?? '2026-01-01T00:00:00.000Z',
    deployFingerprint: extra.deployFingerprint ?? 'sha-a',
    ...extra,
  };
}

test('countFlips counts pass/fail transitions', () => {
  assert.equal(countFlips([outcome(true), outcome(true), outcome(true)]), 0);
  assert.equal(countFlips([outcome(true), outcome(false), outcome(true)]), 2);
  assert.equal(countFlips([outcome(false), outcome(true)]), 1);
});

test('sameDeployWindow is false when fingerprint changes', () => {
  assert.equal(sameDeployWindow([outcome(true), outcome(false)]), true);
  assert.equal(
    sameDeployWindow([outcome(true, { deployFingerprint: 'a' }), outcome(false, { deployFingerprint: 'b' })]),
    false,
  );
});

test('evaluateFlaky: flips on same target with no deploy change', () => {
  const history = [outcome(true), outcome(false), outcome(true)];
  const v = evaluateFlaky(history);
  assert.equal(v.flaky, true);
  assert.match(v.reason, /flipped 2/);
});

test('evaluateFlaky: deploy change is not flake', () => {
  const history = [
    outcome(true, { deployFingerprint: 'a' }),
    outcome(false, { deployFingerprint: 'b' }),
    outcome(true, { deployFingerprint: 'c' }),
  ];
  assert.equal(evaluateFlaky(history).flaky, false);
});

test('evaluateFlaky: never auto-quarantine two consecutive high fails', () => {
  const history = [
    outcome(true, { severity: 'high' }),
    outcome(false, { severity: 'high' }),
    outcome(false, { severity: 'high' }),
  ];
  const v = evaluateFlaky(history);
  assert.equal(v.flaky, false);
  assert.match(v.reason, /high-severity/);
});

test('evaluateFlaky: need at least 3 outcomes in the window', () => {
  assert.equal(evaluateFlaky([outcome(true), outcome(false)]).flaky, false);
  assert.equal(FLAKY_WINDOW_SCANS, 5);
});

test('consecutiveHighFails only looks at the last two outcomes', () => {
  assert.equal(
    consecutiveHighFails([
      outcome(false, { severity: 'high' }),
      outcome(false, { severity: 'high' }),
    ]),
    true,
  );
  assert.equal(
    consecutiveHighFails([
      outcome(false, { severity: 'medium' }),
      outcome(false, { severity: 'high' }),
    ]),
    false,
  );
});

test('recordScanOutcomes quarantines a flipping check and applyQuarantine labels it', () => {
  const target = 'https://app.example.com';
  const fail: Finding = {
    id: 'header.csp',
    category: 'security',
    title: 'Missing CSP',
    severity: 'medium',
    pass: false,
    detail: 'missing',
  };
  const pass: Finding = { ...fail, pass: true, title: 'CSP present' };
  let file = emptyQuarantineFile();
  file = recordScanOutcomes(file, [pass], target, 'sha-a', 't1');
  file = recordScanOutcomes(file, [fail], target, 'sha-a', 't2');
  file = recordScanOutcomes(file, [pass], target, 'sha-a', 't3');
  assert.equal(isQuarantined(file, 'header.csp', target), true);

  const labeled = applyQuarantine([{ ...fail }], file, target);
  assert.equal(labeled[0].quarantined, true);
  assert.match(labeled[0].title, /\[quarantined\]/);
  assert.deepEqual(gateableFindings(labeled).map((f) => f.id), []);
});

test('recordScanOutcomes does not quarantine two consecutive highs', () => {
  const target = 'https://app.example.com';
  const fail: Finding = {
    id: 'secret.stripe',
    category: 'secrets',
    title: 'Stripe key',
    severity: 'high',
    pass: false,
    detail: 'hit',
  };
  const pass: Finding = { ...fail, pass: true };
  let file = emptyQuarantineFile();
  file = recordScanOutcomes(file, [pass], target, 'sha-a', 't1');
  file = recordScanOutcomes(file, [fail], target, 'sha-a', 't2');
  file = recordScanOutcomes(file, [fail], target, 'sha-a', 't3');
  assert.equal(isQuarantined(file, 'secret.stripe', target), false);
});

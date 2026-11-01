/** Same heuristic as OSS `src/quarantine.ts` — keep in lockstep. */
export const FLAKY_WINDOW_SCANS = 5;
export const FLAKY_MIN_FLIPS = 2;

export interface CheckOutcome {
  checkId: string;
  target: string;
  pass: boolean;
  severity: string;
  at: string;
  deployFingerprint?: string | null;
}

export function countFlips(history: CheckOutcome[]): number {
  let flips = 0;
  for (let i = 1; i < history.length; i++) {
    if (history[i].pass !== history[i - 1].pass) flips++;
  }
  return flips;
}

export function sameDeployWindow(history: CheckOutcome[]): boolean {
  if (!history.length) return true;
  const first = history[0].deployFingerprint ?? '';
  return history.every((h) => (h.deployFingerprint ?? '') === first);
}

export function consecutiveHighFails(history: CheckOutcome[]): boolean {
  if (history.length < 2) return false;
  const a = history[history.length - 2];
  const b = history[history.length - 1];
  return !a.pass && !b.pass && a.severity === 'high' && b.severity === 'high';
}

export function evaluateFlaky(history: CheckOutcome[]): { flaky: boolean; reason: string } {
  const slice = history.slice(-FLAKY_WINDOW_SCANS);
  if (slice.length < 3) return { flaky: false, reason: 'insufficient history (need 3 outcomes)' };
  if (consecutiveHighFails(slice)) {
    return { flaky: false, reason: 'two consecutive high-severity failures are never auto-quarantined' };
  }
  const flips = countFlips(slice);
  if (flips < FLAKY_MIN_FLIPS) return { flaky: false, reason: `only ${flips} flip(s); need ${FLAKY_MIN_FLIPS}` };
  if (!sameDeployWindow(slice)) return { flaky: false, reason: 'deploy or config changed between results' };
  return {
    flaky: true,
    reason: `result flipped ${flips} times on the same target with no deploy/config change`,
  };
}

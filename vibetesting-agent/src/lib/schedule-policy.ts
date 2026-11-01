/**
 * Pure cadence / webhook-mode policy. Kept free of DB so root tests can import it.
 * See schedule.ts for the nightly enqueue that uses this.
 */

export const NIGHTLY_FLOOR_HOURS = 20;

export type CadenceScanMode = 'lite' | 'smoke' | 'fast' | 'full' | 'crawl';

export function scheduledModeForPlan(modes: readonly CadenceScanMode[]): CadenceScanMode | null {
  if (modes.includes('crawl')) return 'crawl';
  if (modes.includes('full')) return 'full';
  return null;
}

export function dueForScheduledCrawl(input: {
  verified: boolean;
  planModes: readonly CadenceScanMode[];
  minHoursBetweenScans: number;
  lastScheduledAtMs: number | null;
  nowMs?: number;
}): boolean {
  if (!input.verified) return false;
  if (!scheduledModeForPlan(input.planModes)) return false;
  const windowH = Math.max(input.minHoursBetweenScans, NIGHTLY_FLOOR_HOURS);
  if (!input.lastScheduledAtMs) return true;
  const now = input.nowMs ?? Date.now();
  return (now - input.lastScheduledAtMs) / 3_600_000 >= windowH;
}

/** Preview webhook URLs get a smoke scan; production follows project policy. */
export function webhookScanMode(input: {
  policy: string;
  projectHostname: string;
  targetHostname: string;
}): CadenceScanMode {
  if (input.targetHostname.toLowerCase() !== input.projectHostname.toLowerCase()) {
    return 'smoke';
  }
  return input.policy === 'launch' ? 'crawl' : 'full';
}

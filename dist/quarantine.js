// Flaky-check quarantine.
//
// Heuristic (documented, deliberately simple):
//   A check is flaky when, on the same target, its pass/fail result flips at
//   least twice within the last FLAKY_WINDOW_SCANS outcomes AND those outcomes
//   share the same deploy/config fingerprint (no deploy or config change
//   between them). Quarantined checks still run and are reported, but they
//   do not gate (`--fail-on`, GitHub check-run conclusion).
//
// Never auto-quarantine a check that produced a high-severity finding twice
// in a row — that is a real regression, not flake.
import { readFileSync, writeFileSync } from 'node:fs';
export const FLAKY_WINDOW_SCANS = 5;
export const FLAKY_MIN_FLIPS = 2;
export const QUARANTINE_FILE_VERSION = 1;
export function emptyQuarantineFile() {
    return { version: QUARANTINE_FILE_VERSION, windowScans: FLAKY_WINDOW_SCANS, entries: [] };
}
export function countFlips(history) {
    let flips = 0;
    for (let i = 1; i < history.length; i++) {
        if (history[i].pass !== history[i - 1].pass)
            flips++;
    }
    return flips;
}
export function sameDeployWindow(history) {
    if (!history.length)
        return true;
    const first = history[0].deployFingerprint ?? '';
    return history.every((h) => (h.deployFingerprint ?? '') === first);
}
export function consecutiveHighFails(history) {
    if (history.length < 2)
        return false;
    const a = history[history.length - 2];
    const b = history[history.length - 1];
    return !a.pass && !b.pass && a.severity === 'high' && b.severity === 'high';
}
export function evaluateFlaky(history, window = FLAKY_WINDOW_SCANS) {
    const slice = history.slice(-window);
    if (slice.length < 3)
        return { flaky: false, reason: 'insufficient history (need 3 outcomes)' };
    if (consecutiveHighFails(slice)) {
        return { flaky: false, reason: 'two consecutive high-severity failures are never auto-quarantined' };
    }
    const flips = countFlips(slice);
    if (flips < FLAKY_MIN_FLIPS)
        return { flaky: false, reason: `only ${flips} flip(s); need ${FLAKY_MIN_FLIPS}` };
    if (!sameDeployWindow(slice))
        return { flaky: false, reason: 'deploy or config changed between results' };
    return {
        flaky: true,
        reason: `result flipped ${flips} times on the same target with no deploy/config change`,
    };
}
export function entryKey(checkId, target) {
    return `${target}::${checkId}`;
}
export function loadQuarantineFile(path) {
    try {
        const raw = JSON.parse(readFileSync(path, 'utf8'));
        if (!raw || raw.version !== 1 || !Array.isArray(raw.entries))
            return emptyQuarantineFile();
        return raw;
    }
    catch (e) {
        const err = e;
        if (err?.code === 'ENOENT')
            return emptyQuarantineFile();
        throw e;
    }
}
export function saveQuarantineFile(path, file) {
    writeFileSync(path, JSON.stringify(file, null, 2) + '\n');
}
export function isQuarantined(file, checkId, target) {
    return file.entries.some((e) => e.checkId === checkId && e.target === target && Boolean(e.quarantinedAt));
}
export function applyQuarantine(findings, file, target) {
    return findings.map((f) => {
        if (!isQuarantined(file, f.id, target))
            return f;
        return {
            ...f,
            quarantined: true,
            title: f.title.startsWith('[quarantined]') ? f.title : `[quarantined] ${f.title}`,
        };
    });
}
export function recordScanOutcomes(file, findings, target, deployFingerprint, now = new Date().toISOString()) {
    const next = {
        version: 1,
        windowScans: file.windowScans || FLAKY_WINDOW_SCANS,
        entries: file.entries.map((e) => ({ ...e, history: [...e.history] })),
    };
    const byKey = new Map(next.entries.map((e) => [entryKey(e.checkId, e.target), e]));
    for (const f of findings) {
        if (f.inconclusive)
            continue;
        const key = entryKey(f.id, target);
        let entry = byKey.get(key);
        if (!entry) {
            entry = { checkId: f.id, target, reason: '', quarantinedAt: '', history: [] };
            byKey.set(key, entry);
            next.entries.push(entry);
        }
        entry.history.push({
            checkId: f.id,
            target,
            pass: f.pass,
            severity: f.severity,
            at: now,
            deployFingerprint: deployFingerprint ?? '',
        });
        if (entry.history.length > FLAKY_WINDOW_SCANS) {
            entry.history = entry.history.slice(-FLAKY_WINDOW_SCANS);
        }
        const verdict = evaluateFlaky(entry.history, next.windowScans);
        if (verdict.flaky && !entry.quarantinedAt) {
            entry.reason = verdict.reason;
            entry.quarantinedAt = now;
        }
    }
    // Drop entries that were never quarantined and have no recent history
    next.entries = next.entries.filter((e) => e.quarantinedAt || e.history.length);
    return next;
}
export function unquarantine(file, checkId, target) {
    return {
        ...file,
        entries: file.entries.filter((e) => !(e.checkId === checkId && e.target === target)),
    };
}
export function quarantinedEntries(file) {
    return file.entries.filter((e) => Boolean(e.quarantinedAt));
}

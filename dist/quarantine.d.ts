import type { Finding, Severity } from './types.js';
export declare const FLAKY_WINDOW_SCANS = 5;
export declare const FLAKY_MIN_FLIPS = 2;
export declare const QUARANTINE_FILE_VERSION: 1;
export interface CheckOutcome {
    checkId: string;
    target: string;
    pass: boolean;
    severity: Severity;
    at: string;
    /** git sha, config hash, or empty when unknown / unchanged */
    deployFingerprint?: string | null;
}
export interface QuarantineEntry {
    checkId: string;
    target: string;
    reason: string;
    quarantinedAt: string;
    history: CheckOutcome[];
}
export interface QuarantineFile {
    version: typeof QUARANTINE_FILE_VERSION;
    windowScans: number;
    entries: QuarantineEntry[];
}
export declare function emptyQuarantineFile(): QuarantineFile;
export declare function countFlips(history: CheckOutcome[]): number;
export declare function sameDeployWindow(history: CheckOutcome[]): boolean;
export declare function consecutiveHighFails(history: CheckOutcome[]): boolean;
export declare function evaluateFlaky(history: CheckOutcome[], window?: number): {
    flaky: boolean;
    reason: string;
};
export declare function entryKey(checkId: string, target: string): string;
export declare function loadQuarantineFile(path: string): QuarantineFile;
export declare function saveQuarantineFile(path: string, file: QuarantineFile): void;
export declare function isQuarantined(file: QuarantineFile, checkId: string, target: string): boolean;
export declare function applyQuarantine<T extends Finding>(findings: T[], file: QuarantineFile, target: string): T[];
export declare function recordScanOutcomes(file: QuarantineFile, findings: Finding[], target: string, deployFingerprint?: string | null, now?: string): QuarantineFile;
export declare function unquarantine(file: QuarantineFile, checkId: string, target: string): QuarantineFile;
export declare function quarantinedEntries(file: QuarantineFile): QuarantineEntry[];

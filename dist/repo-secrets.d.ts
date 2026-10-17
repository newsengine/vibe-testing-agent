import type { Severity } from './types.js';
export interface RepoSecretRule {
    id: string;
    name: string;
    severity: Severity;
    re: RegExp;
    confirm?: (match: string, context: string) => boolean;
}
export declare const REPO_SECRET_RULES: RepoSecretRule[];
export interface RepoSecretHit {
    ruleId: string;
    name: string;
    severity: Severity;
    file: string;
    commit?: string;
    line?: number;
    redactedValue: string;
}
export interface RepoScanResult {
    hits: RepoSecretHit[];
    filesScanned: number;
    commitsScanned: number;
    errors: string[];
}
export declare function redactSecret(value: string): string;
export declare function scanContent(content: string, filePath: string, commit?: string): RepoSecretHit[];
export interface LivenessCheck {
    ruleId: string;
    endpoint: string;
    method: 'GET' | 'POST';
    headers?: Record<string, string>;
    parseKey: (match: string) => string | null;
    isValid: (response: Response, body: string) => boolean;
}
export declare const LIVENESS_CHECKS: LivenessCheck[];
export type LivenessResult = 'valid' | 'invalid' | 'unknown' | 'error';
export declare function checkLiveness(ruleId: string, secretValue: string, timeoutMs?: number): Promise<LivenessResult>;
export declare function isEnvFile(filePath: string): boolean;
export declare function shouldSkipFile(filePath: string): boolean;

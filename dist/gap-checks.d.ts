import type { Finding, ScanContext } from './types.js';
/**
 * auth.login-rate-limit: A few bad login attempts to see if 429 or lockout kicks in.
 * Non-destructive: only 5 failed attempts with garbage credentials.
 */
export declare function authLoginRateLimitCheck(ctx: ScanContext): Promise<Finding[]>;
/**
 * auth.reset-token-reuse: Check if a password reset link can be reused.
 * We can't actually test this without a real reset flow, but we check for common insecure patterns
 * in reset endpoints. This is a placeholder that returns a pass if we can't detect insecurity.
 */
export declare function authResetTokenReuseCheck(_ctx: ScanContext): Promise<Finding[]>;
/**
 * auth.session-invalidation: Placeholder for session invalidation check.
 * Requires authenticated session to test properly.
 */
export declare function authSessionInvalidationCheck(_ctx: ScanContext): Promise<Finding[]>;
/**
 * auth.email-plus-alias: Check if the app handles email plus-addressing correctly.
 * Tests signup/login endpoints for email normalization issues.
 */
export declare function authEmailPlusAliasCheck(_ctx: ScanContext): Promise<Finding[]>;
/**
 * authz.idor-sequential: Check for obvious sequential ID IDOR.
 * Looks for patterns where incrementing an ID returns different user data.
 */
export declare function authzIdorSequentialCheck(ctx: ScanContext): Promise<Finding[]>;
/**
 * api.webhook-unsigned: Check if webhook endpoints accept unsigned payloads.
 * Sends a minimal unsigned payload to common webhook paths.
 */
export declare function apiWebhookUnsignedCheck(ctx: ScanContext): Promise<Finding[]>;
/**
 * api.idempotency: Check if POST endpoints handle duplicate requests idempotently.
 * This is a placeholder - full check requires authenticated session.
 */
export declare function apiIdempotencyCheck(_ctx: ScanContext): Promise<Finding[]>;
/**
 * api.key-revocation: Placeholder for checking if revoked API keys are rejected.
 * Requires test fixtures with revoked keys.
 */
export declare function apiKeyRevocationCheck(_ctx: ScanContext): Promise<Finding[]>;
/**
 * agent.prompt-injection: Check for prompt injection vulnerabilities.
 * Extended version of the ATLAS check for owned apps.
 */
export declare function agentPromptInjectionCheck(_ctx: ScanContext): Promise<Finding[]>;
/**
 * agent.llm-data-leak: Check if LLM endpoints leak other users' data.
 */
export declare function agentLlmDataLeakCheck(_ctx: ScanContext): Promise<Finding[]>;
/**
 * agent.llm-rate-limit: Check rate limiting on LLM endpoints.
 */
export declare function agentLlmRateLimitCheck(_ctx: ScanContext): Promise<Finding[]>;
/**
 * upload.content-type: Check if uploads are served with correct content-type and disposition.
 */
export declare function uploadContentTypeCheck(_ctx: ScanContext): Promise<Finding[]>;
/**
 * db.firebase-rules / storage.public-bucket: Check for misconfigured Firebase/Supabase storage.
 * Read-only probe for public listing/access.
 */
export declare function dbFirebaseRulesCheck(ctx: ScanContext): Promise<Finding[]>;
/**
 * dns.dkim: Check for DKIM records on common selectors.
 * Passive DNS lookup - safe for unverified targets.
 */
export declare function dnsDkimCheck(ctx: ScanContext): Promise<Finding[]>;
/**
 * csrf.token: Check for CSRF tokens on state-changing forms.
 * Passive HTML analysis - safe for unverified targets.
 */
export declare function csrfTokenCheck(ctx: ScanContext): Promise<Finding[]>;
/**
 * disclosure.pii-in-response: Check for PII patterns in API responses.
 * Passive regex scan - safe for unverified targets.
 */
export declare function disclosurePiiInResponseCheck(ctx: ScanContext): Promise<Finding[]>;
export interface GapCheckConfig {
    requiresVerification: boolean;
}
export declare const GAP_CHECK_CONFIG: Record<string, GapCheckConfig>;
export declare function isPassiveCheck(checkId: string): boolean;
/**
 * Run all gap analysis checks. For unverified projects, only passive checks run.
 */
export declare function gapChecks(ctx: ScanContext, verified: boolean): Promise<Finding[]>;

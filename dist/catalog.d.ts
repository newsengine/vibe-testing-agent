import type { Category, Severity } from './types.js';
/**
 * How a check reaches its verdict — this is what "not just a black box" means in practice: every check
 * declares whether it merely reads the one homepage response, makes extra safe GETs, sends a crafted/
 * active probe, needs a logged-in session, or is a white-box helper that needs source/tokens/two accounts.
 */
export type CheckClass = 'passive' | 'probe' | 'active' | 'authenticated' | 'white-box';
export interface CheckSpec {
    /** Stable finding id, or — when `dynamic` — the id prefix the engine appends a target to. */
    id: string;
    category: Category | 'testkit';
    /** Short human name for the catalog. */
    title: string;
    /** Typical severity when it fails (some vary at runtime by context). */
    severity: Severity;
    cls: CheckClass;
    /** Needs an explicit flag/option to run at all (off by default). */
    optIn?: boolean;
    /** The id is a family prefix — real findings look like `${id}${target}`. */
    dynamic?: boolean;
    /** Package version the check first shipped in (best-effort). */
    since: string;
    /** MITRE ATLAS technique id(s) this check maps to, when it targets an AI/ML attack (e.g. AML.T0051). */
    atlas?: string[];
    /** One line: what it detects and why it matters. */
    description: string;
}
export declare const CATALOG: CheckSpec[];
/** Exact-match first, then the longest `dynamic` family prefix the id starts with. */
export declare function catalogEntryFor(id: string): CheckSpec | undefined;
/** Every id/family the scanner (non-testkit) is expected to be able to emit. */
export declare function scannerSpecs(): CheckSpec[];
/** The stable integer for a check id or family (exact, else longest dynamic-family prefix). undefined if unnumbered. */
export declare function vtaNumber(id: string): number | undefined;
/** The display code for a check id, e.g. `VTA-0007`. Falls back to `VTA-????` for anything unnumbered. */
export declare function vtaCode(id: string): string;
/**
 * Assign numbers to a list of catalog ids given the existing registry: keeps every existing number,
 * appends the next integer for any new id (append-only, never reusing a retired number). Deterministic —
 * used by `npm run catalog` to update src/catalog-numbers.ts and by the drift test to detect a stale registry.
 */
export declare function assignNumbers(ids: string[], existing?: Record<string, number>): Record<string, number>;
/** Serialize a numbering registry to the exact contents of src/catalog-numbers.ts (deterministic). */
export declare function renderCatalogNumbers(map: Record<string, number>): string;
/** Render docs/CHECKS.md from the catalog. Kept deterministic so a drift test can compare byte-for-byte. */
export declare function renderCatalogMarkdown(): string;

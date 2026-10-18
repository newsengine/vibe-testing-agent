// src/types.ts
// Shared types for the comprehensive black-box scan. Every check returns Finding[]; the CLI groups
// them by category and turns the worst severities into an exit code so CI gates on real problems.

export type Severity = 'high' | 'medium' | 'low' | 'info';

/** Buckets a vibe coder actually cares about: "is it broken / leaking / unfindable / slow?". */
export type Category =
  | 'security'     // headers, TLS, CORS, cookies
  | 'secrets'      // API keys / private keys / source leaked to the browser
  | 'exposure'     // .env / .git / config / debug endpoints reachable
  | 'dns'          // SPF/DMARC email hygiene, CAA, dangling-CNAME takeover
  | 'reliability'  // broken links/images, 500s, stack-trace leaks, mixed content
  | 'seo'          // title/description/canonical/robots/sitemap
  | 'a11y'         // lang, alt text, labels, viewport
  | 'performance'  // compression, caching, page weight
  | 'agent'        // agent-readiness: llms.txt, AI-crawler policy, SSR content, structured data
  | 'framework'    // stack-specific misconfigs (Next.js/WordPress/Laravel/Django/Rails/Spring/ASP.NET)
  | 'components'   // OWASP A06: vulnerable/outdated client-side JS libraries (retire.js-style)
  | 'host'         // passive infra intel: resolved IP(s), reverse DNS, CDN/hosting provider (no scanning)
  | 'appstyle'     // business-archetype rules: detects the app TYPE and runs that type's extra checks
  | 'atlas'        // MITRE ATLAS: AI/LLM attack surface (inference/model/prompt-injection/cost-DoS)
  | 'plugins';     // user-supplied JSON templates (Nuclei-style declarative checks) run by src/plugins.ts

export interface Finding {
  id: string;
  category: Category;
  title: string;
  severity: Severity;
  pass: boolean;
  detail: string;
  /** Optional one-line "how to fix" aimed at a non-expert. */
  fix?: string;
}

export interface ScanOptions {
  /** Path expected to hold security.txt (default /.well-known/security.txt). */
  securityTxtPath?: string;
  /** An API path to test CORS reflection against. */
  corsTestPath?: string;
  /** Opt-in: a path to burst-test for rate limiting (sends ~25 quick requests; expects a 429). */
  rateLimitPath?: string;
  /** Treat CSP-Report-Only as a pass (apps mid-rollout). */
  allowReportOnlyCsp?: boolean;
  /** Only run these categories (default: all). */
  only?: Category[];
  /** Skip these categories. */
  skip?: Category[];
  /** Max same-origin links/images/scripts to fetch when checking for breakage (default 25). */
  maxCrawl?: number;
  /** Per-request network timeout in ms (default 10000). Guards against sites that never respond. */
  timeoutMs?: number;
  /** Directory of user JSON plugin templates for the `plugins` category (default ./vibetesting-agent-plugins). */
  pluginsDir?: string;
  /** Extra headers (e.g. Cookie / Authorization) sent ONLY on same-origin requests, so the scan can
   *  reach pages behind login. Never attached to the attack-probe requests (CORS/open-redirect) or any
   *  cross-origin fetch, to avoid leaking your session to a third party. */
  extraHeaders?: Record<string, string>;
  /** Opt-in (#24): send a benign unauthenticated POST to write-suggestive API routes and flag any 2xx.
   *  Non-destructive (no-op body, destructive verbs skipped) but off by default so the scan stays quiet. */
  apiWrite?: boolean;
  /** Opt-in (#24): autonomously burst discovered expensive /api/* routes (~15 requests each) and expect
   *  a 429. Off by default — bursting is louder than a plain GET. */
  rateLimitScan?: boolean;
  /** Opt-in (#24): probe public query params with an inert marker and flag unencoded reflection
   *  (reflected XSS / HTML injection). Off by default — this actively injects a (non-executing) payload. */
  reflectedXss?: boolean;
  /** Opt-in (ATLAS): send a benign canary prompt-injection probe to a detected chat/LLM endpoint
   *  (AML.T0051). Off by default — it POSTs an (inert) instruction to the model. */
  aiProbe?: boolean;
  /** Opt-in + AUTHORIZED (#43): run the active injection engine (SQLi/SSTI/cmd/traversal) over discovered
   *  GET parameters. Off by default; non-destructive (GET only, no writes/DoS/brute-force). Only enable on
   *  targets you own or are explicitly authorized to test. */
  authorizedActive?: boolean;
  /** Opt-in + AUTHORIZED: run verified-only gap checks (login rate-limit, IDOR, unsigned webhooks, etc.).
   *  Off by default. CLI: `--authorized-gap` (also implied by `--authorized-active`). Hosted: set when
   *  the project is ownership-verified. */
  authorizedGap?: boolean;
  /** Hosted-scan flag: project ownership is verified. Enables the same verified-only gap checks as
   *  `authorizedGap`. */
  verified?: boolean;
  /** Local path or git working tree for the opt-in `repo.secrets` scan (`--repo <path>`). */
  repoPath?: string;
}

/** Shared, fetched-once context handed to every check so we hit the homepage a single time. */
export interface ScanContext {
  baseUrl: string;
  origin: string;
  url: URL;
  /** The main document response (null if unreachable). */
  res: Response | null;
  /** The main document HTML (empty string if unreachable / non-HTML). */
  html: string;
  headers: Headers;
  opts: ScanOptions;
  /** Frameworks/platforms fingerprinted from the homepage (populated by the scanner; used by the
   *  `framework` category and available for reporting). */
  stacks?: import('./detect.js').StackSignal[];
}

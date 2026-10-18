/**
 * VibeTesting Agent — hosted plan entitlements.
 *
 * Free: lite public scan (homepage) + limited API
 * Casual Coding ($25): 1 full scan / week
 * Business Prototyping ($100): 1 full scan / day
 * Mission Critical ($250): scan on every commit/deploy webhook
 */

export type PlanId = 'free' | 'weekly' | 'daily' | 'commit';
export type ScanMode = 'lite' | 'fast' | 'full' | 'crawl';
export type Policy = 'chill' | 'ship' | 'client' | 'launch';

export interface PlanLimits {
  id: PlanId;
  name: string;
  priceMonthlyUsd: number;
  tagline: string;
  /** Max verified projects */
  maxProjects: number;
  /** Full scans allowed per calendar month (soft quota) */
  scansPerMonth: number;
  /** Minimum hours between scheduled full scans (enforced) */
  minHoursBetweenScans: number;
  crawlPerMonth: number;
  retentionDays: number;
  deployHooks: boolean;
  commitHooks: boolean;
  githubApp: boolean;
  mcp: boolean;
  sharePermanent: boolean;
  badge: boolean;
  slack: boolean;
  modes: ScanMode[];
  /** Require domain-email or DNS ownership proof before any non-lite scan */
  requireOwnership: boolean;
}

export const PLANS: Record<PlanId, PlanLimits> = {
  free: {
    id: 'free',
    name: 'Lite',
    priceMonthlyUsd: 0,
    tagline: 'Public homepage lite scan — tease the full suite',
    // Allow one project so ownership setup works before paid full scans
    maxProjects: 1,
    scansPerMonth: 5, // lite only
    minHoursBetweenScans: 1,
    crawlPerMonth: 0,
    retentionDays: 1,
    deployHooks: false,
    commitHooks: false,
    githubApp: false,
    mcp: false,
    sharePermanent: false,
    badge: false,
    slack: false,
    modes: ['lite'],
    requireOwnership: false,
  },
  weekly: {
    id: 'weekly',
    name: 'Casual Coding',
    priceMonthlyUsd: 25,
    tagline: 'Ship side projects with a weekly full suite check',
    maxProjects: 1,
    scansPerMonth: 5, // ~1/week + buffer
    minHoursBetweenScans: 24 * 6, // ~weekly
    crawlPerMonth: 2,
    retentionDays: 60,
    deployHooks: false,
    commitHooks: false,
    githubApp: false,
    mcp: true,
    sharePermanent: true,
    badge: true,
    slack: true,
    modes: ['lite', 'fast', 'full'],
    requireOwnership: true,
  },
  daily: {
    id: 'daily',
    name: 'Business Prototyping',
    priceMonthlyUsd: 100,
    tagline: 'Daily full scans while you iterate with customers',
    maxProjects: 3,
    scansPerMonth: 35,
    minHoursBetweenScans: 20, // ~daily
    crawlPerMonth: 15,
    retentionDays: 90,
    deployHooks: true,
    commitHooks: false,
    githubApp: true,
    mcp: true,
    sharePermanent: true,
    badge: true,
    slack: true,
    modes: ['lite', 'fast', 'full', 'crawl'],
    requireOwnership: true,
  },
  commit: {
    id: 'commit',
    name: 'Mission Critical',
    priceMonthlyUsd: 250,
    tagline: 'Every production deploy scanned — Claude/Codex fix loop ready',
    maxProjects: 10,
    scansPerMonth: 500,
    minHoursBetweenScans: 0,
    crawlPerMonth: 100,
    retentionDays: 180,
    deployHooks: true,
    commitHooks: true,
    githubApp: true,
    mcp: true,
    sharePermanent: true,
    badge: true,
    slack: true,
    modes: ['lite', 'fast', 'full', 'crawl'],
    requireOwnership: true,
  },
};

/** Back-compat aliases from older VibeTesting Agent plan ids */
const ALIASES: Record<string, PlanId> = {
  free: 'free',
  lite: 'free',
  vibe: 'weekly',
  studio: 'daily',
  weekly: 'weekly',
  daily: 'daily',
  commit: 'commit',
};

export function planOf(plan: string | null | undefined): PlanLimits {
  const id = ALIASES[plan || 'free'] || 'free';
  return PLANS[id];
}

export const POLICY_LABELS: Record<Policy, { label: string; description: string }> = {
  chill: { label: 'Chill', description: 'Notify only — never block deploys' },
  ship: { label: 'Ship', description: 'Block on new high severity; warn on medium' },
  client: { label: 'Client', description: 'Block on new high + medium; attach report' },
  launch: { label: 'Launch day', description: 'Full crawl preferred; block high + medium' },
};

/**
 * Honest inventory of the OSS vibetesting-agent suite (not marketing inflation).
 * Counts are fixed probes / rule rows in the engine — dynamic multiplications
 * (per cookie, per script, per crawl page, NVD recon) grow further at runtime.
 */
export const SUITE_STATS = {
  categories: 14,
  /** Fixed black-box probes across headers, paths, secrets, DNS, framework, SEO, new gap checks… */
  blackBoxProbes: 168,
  /** retire.js-style version ranges in the client component feed */
  clientVulnRanges: 213,
  clientLibs: 12,
  /** Unique CVE strings referenced in that feed */
  clientCveRefs: 117,
  exposurePaths: 27,
  secretPatterns: 12,
  /** OWASP ASVS 4.0.3 Level 1 black-box-testable requirements covered */
  asvsL1Covered: 25,
  asvsL1Total: 27,
  /** Headline: probes + client vuln ranges (rules the full suite can evaluate) */
  ruleSurface: 168 + 213,
} as const;

/** Opt-in / adjacent modes beyond the default black-box pass. */
export const EXTRA_MODES = [
  {
    id: 'recon',
    title: 'Recon + service CVEs',
    detail: 'Authorization-gated port/service ID; optional NVD CVE correlation (identify-only).',
  },
  {
    id: 'crawl',
    title: 'Deep browser crawl',
    detail: 'Every reachable page: JS errors, broken assets, safe reflected-input probes.',
  },
  {
    id: 'browse',
    title: 'Headless functional smoke',
    detail: 'Playwright browse: does the UI actually load and accept input?',
  },
  {
    id: 'separation',
    title: 'Tenant isolation',
    detail: 'Two-account cross-tenant leak test for multi-tenant apps.',
  },
  {
    id: 'audit',
    title: 'Dependency CVEs',
    detail: 'npm advisory audit when you point at a repo / lockfile context.',
  },
  {
    id: 'whitebox',
    title: 'White-box helpers',
    detail: 'IDOR, RBAC, mass-assignment, data-isolation probes for your own test suite.',
  },
] as const;

/** Catalog of black-box test categories for the landing page. */
export const TEST_CATALOG = [
  {
    id: 'secrets',
    icon: '🔑',
    title: 'Leaked secrets',
    description:
      'HTML + every same-origin JS bundle scanned for real credentials. Public keys (pk_live, anon) ignored. Source maps flagged when downloadable.',
    severity: 'Critical when hit',
    lite: true,
    probeCount: 13,
    samples: [
      'Stripe sk_live / rk_live',
      'AWS AKIA…',
      'OpenAI / Anthropic',
      'GitHub PAT',
      'Slack token',
      'PEM private key',
      'Supabase service_role JWT',
      'SendGrid / Twilio / Google',
      'Source maps exposed',
    ],
  },
  {
    id: 'exposure',
    icon: '📂',
    title: 'Exposed config & debug',
    description:
      '27+ paths body-validated (no SPA false positives), plus stack traces, GraphQL introspection, directory listings, robots sensitive paths.',
    severity: 'High',
    lite: true,
    probeCount: 40,
    samples: [
      '/.env (+.local/.production/.bak)',
      '/.git/config + HEAD',
      '/.aws/credentials',
      'wrangler.toml / package.json',
      'backup.sql / .zip / .tar.gz',
      'actuator / metrics / swagger',
      'GraphQL introspection',
      'Directory listing',
      'Stack-trace error pages',
    ],
  },
  {
    id: 'security',
    icon: '🔐',
    title: 'Headers, TLS, CORS, cookies',
    description:
      'Deepest category: required headers, CSP weakness grading, cookie flags, TLS grade, open redirects, SRI, JWT hygiene, host-header, CSRF heuristics, DOM-XSS sinks.',
    severity: 'High–Medium',
    lite: true,
    probeCount: 45,
    samples: [
      'HSTS + preload eligibility',
      'CSP unsafe-inline / eval / wildcards',
      'nosniff · clickjacking · Referrer-Policy',
      'Permissions-Policy · COOP · CORP',
      'Cookie Secure/HttpOnly/SameSite/__Host-',
      'TLS protocol + cipher + expiry',
      'CORS reflection + credentials',
      'Open redirect params (8)',
      'SRI · JWT · host-header · DOM-XSS',
    ],
  },
  {
    id: 'dns',
    icon: '🌐',
    title: 'DNS & email hygiene',
    description:
      'SPF + DMARC policy strength, CAA (who may issue certs), dangling-CNAME subdomain takeover heuristics — all passive DNS.',
    severity: 'Medium',
    lite: true,
    probeCount: 4,
    samples: ['SPF present', 'DMARC policy strength', 'CAA issuers', 'Dangling CNAME takeover'],
  },
  {
    id: 'framework',
    icon: '🧩',
    title: 'Framework misconfigs',
    description:
      'Fingerprints Next.js, WordPress, Laravel, Django, Rails, Spring, ASP.NET — probes stack footguns only on confident match.',
    severity: 'High when hit',
    lite: false,
    probeCount: 20,
    samples: [
      'Next.js __NEXT_DATA__ secrets',
      'WP users REST + xmlrpc',
      'Laravel Telescope / Ignition',
      'Django DEBUG pages',
      'Rails /sidekiq · /rails/info',
      'Spring Actuator env/heapdump',
      'ASP.NET elmah / trace.axd',
    ],
  },
  {
    id: 'components',
    icon: '📦',
    title: 'Vulnerable client libraries',
    description:
      'OWASP A06: fingerprint jQuery, Bootstrap, Lodash, AngularJS, Vue 2, axios… against an auto-updating feed of version ranges.',
    severity: 'High–Medium',
    lite: false,
    probeCount: 213, // version ranges in feed
    samples: [
      'jQuery XSS ranges',
      'Bootstrap <4.3.1',
      'Lodash proto-pollution',
      'AngularJS EOL + CVEs',
      'axios SSRF / header gadgets',
      'Vue 2 EOL',
      'DOMPurify / Handlebars / Moment',
      '200+ version ranges · 100+ CVE refs',
    ],
  },
  {
    id: 'reliability',
    icon: '🔗',
    title: 'Reliability',
    description: 'Homepage health, broken same-origin links/images (sampled), mixed content on HTTPS pages.',
    severity: 'Medium–Low',
    lite: false,
    probeCount: 5,
    samples: ['Homepage status', 'Broken links', 'Broken images', 'Mixed content'],
  },
  {
    id: 'seo',
    icon: '🔎',
    title: 'SEO basics',
    description: 'Title, meta description, Open Graph, canonical, single h1, robots.txt, sitemap.xml.',
    severity: 'Low',
    lite: false,
    probeCount: 7,
    samples: ['<title>', 'meta description', 'Open Graph', 'canonical', 'single h1', 'robots.txt', 'sitemap.xml'],
  },
  {
    id: 'a11y',
    icon: '♿',
    title: 'Accessibility basics',
    description: 'html lang, viewport, images missing alt, unlabeled form inputs (WCAG starter checks).',
    severity: 'Low',
    lite: false,
    probeCount: 4,
    samples: ['html lang', 'viewport meta', 'img alt', 'form labels'],
  },
  {
    id: 'performance',
    icon: '⚡',
    title: 'Performance hygiene',
    description: 'Compression, oversized HTML, script count, cache headers on static assets.',
    severity: 'Low',
    lite: false,
    probeCount: 4,
    samples: ['gzip/brotli', 'HTML weight', 'script count', 'cache headers'],
  },
  {
    id: 'agent',
    icon: '🤖',
    title: 'Agent readiness',
    description:
      'Is your deploy consumable by AI crawlers? llms.txt, robots AI bots, SSR text density, structured data, MCP/ai-plugin manifests.',
    severity: 'Info–Low',
    lite: false,
    probeCount: 8,
    samples: ['llms.txt', 'AI bot robots', 'SSR text density', 'JSON-LD', 'MCP / ai-plugin manifests'],
  },
  {
    id: 'host',
    icon: '🖥️',
    title: 'Host intel (passive)',
    description: 'Resolved IPs, reverse DNS, CDN/hosting fingerprint — no port scanning in default mode.',
    severity: 'Info',
    lite: false,
    probeCount: 3,
    samples: ['A/AAAA resolve', 'Reverse DNS', 'CDN / hosting fingerprint'],
  },
  {
    id: 'plugins',
    icon: '🔌',
    title: 'Custom plugin checks',
    description: 'Drop JSON templates (status/header/body matchers) for org-specific checks with zero code.',
    severity: 'Custom',
    lite: false,
    probeCount: 0, // user-supplied
    samples: ['GET/HEAD only', 'status / header / body matchers', 'and|or conditions', 'Nuclei-style JSON'],
  },
] as const;

export const LITE_CATEGORIES = ['secrets', 'exposure', 'security', 'dns'] as const;

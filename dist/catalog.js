// src/catalog.ts
// THE canonical, maintained list of every check the scanner performs — the single source of truth that
// stops the test surface being a black box. `docs/CHECKS.md` is generated from this (npm run catalog),
// and `tests/catalog.test.ts` fails the build if the engine ever emits a finding id that isn't listed
// here (new check → add its entry) or if docs/CHECKS.md drifts. Keep this in sync as checks are added
// or upgraded; that is the whole point of the file.
import { refsFor } from './compliance.js';
import { appStyleRuleSpecs } from './appstyle.js';
import { atlasCheckSpecs } from './atlas.js';
import { CATALOG_NUMBERS } from './catalog-numbers.js';
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The catalog. Grouped by category. Families (dynamic:true) cover checks whose id embeds the target
// (a header name, cookie name, probed path, secret rule, query param, …).
// ─────────────────────────────────────────────────────────────────────────────────────────────────
export const CATALOG = [
    // ── security: transport ──────────────────────────────────────────────────────────────────────
    { id: 'tls.scheme', category: 'security', title: 'Served over HTTPS', severity: 'high', cls: 'passive', since: '0.1.0', description: 'Site is reachable over https:// (not plain http).' },
    { id: 'tls.redirect', category: 'security', title: 'HTTP → HTTPS redirect', severity: 'medium', cls: 'probe', since: '0.1.0', description: 'Plain-http requests 3xx-redirect to https.' },
    { id: 'reachability', category: 'security', title: 'Site reachable', severity: 'high', cls: 'passive', since: '0.1.0', description: 'The homepage responded at all.' },
    { id: 'tls.expiry', category: 'security', title: 'TLS certificate expiry', severity: 'medium', cls: 'probe', since: '0.2.0', description: 'Days remaining on the served certificate (fails when near expiry).' },
    { id: 'tls.protocol', category: 'security', title: 'TLS protocol version', severity: 'high', cls: 'probe', since: '0.6.0', description: 'Flags deprecated TLS 1.0/1.1/SSLv3.' },
    { id: 'tls.cipher', category: 'security', title: 'TLS cipher strength', severity: 'medium', cls: 'probe', since: '0.6.0', description: 'Flags weak/legacy cipher suites (RC4/3DES/CBC/MD5/EXPORT).' },
    { id: 'tls.hsts-preload', category: 'security', title: 'HSTS preload eligibility', severity: 'low', cls: 'passive', since: '0.5.0', description: 'HSTS has max-age≥1y + includeSubDomains + preload.' },
    // ── security: response headers ───────────────────────────────────────────────────────────────
    { id: 'header.', dynamic: true, category: 'security', title: 'Security response header present/valid', severity: 'high', cls: 'passive', since: '0.1.0', description: 'HSTS, X-Content-Type-Options, Referrer-Policy, X-Frame-Options, CSP, Permissions-Policy, COOP, CORP, Content-Type/charset.' },
    { id: 'csp.unsafe-inline', category: 'security', title: "CSP allows 'unsafe-inline'", severity: 'high', cls: 'passive', since: '0.2.0', description: "script-src permits inline scripts, defeating most of the CSP." },
    { id: 'csp.unsafe-eval', category: 'security', title: "CSP allows 'unsafe-eval'", severity: 'medium', cls: 'passive', since: '0.2.0', description: 'script-src permits eval()/new Function().' },
    { id: 'csp.wildcard-script', category: 'security', title: 'CSP wildcard script source', severity: 'high', cls: 'passive', since: '0.2.0', description: 'script-src allows * / https: / data: — any host can supply scripts.' },
    { id: 'csp.object-src', category: 'security', title: "CSP missing object-src 'none'", severity: 'low', cls: 'passive', since: '0.2.0', description: 'Legacy plugin vectors (<object>/<embed>) remain open.' },
    { id: 'csp.base-uri', category: 'security', title: 'CSP missing base-uri', severity: 'low', cls: 'passive', since: '0.2.0', description: 'An injected <base> tag can hijack relative URLs.' },
    { id: 'http.methods', category: 'security', title: 'HTTP methods restrained', severity: 'medium', cls: 'probe', since: '0.6.0', description: 'Flags TRACE/TRACK (XST) and stray write verbs via OPTIONS.' },
    { id: 'cache.sensitive', category: 'security', title: 'Anti-caching on authed responses', severity: 'medium', cls: 'authenticated', since: '0.6.0', description: 'Authenticated pages send Cache-Control: no-store/private.' },
    { id: 'disclosure.', dynamic: true, category: 'security', title: 'Version banner disclosure', severity: 'low', cls: 'passive', since: '0.1.0', description: 'Server / X-Powered-By headers leak exact versions (disclosure.none when clean).' },
    // ── security: cookies ────────────────────────────────────────────────────────────────────────
    { id: 'cookie.', dynamic: true, category: 'security', title: 'Cookie flags (Secure+HttpOnly+SameSite)', severity: 'medium', cls: 'passive', since: '0.2.0', description: 'Each Set-Cookie carries the full flag trio.' },
    { id: 'cookie-secure.', dynamic: true, category: 'security', title: 'Cookie Secure flag', severity: 'medium', cls: 'passive', optIn: false, since: '0.7.0', description: 'Every cookie sets Secure so it can never ride a downgraded/mixed request (split out per #24).' },
    { id: 'cookie-prefix.', dynamic: true, category: 'security', title: 'Cookie __Host-/__Secure- prefix', severity: 'info', cls: 'passive', since: '0.6.0', description: 'Session cookies use a host/secure prefix (defense in depth).' },
    // ── security: active probes ──────────────────────────────────────────────────────────────────
    { id: 'securitytxt', category: 'security', title: 'security.txt present', severity: 'low', cls: 'probe', since: '0.1.0', description: 'A /.well-known/security.txt with Contact + Expires (RFC 9116).' },
    { id: 'cors.reflection', category: 'security', title: 'CORS origin reflection', severity: 'high', cls: 'active', optIn: true, since: '0.1.0', description: 'A path reflects an arbitrary Origin while allowing credentials (--cors-path).' },
    { id: 'sri', category: 'security', title: 'Subresource Integrity', severity: 'low', cls: 'passive', since: '0.2.0', description: 'Cross-origin <script>/<link> carry an integrity attribute.' },
    { id: 'open-redirect', category: 'security', title: 'Open redirect', severity: 'high', cls: 'active', since: '0.2.0', description: 'Common redirect params bounce off-domain to an attacker URL.' },
    { id: 'rate-limit', category: 'security', title: 'Rate limiting (single path)', severity: 'medium', cls: 'active', optIn: true, since: '0.2.0', description: 'A named path (--rate-limit-path) is throttled under a 25-request burst.' },
    { id: 'jwt.', dynamic: true, category: 'security', title: 'JWT hygiene', severity: 'high', cls: 'passive', since: '0.6.0', description: 'Browser-exposed JWTs: alg:none, no-exp, long-lived, non-HttpOnly cookie, sensitive claims.' },
    { id: 'host-header.injection', category: 'security', title: 'Host-header injection', severity: 'medium', cls: 'active', since: '0.6.0', description: 'A spoofed Host is reflected into a link/redirect (cache-poison / reset-poison).' },
    { id: 'csrf', category: 'security', title: 'CSRF protection on forms', severity: 'medium', cls: 'passive', since: '0.6.0', description: 'State-changing HTML forms carry a token or SameSite mitigation.' },
    { id: 'dom-xss', category: 'security', title: 'DOM-XSS sink', severity: 'medium', cls: 'passive', since: '0.6.0', description: 'A user-controllable source flows into an HTML/JS sink in inline script.' },
    { id: 'xss.jsonld', category: 'security', title: 'JSON-LD script breakout', severity: 'medium', cls: 'passive', since: '0.6.0', description: 'Structured-data blocks that fail to escape </script> (stored XSS).' },
    // ── security: active injection engine (#43 — opt-in --authorized-active, non-destructive) ────────
    { id: 'inject.sqli', dynamic: true, category: 'security', title: 'SQL injection', severity: 'high', cls: 'active', optIn: true, since: '0.7.0', description: 'A GET parameter is injectable via error/boolean/time-based SQL injection (--authorized-active).' },
    { id: 'inject.ssti', dynamic: true, category: 'security', title: 'Server-side template injection', severity: 'high', cls: 'active', optIn: true, since: '0.7.0', description: 'A GET parameter renders as a server-side template (7*7→49) (--authorized-active).' },
    { id: 'inject.cmdi', dynamic: true, category: 'security', title: 'OS command injection', severity: 'high', cls: 'active', optIn: true, since: '0.7.0', description: 'A GET parameter injects into a shell (time-based) (--authorized-active).' },
    { id: 'inject.traversal', dynamic: true, category: 'security', title: 'Path traversal', severity: 'high', cls: 'active', optIn: true, since: '0.7.0', description: 'A GET parameter allows ../ path traversal (/etc/passwd) (--authorized-active).' },
    { id: 'inject.none', category: 'security', title: 'No injection on tested params', severity: 'info', cls: 'active', optIn: true, since: '0.7.0', description: 'Clean-signal pass — active injection probes found nothing on the tested parameters.' },
    // ── security: API-surface checks (issue #24) ───────────────────────────────────────────────────
    { id: 'api.cors', dynamic: true, category: 'security', title: 'CORS on discovered API route', severity: 'high', cls: 'active', since: '0.7.0', description: 'A discovered /api/* route reflects an arbitrary Origin with credentials (auto-generalized from --cors-path).' },
    { id: 'api.rate-limit', dynamic: true, category: 'security', title: 'Rate limiting on API routes (auto)', severity: 'medium', cls: 'active', optIn: true, since: '0.7.0', description: 'Discovered expensive /api/* routes are bursted and expected to 429 (--rate-limit-scan; high on LLM/compute paths).' },
    { id: 'xss.reflected', dynamic: true, category: 'security', title: 'Reflected XSS / HTML injection', severity: 'high', cls: 'active', optIn: true, since: '0.7.0', description: 'A benign marker injected into a public query param reflects unencoded into the HTML (--xss).' },
    // ── secrets ────────────────────────────────────────────────────────────────────────────────────
    { id: 'secret.', dynamic: true, category: 'secrets', title: 'Hardcoded secret in client code', severity: 'high', cls: 'probe', since: '0.1.0', description: 'API/private keys leaked in the HTML or same-origin JS bundles (secret.none when clean).' },
    { id: 'sourcemap.exposed', category: 'secrets', title: 'Public source maps', severity: 'medium', cls: 'probe', since: '0.5.0', description: 'Reachable .map files expose the original unminified source.' },
    // ── exposure ─────────────────────────────────────────────────────────────────────────────────
    { id: 'exposed', dynamic: true, category: 'exposure', title: 'Config/dotfile/backup reachable', severity: 'high', cls: 'probe', since: '0.1.0', description: '.env/.git/config/backup/actuator/swagger/metrics etc. web-served (body-validated).' },
    { id: 'dir-listing', dynamic: true, category: 'exposure', title: 'Directory listing enabled', severity: 'medium', cls: 'probe', since: '0.5.0', description: 'Autoindex on a common dir leaks internal file structure.' },
    { id: 'robots.sensitive', category: 'exposure', title: 'robots.txt discloses sensitive paths', severity: 'low', cls: 'probe', since: '0.5.0', description: 'Disallow entries advertise admin/internal/backup paths.' },
    { id: 'debug-leak', dynamic: true, category: 'exposure', title: 'Debug endpoint leaks secrets', severity: 'high', cls: 'probe', since: '0.6.0', description: 'A debug/introspection route returns service-role keys, tokens or password hashes.' },
    { id: 'error.stacktrace', category: 'exposure', title: 'Stack-trace / internal-path leak', severity: 'medium', cls: 'probe', since: '0.2.0', description: 'An unknown URL returns a server stack trace or internal file paths.' },
    { id: 'graphql.introspection', dynamic: true, category: 'exposure', title: 'GraphQL introspection enabled', severity: 'medium', cls: 'probe', since: '0.2.0', description: 'A GraphQL endpoint answers __schema queries in production.' },
    { id: 'exposure.none', category: 'exposure', title: 'No exposed surfaces', severity: 'info', cls: 'probe', since: '0.2.0', description: 'Clean-signal pass emitted when nothing above fired.' },
    { id: 'api.unauth-data', dynamic: true, category: 'exposure', title: 'API route returns data without auth', severity: 'high', cls: 'probe', since: '0.7.0', description: 'A discovered/wordlist /api/* route answers 200 + JSON data with no auth challenge (#24).' },
    { id: 'api.unauth-write', dynamic: true, category: 'exposure', title: 'API route accepts unauth write', severity: 'high', cls: 'active', optIn: true, since: '0.7.0', description: 'A write-suggestive route accepts a benign unauthenticated POST (2xx) (--api-write; #24).' },
    // ── reliability ────────────────────────────────────────────────────────────────────────────────
    { id: 'home.status', category: 'reliability', title: 'Homepage status', severity: 'high', cls: 'passive', since: '0.1.0', description: 'The homepage returns a non-error status.' },
    { id: 'mixed-content', category: 'reliability', title: 'Mixed content', severity: 'medium', cls: 'passive', since: '0.1.0', description: 'An https page loads http:// resources.' },
    { id: 'broken-links', category: 'reliability', title: 'Broken links/images', severity: 'medium', cls: 'probe', since: '0.1.0', description: 'Sampled same-origin links/images that 4xx/5xx.' },
    // ── seo ──────────────────────────────────────────────────────────────────────────────────────
    { id: 'seo.title', category: 'seo', title: '<title>', severity: 'medium', cls: 'passive', since: '0.1.0', description: 'A descriptive page title exists.' },
    { id: 'seo.description', category: 'seo', title: 'Meta description', severity: 'low', cls: 'passive', since: '0.1.0', description: 'A <meta name="description"> exists.' },
    { id: 'seo.opengraph', category: 'seo', title: 'Open Graph tags', severity: 'low', cls: 'passive', since: '0.1.0', description: 'og:title / og:image present for social unfurls.' },
    { id: 'seo.canonical', category: 'seo', title: 'Canonical URL', severity: 'low', cls: 'passive', since: '0.1.0', description: 'A <link rel="canonical"> exists.' },
    { id: 'seo.h1', category: 'seo', title: 'Single <h1>', severity: 'low', cls: 'passive', since: '0.1.0', description: 'Exactly one <h1> on the page.' },
    { id: 'seo.robots.txt', category: 'seo', title: 'robots.txt present', severity: 'low', cls: 'probe', since: '0.1.0', description: 'A robots.txt is served.' },
    { id: 'seo.sitemap.xml', category: 'seo', title: 'sitemap.xml present', severity: 'low', cls: 'probe', since: '0.1.0', description: 'A sitemap.xml is served.' },
    // ── a11y ───────────────────────────────────────────────────────────────────────────────────────
    { id: 'a11y.lang', category: 'a11y', title: '<html lang>', severity: 'medium', cls: 'passive', since: '0.1.0', description: 'The document declares a language.' },
    { id: 'a11y.viewport', category: 'a11y', title: 'Viewport meta', severity: 'medium', cls: 'passive', since: '0.1.0', description: 'A responsive viewport meta exists.' },
    { id: 'a11y.alt', category: 'a11y', title: 'Image alt text', severity: 'low', cls: 'passive', since: '0.1.0', description: 'Images carry alt attributes.' },
    { id: 'a11y.labels', category: 'a11y', title: 'Form input labels', severity: 'low', cls: 'passive', since: '0.1.0', description: 'Labelable inputs appear labelled.' },
    // ── performance ──────────────────────────────────────────────────────────────────────────────
    { id: 'perf.compression', category: 'performance', title: 'Compression', severity: 'low', cls: 'probe', since: '0.1.0', description: 'The document is served gzip/brotli-compressed.' },
    { id: 'perf.html-weight', category: 'performance', title: 'HTML weight', severity: 'low', cls: 'passive', since: '0.1.0', description: 'The HTML document is not excessively large.' },
    { id: 'perf.scripts', category: 'performance', title: 'Script count', severity: 'low', cls: 'passive', since: '0.1.0', description: 'A reasonable number of <script src> requests.' },
    { id: 'perf.caching', category: 'performance', title: 'Static-asset caching', severity: 'low', cls: 'probe', since: '0.1.0', description: 'Hashed static assets carry long-lived cache headers.' },
    // ── dns ────────────────────────────────────────────────────────────────────────────────────────
    { id: 'dns', category: 'dns', title: 'DNS resolvable', severity: 'info', cls: 'probe', since: '0.4.0', description: 'The apex resolves (base finding for the DNS category).' },
    { id: 'dns.spf', category: 'dns', title: 'SPF record', severity: 'medium', cls: 'probe', since: '0.4.0', description: 'An SPF TXT record restricts who can send mail as the domain.' },
    { id: 'dns.dmarc', category: 'dns', title: 'DMARC policy', severity: 'medium', cls: 'probe', since: '0.4.0', description: 'A DMARC record with an enforcing policy exists.' },
    { id: 'dns.caa', category: 'dns', title: 'CAA record', severity: 'low', cls: 'probe', since: '0.4.0', description: 'A CAA record limits which CAs can issue certs.' },
    { id: 'dns.dangling-cname', category: 'dns', title: 'Dangling CNAME (takeover)', severity: 'high', cls: 'probe', since: '0.4.0', description: 'A CNAME points at an unclaimed provider host (subdomain-takeover risk).' },
    // ── agent readiness ──────────────────────────────────────────────────────────────────────────
    { id: 'agent', category: 'agent', title: 'Agent-readiness base', severity: 'info', cls: 'passive', since: '0.6.0', description: 'Base finding for the agent-readiness category.' },
    { id: 'agent.ssr-content', category: 'agent', title: 'Server-rendered content', severity: 'medium', cls: 'passive', since: '0.6.0', description: 'Meaningful content is present without running JS (crawlable by agents).' },
    { id: 'agent.llms-txt', category: 'agent', title: 'llms.txt', severity: 'low', cls: 'probe', since: '0.6.0', description: 'A /llms.txt guide for AI crawlers is present.' },
    { id: 'agent.ai-crawlers', category: 'agent', title: 'AI-crawler policy', severity: 'low', cls: 'probe', since: '0.6.0', description: 'robots.txt does not blanket-block AI crawlers unintentionally.' },
    { id: 'agent.structured-data', category: 'agent', title: 'Structured data (JSON-LD)', severity: 'low', cls: 'passive', since: '0.6.0', description: 'JSON-LD structured data helps agents understand the page.' },
    { id: 'agent.manifest', category: 'agent', title: 'MCP / app manifest', severity: 'info', cls: 'probe', since: '0.6.0', description: 'A machine manifest (MCP / web app) is discoverable.' },
    // ── framework-specific ─────────────────────────────────────────────────────────────────────────
    { id: 'framework', category: 'framework', title: 'Framework base', severity: 'info', cls: 'passive', since: '0.6.0', description: 'Base finding for the framework category.' },
    { id: 'framework.detected', category: 'framework', title: 'Stack fingerprinted', severity: 'info', cls: 'passive', since: '0.6.0', description: 'The app stack was identified with high confidence.' },
    { id: 'framework.none', category: 'framework', title: 'No stack-specific issues', severity: 'info', cls: 'passive', since: '0.6.0', description: 'Clean-signal pass for the framework category.' },
    { id: 'framework.next.data-secrets', category: 'framework', title: 'Next.js __NEXT_DATA__ secrets', severity: 'high', cls: 'passive', since: '0.6.0', description: 'Server props serialize secrets into __NEXT_DATA__.' },
    { id: 'framework.wp.user-enum', category: 'framework', title: 'WordPress user enumeration', severity: 'medium', cls: 'probe', since: '0.6.0', description: 'The WP REST API leaks the user list.' },
    { id: 'framework.django.debug', category: 'framework', title: 'Django DEBUG=True', severity: 'high', cls: 'probe', since: '0.6.0', description: 'Django is running with DEBUG enabled in production.' },
    // ── components (OWASP A06) ─────────────────────────────────────────────────────────────────────
    { id: 'components.server-cve.', dynamic: true, category: 'components', title: 'Server/runtime version has a known CVE', severity: 'high', cls: 'passive', since: '0.7.0', description: 'A disclosed Server/X-Powered-By version matches a curated high-signal CVE (Apache/nginx/OpenSSH/OpenSSL/PHP).' },
    { id: 'components.', dynamic: true, category: 'components', title: 'Client library vulnerability', severity: 'high', cls: 'passive', since: '0.6.0', description: 'A fingerprinted client-side JS library (retire.js-style) is in a known-vulnerable version range.' },
    { id: 'components.summary', category: 'components', title: 'Client library inventory', severity: 'info', cls: 'passive', since: '0.6.0', description: 'Summary of client-side JS libraries detected.' },
    { id: 'components.none', category: 'components', title: 'No vulnerable components', severity: 'info', cls: 'passive', since: '0.6.0', description: 'Clean-signal pass — no known-vulnerable client libs.' },
    // ── host & infrastructure (passive intel) ──────────────────────────────────────────────────────
    { id: 'host', category: 'host', title: 'Host base', severity: 'info', cls: 'probe', since: '0.6.0', description: 'Base finding for the host-intel category.' },
    { id: 'host.ip', category: 'host', title: 'Resolved IP(s)', severity: 'info', cls: 'probe', since: '0.6.0', description: 'The A/AAAA records for the host.' },
    { id: 'host.ptr', category: 'host', title: 'Reverse DNS', severity: 'info', cls: 'probe', since: '0.6.0', description: 'PTR record for the resolved IP.' },
    { id: 'host.provider', category: 'host', title: 'Hosting provider', severity: 'info', cls: 'probe', since: '0.6.0', description: 'The hosting/cloud provider inferred from IP/headers.' },
    { id: 'host.cdn', category: 'host', title: 'CDN / edge', severity: 'info', cls: 'passive', since: '0.6.0', description: 'The CDN/edge fronting the origin.' },
    { id: 'host.exposed', category: 'host', title: 'Origin exposure', severity: 'low', cls: 'probe', since: '0.6.0', description: 'Whether the origin IP appears reachable behind the CDN.' },
    // ── appstyle: business-archetype detection (per-type rules are appended below from appstyle.ts) ──
    { id: 'appstyle.detected', category: 'appstyle', title: 'App type detected', severity: 'info', cls: 'passive', since: '0.7.0', description: 'The business archetype(s) the homepage was fingerprinted as (drives which type-specific rules run).' },
    { id: 'appstyle.none', category: 'appstyle', title: 'App type not identified', severity: 'info', cls: 'passive', since: '0.7.0', description: 'No archetype reached the confidence threshold — no type-specific rules ran.' },
    // ── plugins (user-supplied declarative templates) ──────────────────────────────────────────────
    { id: 'plugins', category: 'plugins', title: 'Plugins base', severity: 'info', cls: 'probe', since: '0.5.0', description: 'Base finding for user JSON plugin templates.' },
    { id: 'plugins.none', category: 'plugins', title: 'No plugin templates', severity: 'info', cls: 'probe', since: '0.5.0', description: 'No custom templates were loaded.' },
    { id: 'plugins.loaded', category: 'plugins', title: 'Plugin templates loaded', severity: 'info', cls: 'probe', since: '0.5.0', description: 'Count of custom templates executed.' },
    // ── white-box testkit helpers (not part of the URL scan; require tokens / two accounts) ─────────
    { id: 'testkit.idorProbe', category: 'testkit', title: 'IDOR / object-access probe', severity: 'high', cls: 'white-box', since: '0.2.0', description: 'Diffs object access across two identities to catch IDOR/BOLA.' },
    { id: 'testkit.rbacProbe', category: 'testkit', title: 'RBAC enforcement probe', severity: 'high', cls: 'white-box', since: '0.6.0', description: 'Confirms role-gated routes reject lower-privilege actors.' },
    { id: 'testkit.dataIsolationProbe', category: 'testkit', title: 'Tenant data-isolation probe', severity: 'high', cls: 'white-box', since: '0.6.0', description: "Confirms tenant A cannot read tenant B's data." },
    { id: 'testkit.massAssignmentProbe', category: 'testkit', title: 'Mass-assignment probe', severity: 'high', cls: 'white-box', since: '0.6.0', description: 'Detects privileged fields accepted from an untrusted body.' },
    { id: 'testkit.findSensitiveFields', category: 'testkit', title: 'Sensitive-field scan', severity: 'medium', cls: 'white-box', since: '0.6.0', description: 'Flags PII/secret-looking fields leaking in API responses.' },
];
// Append every top-20 app-type rule from appstyle.ts so the catalog (and docs/CHECKS.md) lists them all
// without a second copy to maintain. Each rule only runs when its archetype is confidently detected.
for (const spec of appStyleRuleSpecs()) {
    CATALOG.push({
        id: spec.id, category: 'appstyle', title: spec.title, severity: spec.severity, cls: 'probe', since: '0.7.0',
        description: `[${spec.label}] ${spec.description}`,
    });
}
// Append the MITRE ATLAS AI/LLM-attack checks, each carrying its ATLAS technique id(s).
for (const spec of atlasCheckSpecs()) {
    const cls = spec.optIn ? 'active' : spec.id === 'atlas.detected' || spec.id === 'atlas.none' ? 'passive' : 'probe';
    CATALOG.push({
        id: spec.id, category: 'atlas', title: spec.title, severity: spec.severity, cls, optIn: spec.optIn,
        dynamic: spec.dynamic, atlas: spec.atlas.length ? spec.atlas : undefined, since: '0.7.0', description: spec.description,
    });
}
/** Exact-match first, then the longest `dynamic` family prefix the id starts with. */
export function catalogEntryFor(id) {
    const exact = CATALOG.find((c) => c.id === id);
    if (exact)
        return exact;
    let best;
    for (const c of CATALOG) {
        if (c.dynamic && id.startsWith(c.id) && (!best || c.id.length > best.id.length))
            best = c;
    }
    return best;
}
/** Every id/family the scanner (non-testkit) is expected to be able to emit. */
export function scannerSpecs() {
    return CATALOG.filter((c) => c.category !== 'testkit');
}
// ── stable test numbering (VTA-NNNN) ────────────────────────────────────────────────────────────────
// Every check/family carries a permanent number from src/catalog-numbers.ts (an append-only registry:
// numbers are assigned once by `npm run catalog` and NEVER reused, even if a check is retired). This is
// the identifier the run-ledger, daily report, and GitHub-issue feed key off. A concrete finding inherits
// its family's number (e.g. `header.x-frame-options` → the `header.` family's VTA number).
/** The stable integer for a check id or family (exact, else longest dynamic-family prefix). undefined if unnumbered. */
export function vtaNumber(id) {
    if (id in CATALOG_NUMBERS)
        return CATALOG_NUMBERS[id];
    const entry = catalogEntryFor(id);
    return entry ? CATALOG_NUMBERS[entry.id] : undefined;
}
/** The display code for a check id, e.g. `VTA-0007`. Falls back to `VTA-????` for anything unnumbered. */
export function vtaCode(id) {
    const n = vtaNumber(id);
    return n === undefined ? 'VTA-????' : `VTA-${String(n).padStart(4, '0')}`;
}
/**
 * Assign numbers to a list of catalog ids given the existing registry: keeps every existing number,
 * appends the next integer for any new id (append-only, never reusing a retired number). Deterministic —
 * used by `npm run catalog` to update src/catalog-numbers.ts and by the drift test to detect a stale registry.
 */
export function assignNumbers(ids, existing = CATALOG_NUMBERS) {
    const out = { ...existing };
    let next = Object.values(out).reduce((m, n) => Math.max(m, n), 0) + 1;
    for (const id of ids)
        if (!(id in out))
            out[id] = next++;
    return out;
}
/** Serialize a numbering registry to the exact contents of src/catalog-numbers.ts (deterministic). */
export function renderCatalogNumbers(map) {
    const entries = Object.entries(map).sort((a, b) => a[1] - b[1]);
    const body = entries.map(([id, n]) => `  ${JSON.stringify(id)}: ${n},`).join('\n');
    return [
        '// src/catalog-numbers.ts',
        '// APPEND-ONLY registry of stable VTA test numbers (id → number). Generated by `npm run catalog`.',
        '// Numbers are permanent: never edit or reuse one, even if a check is retired — the run-ledger, daily',
        '// report, and GitHub-issue feed all key off these. New checks get the next integer automatically.',
        '',
        'export const CATALOG_NUMBERS: Record<string, number> = {',
        body,
        '};',
        '',
    ].join('\n');
}
const CLASS_LABEL = {
    passive: 'passive (reads the homepage response only)',
    probe: 'probe (extra safe same-origin GETs)',
    active: 'active (sends a crafted probe / burst / write)',
    authenticated: 'authenticated (needs --cookie/--header)',
    'white-box': 'white-box (needs source / tokens / two accounts)',
};
/** Render docs/CHECKS.md from the catalog. Kept deterministic so a drift test can compare byte-for-byte. */
export function renderCatalogMarkdown() {
    const lines = [];
    lines.push('# Check catalog');
    lines.push('');
    lines.push('> Generated from `src/catalog.ts` by `npm run catalog`. Do not edit by hand — edit the catalog and regenerate.');
    lines.push('> `tests/catalog.test.ts` fails the build if the engine emits a finding id that is not listed here, or if this file is stale.');
    lines.push('');
    lines.push(`**${scannerSpecs().length}** scanner checks + **${CATALOG.filter((c) => c.category === 'testkit').length}** white-box testkit helpers.`);
    lines.push('');
    lines.push('Legend — how each check reaches its verdict:');
    lines.push('');
    for (const k of Object.keys(CLASS_LABEL))
        lines.push(`- **${k}** — ${CLASS_LABEL[k].replace(/^[a-z-]+ \(/, '').replace(/\)$/, '')}`);
    lines.push('');
    const order = [
        'security', 'secrets', 'exposure', 'dns', 'reliability', 'seo', 'a11y', 'performance',
        'agent', 'framework', 'components', 'host', 'appstyle', 'atlas', 'plugins', 'testkit',
    ];
    const CAT_TITLE = {
        security: 'Security', secrets: 'Leaked secrets', exposure: 'Exposed files & debug', dns: 'DNS & email',
        reliability: 'Reliability', seo: 'SEO', a11y: 'Accessibility', performance: 'Performance', agent: 'Agent readiness',
        framework: 'Framework-specific', components: 'Vulnerable components', host: 'Host & infrastructure',
        appstyle: 'App-type rules (top-20 business archetypes)', atlas: 'AI/LLM attack surface (MITRE ATLAS)',
        plugins: 'Custom plugins', testkit: 'White-box testkit helpers',
    };
    for (const cat of order) {
        const rows = CATALOG.filter((c) => c.category === cat);
        if (!rows.length)
            continue;
        lines.push(`## ${CAT_TITLE[cat]}`);
        lines.push('');
        lines.push('| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |');
        lines.push('| --- | --- | --- | --- | --- | --- | --- | --- | --- |');
        for (const c of rows) {
            const id = c.dynamic ? `\`${c.id}*\`` : `\`${c.id}\``;
            const std = standardsFor(c);
            const dflt = c.cls === 'white-box' ? '—' : c.optIn ? 'opt-in' : 'on';
            lines.push(`| ${vtaCode(c.id)} | ${id} | ${c.title} | ${c.severity} | ${c.cls} | ${dflt} | ${std || '—'} | ${c.since} | ${c.description} |`);
        }
        lines.push('');
    }
    return lines.join('\n') + '\n';
}
/** Compact standards string (OWASP/CWE/ATLAS) for a check, via the compliance map + catalog atlas field. */
function standardsFor(c) {
    const r = refsFor(c.dynamic ? sampleIdFor(c.id) : c.id);
    const bits = [];
    if (r.owasp)
        bits.push(r.owasp);
    if (r.apiTop10)
        bits.push(r.apiTop10);
    if (r.cwe?.length)
        bits.push(r.cwe.join(' ')); // cwe values already carry the "CWE-" prefix
    if (c.atlas?.length)
        bits.push(c.atlas.join(' '));
    return bits.join('; ');
}
/** For a dynamic family, use a representative concrete id so refsFor resolves. */
function sampleIdFor(id) {
    switch (id) {
        case 'header.': return 'header.content-security-policy';
        case 'cookie.': return 'cookie.session';
        case 'cookie-secure.': return 'cookie-secure.session';
        case 'cookie-prefix.': return 'cookie-prefix.session';
        case 'secret.': return 'secret.aws.akid';
        case 'jwt.': return 'jwt.alg-none';
        case 'disclosure.': return 'disclosure.server';
        case 'exposed': return 'exposed/.env';
        case 'dir-listing': return 'dir-listing/uploads/';
        case 'debug-leak': return 'debug-leak/api/debug';
        case 'graphql.introspection': return 'graphql.introspection/graphql';
        case 'api.cors': return 'api.cors/api/config';
        case 'api.rate-limit': return 'api.rate-limit/api/ai';
        case 'api.unauth-data': return 'api.unauth-data/api/config';
        case 'api.unauth-write': return 'api.unauth-write/api/sync';
        case 'xss.reflected': return 'xss.reflected.q';
        default: return id;
    }
}

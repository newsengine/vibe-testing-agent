# Check catalog

> Generated from `src/catalog.ts` by `npm run catalog`. Do not edit by hand — edit the catalog and regenerate.
> `tests/catalog.test.ts` fails the build if the engine emits a finding id that is not listed here, or if this file is stale.

**149** scanner checks + **5** white-box testkit helpers.

Legend — how each check reaches its verdict:

- **passive** — reads the homepage response only
- **probe** — extra safe same-origin GETs
- **active** — sends a crafted probe / burst / write
- **authenticated** — needs --cookie/--header
- **white-box** — needs source / tokens / two accounts

## Security

| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VTA-0001 | `tls.scheme` | Served over HTTPS | high | passive | on | A02; CWE-319 | 0.1.0 | Site is reachable over https:// (not plain http). |
| VTA-0002 | `tls.redirect` | HTTP → HTTPS redirect | medium | probe | on | A02; CWE-319 | 0.1.0 | Plain-http requests 3xx-redirect to https. |
| VTA-0003 | `reachability` | Site reachable | high | passive | on | — | 0.1.0 | The homepage responded at all. |
| VTA-0004 | `tls.expiry` | TLS certificate expiry | medium | probe | on | A02; CWE-295 | 0.2.0 | Days remaining on the served certificate (fails when near expiry). |
| VTA-0005 | `tls.protocol` | TLS protocol version | high | probe | on | A02; CWE-326 | 0.6.0 | Flags deprecated TLS 1.0/1.1/SSLv3. |
| VTA-0006 | `tls.cipher` | TLS cipher strength | medium | probe | on | A02; CWE-327 | 0.6.0 | Flags weak/legacy cipher suites (RC4/3DES/CBC/MD5/EXPORT). |
| VTA-0007 | `tls.hsts-preload` | HSTS preload eligibility | low | passive | on | A05; CWE-319 | 0.5.0 | HSTS has max-age≥1y + includeSubDomains + preload. |
| VTA-0008 | `header.*` | Security response header present/valid | high | passive | on | A05; CWE-693 CWE-79 | 0.1.0 | HSTS, X-Content-Type-Options, Referrer-Policy, X-Frame-Options, CSP, Permissions-Policy, COOP, CORP, Content-Type/charset. |
| VTA-0009 | `csp.unsafe-inline` | CSP allows 'unsafe-inline' | high | passive | on | A05; CWE-79 CWE-693 | 0.2.0 | script-src permits inline scripts, defeating most of the CSP. |
| VTA-0010 | `csp.unsafe-eval` | CSP allows 'unsafe-eval' | medium | passive | on | A05; CWE-79 CWE-693 | 0.2.0 | script-src permits eval()/new Function(). |
| VTA-0011 | `csp.wildcard-script` | CSP wildcard script source | high | passive | on | A05; CWE-79 CWE-693 | 0.2.0 | script-src allows * / https: / data: — any host can supply scripts. |
| VTA-0012 | `csp.object-src` | CSP missing object-src 'none' | low | passive | on | A05; CWE-79 CWE-693 | 0.2.0 | Legacy plugin vectors (<object>/<embed>) remain open. |
| VTA-0013 | `csp.base-uri` | CSP missing base-uri | low | passive | on | A05; CWE-79 CWE-693 | 0.2.0 | An injected <base> tag can hijack relative URLs. |
| VTA-0014 | `http.methods` | HTTP methods restrained | medium | probe | on | A05; API8:2023; CWE-16 | 0.6.0 | Flags TRACE/TRACK (XST) and stray write verbs via OPTIONS. |
| VTA-0015 | `cache.sensitive` | Anti-caching on authed responses | medium | authenticated | on | A05; CWE-525 | 0.6.0 | Authenticated pages send Cache-Control: no-store/private. |
| VTA-0016 | `disclosure.*` | Version banner disclosure | low | passive | on | A05; API9:2023; CWE-200 | 0.1.0 | Server / X-Powered-By headers leak exact versions (disclosure.none when clean). |
| VTA-0017 | `cookie.*` | Cookie flags (Secure+HttpOnly+SameSite) | medium | passive | on | A05; CWE-614 CWE-1004 | 0.2.0 | Each Set-Cookie carries the full flag trio. |
| VTA-0018 | `cookie-secure.*` | Cookie Secure flag | medium | passive | on | — | 0.7.0 | Every cookie sets Secure so it can never ride a downgraded/mixed request (split out per #24). |
| VTA-0019 | `cookie-prefix.*` | Cookie __Host-/__Secure- prefix | info | passive | on | A05; CWE-614 | 0.6.0 | Session cookies use a host/secure prefix (defense in depth). |
| VTA-0020 | `securitytxt` | security.txt present | low | probe | on | A05 | 0.1.0 | A /.well-known/security.txt with Contact + Expires (RFC 9116). |
| VTA-0021 | `cors.reflection` | CORS origin reflection | high | active | opt-in | A05; API8:2023; CWE-942 | 0.1.0 | A path reflects an arbitrary Origin while allowing credentials (--cors-path). |
| VTA-0022 | `sri` | Subresource Integrity | low | passive | on | A08; CWE-353 CWE-830 | 0.2.0 | Cross-origin <script>/<link> carry an integrity attribute. |
| VTA-0023 | `open-redirect` | Open redirect | high | active | on | A01; CWE-601 | 0.2.0 | Common redirect params bounce off-domain to an attacker URL. |
| VTA-0024 | `rate-limit` | Rate limiting (single path) | medium | active | opt-in | A07; API4:2023; CWE-307 CWE-799 | 0.2.0 | A named path (--rate-limit-path) is throttled under a 25-request burst. |
| VTA-0025 | `jwt.*` | JWT hygiene | high | passive | on | A02; API2:2023; CWE-347 | 0.6.0 | Browser-exposed JWTs: alg:none, no-exp, long-lived, non-HttpOnly cookie, sensitive claims. |
| VTA-0026 | `host-header.injection` | Host-header injection | medium | active | on | A03; CWE-644 CWE-20 | 0.6.0 | A spoofed Host is reflected into a link/redirect (cache-poison / reset-poison). |
| VTA-0027 | `csrf` | CSRF protection on forms | medium | passive | on | A01; CWE-352 | 0.6.0 | State-changing HTML forms carry a token or SameSite mitigation. |
| VTA-0028 | `dom-xss` | DOM-XSS sink | medium | passive | on | A03; CWE-79 | 0.6.0 | A user-controllable source flows into an HTML/JS sink in inline script. |
| VTA-0029 | `xss.jsonld` | JSON-LD script breakout | medium | passive | on | — | 0.6.0 | Structured-data blocks that fail to escape </script> (stored XSS). |
| VTA-0150 | `inject.sqli*` | SQL injection | high | active | opt-in | A03; API8:2023; CWE-89 | 0.7.0 | A GET parameter is injectable via error/boolean/time-based SQL injection (--authorized-active). |
| VTA-0151 | `inject.ssti*` | Server-side template injection | high | active | opt-in | A03; CWE-1336 CWE-94 | 0.7.0 | A GET parameter renders as a server-side template (7*7→49) (--authorized-active). |
| VTA-0152 | `inject.cmdi*` | OS command injection | high | active | opt-in | A03; CWE-78 | 0.7.0 | A GET parameter injects into a shell (time-based) (--authorized-active). |
| VTA-0153 | `inject.traversal*` | Path traversal | high | active | opt-in | A01; CWE-22 | 0.7.0 | A GET parameter allows ../ path traversal (/etc/passwd) (--authorized-active). |
| VTA-0154 | `inject.none` | No injection on tested params | info | active | opt-in | — | 0.7.0 | Clean-signal pass — active injection probes found nothing on the tested parameters. |
| VTA-0030 | `api.cors*` | CORS on discovered API route | high | active | on | — | 0.7.0 | A discovered /api/* route reflects an arbitrary Origin with credentials (auto-generalized from --cors-path). |
| VTA-0031 | `api.rate-limit*` | Rate limiting on API routes (auto) | medium | active | opt-in | — | 0.7.0 | Discovered expensive /api/* routes are bursted and expected to 429 (--rate-limit-scan; high on LLM/compute paths). |
| VTA-0032 | `xss.reflected*` | Reflected XSS / HTML injection | high | active | opt-in | — | 0.7.0 | A benign marker injected into a public query param reflects unencoded into the HTML (--xss). |

## Leaked secrets

| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VTA-0033 | `secret.*` | Hardcoded secret in client code | high | probe | on | A02; CWE-798 CWE-312 | 0.1.0 | API/private keys leaked in the HTML or same-origin JS bundles (secret.none when clean). |
| VTA-0034 | `sourcemap.exposed` | Public source maps | medium | probe | on | A05; CWE-540 | 0.5.0 | Reachable .map files expose the original unminified source. |

## Exposed files & debug

| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VTA-0035 | `exposed*` | Config/dotfile/backup reachable | high | probe | on | A05; CWE-538 CWE-200 | 0.1.0 | .env/.git/config/backup/actuator/swagger/metrics etc. web-served (body-validated). |
| VTA-0036 | `dir-listing*` | Directory listing enabled | medium | probe | on | A05; CWE-548 | 0.5.0 | Autoindex on a common dir leaks internal file structure. |
| VTA-0037 | `robots.sensitive` | robots.txt discloses sensitive paths | low | probe | on | A05; CWE-200 | 0.5.0 | Disallow entries advertise admin/internal/backup paths. |
| VTA-0038 | `debug-leak*` | Debug endpoint leaks secrets | high | probe | on | A05; CWE-200 CWE-489 | 0.6.0 | A debug/introspection route returns service-role keys, tokens or password hashes. |
| VTA-0039 | `error.stacktrace` | Stack-trace / internal-path leak | medium | probe | on | A05; CWE-209 | 0.2.0 | An unknown URL returns a server stack trace or internal file paths. |
| VTA-0040 | `graphql.introspection*` | GraphQL introspection enabled | medium | probe | on | A05; API9:2023; CWE-200 | 0.2.0 | A GraphQL endpoint answers __schema queries in production. |
| VTA-0041 | `exposure.none` | No exposed surfaces | info | probe | on | — | 0.2.0 | Clean-signal pass emitted when nothing above fired. |
| VTA-0042 | `api.unauth-data*` | API route returns data without auth | high | probe | on | — | 0.7.0 | A discovered/wordlist /api/* route answers 200 + JSON data with no auth challenge (#24). |
| VTA-0043 | `api.unauth-write*` | API route accepts unauth write | high | active | opt-in | — | 0.7.0 | A write-suggestive route accepts a benign unauthenticated POST (2xx) (--api-write; #24). |

## DNS & email

| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VTA-0062 | `dns` | DNS resolvable | info | probe | on | — | 0.4.0 | The apex resolves (base finding for the DNS category). |
| VTA-0063 | `dns.spf` | SPF record | medium | probe | on | — | 0.4.0 | An SPF TXT record restricts who can send mail as the domain. |
| VTA-0064 | `dns.dmarc` | DMARC policy | medium | probe | on | — | 0.4.0 | A DMARC record with an enforcing policy exists. |
| VTA-0065 | `dns.caa` | CAA record | low | probe | on | — | 0.4.0 | A CAA record limits which CAs can issue certs. |
| VTA-0066 | `dns.dangling-cname` | Dangling CNAME (takeover) | high | probe | on | — | 0.4.0 | A CNAME points at an unclaimed provider host (subdomain-takeover risk). |

## Reliability

| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VTA-0044 | `home.status` | Homepage status | high | passive | on | — | 0.1.0 | The homepage returns a non-error status. |
| VTA-0045 | `mixed-content` | Mixed content | medium | passive | on | — | 0.1.0 | An https page loads http:// resources. |
| VTA-0046 | `broken-links` | Broken links/images | medium | probe | on | — | 0.1.0 | Sampled same-origin links/images that 4xx/5xx. |

## SEO

| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VTA-0047 | `seo.title` | <title> | medium | passive | on | — | 0.1.0 | A descriptive page title exists. |
| VTA-0048 | `seo.description` | Meta description | low | passive | on | — | 0.1.0 | A <meta name="description"> exists. |
| VTA-0049 | `seo.opengraph` | Open Graph tags | low | passive | on | — | 0.1.0 | og:title / og:image present for social unfurls. |
| VTA-0050 | `seo.canonical` | Canonical URL | low | passive | on | — | 0.1.0 | A <link rel="canonical"> exists. |
| VTA-0051 | `seo.h1` | Single <h1> | low | passive | on | — | 0.1.0 | Exactly one <h1> on the page. |
| VTA-0052 | `seo.robots.txt` | robots.txt present | low | probe | on | — | 0.1.0 | A robots.txt is served. |
| VTA-0053 | `seo.sitemap.xml` | sitemap.xml present | low | probe | on | — | 0.1.0 | A sitemap.xml is served. |

## Accessibility

| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VTA-0054 | `a11y.lang` | <html lang> | medium | passive | on | — | 0.1.0 | The document declares a language. |
| VTA-0055 | `a11y.viewport` | Viewport meta | medium | passive | on | — | 0.1.0 | A responsive viewport meta exists. |
| VTA-0056 | `a11y.alt` | Image alt text | low | passive | on | — | 0.1.0 | Images carry alt attributes. |
| VTA-0057 | `a11y.labels` | Form input labels | low | passive | on | — | 0.1.0 | Labelable inputs appear labelled. |

## Performance

| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VTA-0058 | `perf.compression` | Compression | low | probe | on | — | 0.1.0 | The document is served gzip/brotli-compressed. |
| VTA-0059 | `perf.html-weight` | HTML weight | low | passive | on | — | 0.1.0 | The HTML document is not excessively large. |
| VTA-0060 | `perf.scripts` | Script count | low | passive | on | — | 0.1.0 | A reasonable number of <script src> requests. |
| VTA-0061 | `perf.caching` | Static-asset caching | low | probe | on | — | 0.1.0 | Hashed static assets carry long-lived cache headers. |

## Agent readiness

| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VTA-0067 | `agent` | Agent-readiness base | info | passive | on | — | 0.6.0 | Base finding for the agent-readiness category. |
| VTA-0068 | `agent.ssr-content` | Server-rendered content | medium | passive | on | — | 0.6.0 | Meaningful content is present without running JS (crawlable by agents). |
| VTA-0069 | `agent.llms-txt` | llms.txt | low | probe | on | — | 0.6.0 | A /llms.txt guide for AI crawlers is present. |
| VTA-0070 | `agent.ai-crawlers` | AI-crawler policy | low | probe | on | — | 0.6.0 | robots.txt does not blanket-block AI crawlers unintentionally. |
| VTA-0071 | `agent.structured-data` | Structured data (JSON-LD) | low | passive | on | — | 0.6.0 | JSON-LD structured data helps agents understand the page. |
| VTA-0072 | `agent.manifest` | MCP / app manifest | info | probe | on | — | 0.6.0 | A machine manifest (MCP / web app) is discoverable. |

## Framework-specific

| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VTA-0073 | `framework` | Framework base | info | passive | on | A05; CWE-16 | 0.6.0 | Base finding for the framework category. |
| VTA-0074 | `framework.detected` | Stack fingerprinted | info | passive | on | A05; CWE-16 | 0.6.0 | The app stack was identified with high confidence. |
| VTA-0075 | `framework.none` | No stack-specific issues | info | passive | on | A05; CWE-16 | 0.6.0 | Clean-signal pass for the framework category. |
| VTA-0076 | `framework.next.data-secrets` | Next.js __NEXT_DATA__ secrets | high | passive | on | A05; CWE-16 | 0.6.0 | Server props serialize secrets into __NEXT_DATA__. |
| VTA-0077 | `framework.wp.user-enum` | WordPress user enumeration | medium | probe | on | A05; CWE-16 | 0.6.0 | The WP REST API leaks the user list. |
| VTA-0078 | `framework.django.debug` | Django DEBUG=True | high | probe | on | A05; CWE-16 | 0.6.0 | Django is running with DEBUG enabled in production. |

## Vulnerable components

| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VTA-0149 | `components.server-cve.*` | Server/runtime version has a known CVE | high | passive | on | A06; API8:2023; CWE-1104 CWE-1035 | 0.7.0 | A disclosed Server/X-Powered-By version matches a curated high-signal CVE (Apache/nginx/OpenSSH/OpenSSL/PHP). |
| VTA-0079 | `components.*` | Client library vulnerability | high | passive | on | A06; API8:2023; CWE-1104 CWE-1035 | 0.6.0 | A fingerprinted client-side JS library (retire.js-style) is in a known-vulnerable version range. |
| VTA-0080 | `components.summary` | Client library inventory | info | passive | on | A06; API8:2023; CWE-1104 CWE-1035 | 0.6.0 | Summary of client-side JS libraries detected. |
| VTA-0081 | `components.none` | No vulnerable components | info | passive | on | A06; API8:2023; CWE-1104 CWE-1035 | 0.6.0 | Clean-signal pass — no known-vulnerable client libs. |

## Host & infrastructure

| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VTA-0082 | `host` | Host base | info | probe | on | — | 0.6.0 | Base finding for the host-intel category. |
| VTA-0083 | `host.ip` | Resolved IP(s) | info | probe | on | — | 0.6.0 | The A/AAAA records for the host. |
| VTA-0084 | `host.ptr` | Reverse DNS | info | probe | on | — | 0.6.0 | PTR record for the resolved IP. |
| VTA-0085 | `host.provider` | Hosting provider | info | probe | on | — | 0.6.0 | The hosting/cloud provider inferred from IP/headers. |
| VTA-0086 | `host.cdn` | CDN / edge | info | passive | on | — | 0.6.0 | The CDN/edge fronting the origin. |
| VTA-0087 | `host.exposed` | Origin exposure | low | probe | on | — | 0.6.0 | Whether the origin IP appears reachable behind the CDN. |

## App-type rules (top-20 business archetypes)

| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VTA-0088 | `appstyle.detected` | App type detected | info | passive | on | — | 0.7.0 | The business archetype(s) the homepage was fingerprinted as (drives which type-specific rules run). |
| VTA-0089 | `appstyle.none` | App type not identified | info | passive | on | — | 0.7.0 | No archetype reached the confidence threshold — no type-specific rules ran. |
| VTA-0098 | `appstyle.ecommerce.csp` | Store has a CSP (card-skimmer defense) | high | probe | on | — | 0.7.0 | [E-commerce / online store] A store without a Content-Security-Policy is the prime Magecart target — injected JS can skim card fields. |
| VTA-0099 | `appstyle.ecommerce.hsts` | Store enforces HSTS on payment traffic | high | probe | on | — | 0.7.0 | [E-commerce / online store] Payment pages must never be downgradable to http. |
| VTA-0100 | `appstyle.ecommerce.third-party-scripts` | Third-party scripts on the store are pinned (SRI) | medium | probe | on | — | 0.7.0 | [E-commerce / online store] Every un-pinned third-party script on a store is a potential skimmer injection point. |
| VTA-0101 | `appstyle.saas.frame-protection` | App is protected from clickjacking | medium | probe | on | — | 0.7.0 | [SaaS app / dashboard] An authenticated app framed by an attacker enables clickjacking of privileged actions. |
| VTA-0102 | `appstyle.saas.csp` | App ships a CSP | medium | probe | on | — | 0.7.0 | [SaaS app / dashboard] A dashboard handling user data should constrain script sources. |
| VTA-0103 | `appstyle.marketing.open-graph` | Landing page has Open Graph tags | low | probe | on | — | 0.7.0 | [Marketing / landing site] Marketing links that don't unfurl with a title/image lose clicks when shared. |
| VTA-0104 | `appstyle.marketing.compression` | Landing page is compressed | low | probe | on | — | 0.7.0 | [Marketing / landing site] Conversion drops with load time; an uncompressed landing page is an easy win. |
| VTA-0105 | `appstyle.blog.feed` | Blog exposes an RSS/Atom feed | low | probe | on | — | 0.7.0 | [Blog / news / CMS] A content site without a feed loses syndication and reader tooling. |
| VTA-0106 | `appstyle.blog.article-schema` | Articles carry JSON-LD schema | low | probe | on | — | 0.7.0 | [Blog / news / CMS] Article structured data drives rich results in search. |
| VTA-0107 | `appstyle.auth.https` | Login is served over HTTPS | high | probe | on | — | 0.7.0 | [Auth / login / identity portal] Credentials entered on an http page are sent in clear text. |
| VTA-0108 | `appstyle.auth.no-cache` | Login page is not cached | medium | probe | on | — | 0.7.0 | [Auth / login / identity portal] A cached login/identity page can leak on shared machines and proxies. |
| VTA-0109 | `appstyle.auth.form-secure` | Login form posts to an https target | high | probe | on | — | 0.7.0 | [Auth / login / identity portal] A login <form> whose action is http (or method GET) leaks credentials. |
| VTA-0110 | `appstyle.api.docs-public` | API docs/spec are not wide open | medium | probe | on | — | 0.7.0 | [Headless API / JSON service] A public OpenAPI/Swagger spec hands attackers your full endpoint map. |
| VTA-0111 | `appstyle.api.json-errors` | API returns JSON errors, not HTML stack traces | medium | probe | on | — | 0.7.0 | [Headless API / JSON service] An API that returns an HTML error page for a bad path is likely leaking a framework debug page. |
| VTA-0112 | `appstyle.marketplace.frame-protection` | Marketplace is protected from clickjacking | medium | probe | on | — | 0.7.0 | [Multi-vendor marketplace] Purchase/checkout actions on a marketplace must not be framable. |
| VTA-0113 | `appstyle.marketplace.csp` | Marketplace ships a CSP | medium | probe | on | — | 0.7.0 | [Multi-vendor marketplace] User-generated listings raise XSS risk; a CSP limits the blast radius. |
| VTA-0114 | `appstyle.booking.https` | Booking flow is served over HTTPS | high | probe | on | — | 0.7.0 | [Booking / scheduling / reservations] Booking captures names, contact details and often payment — it must be https. |
| VTA-0115 | `appstyle.booking.csp` | Booking app ships a CSP | medium | probe | on | — | 0.7.0 | [Booking / scheduling / reservations] Payment + PII collection warrants a CSP. |
| VTA-0116 | `appstyle.fintech.hsts` | Fintech enforces HSTS | high | probe | on | — | 0.7.0 | [Fintech / banking / payments] Financial apps must never be downgradable to http. |
| VTA-0117 | `appstyle.fintech.csp` | Fintech ships a strict CSP | high | probe | on | — | 0.7.0 | [Fintech / banking / payments] Money-movement UIs are high-value XSS targets. |
| VTA-0118 | `appstyle.fintech.no-cache` | Fintech responses are non-cacheable | medium | probe | on | — | 0.7.0 | [Fintech / banking / payments] Account/balance data must not be cached by shared proxies or browsers. |
| VTA-0119 | `appstyle.healthcare.https` | Health portal is HTTPS-only | high | probe | on | — | 0.7.0 | [Healthcare / patient portal] PHI must only ever travel over TLS. |
| VTA-0120 | `appstyle.healthcare.no-cache` | Health portal is non-cacheable | medium | probe | on | — | 0.7.0 | [Healthcare / patient portal] PHI must not linger in browser or proxy caches. |
| VTA-0121 | `appstyle.social.csp` | Community app ships a CSP | medium | probe | on | — | 0.7.0 | [Social network / community / forum] User posts/comments make stored XSS the top risk for social apps. |
| VTA-0122 | `appstyle.social.frame-protection` | Community app resists clickjacking | medium | probe | on | — | 0.7.0 | [Social network / community / forum] Framing enables like/follow/post clickjacking. |
| VTA-0123 | `appstyle.chat.csp` | Chat app ships a CSP | medium | probe | on | — | 0.7.0 | [Chat / messaging app] Messages are attacker-controlled content rendered to other users — stored XSS risk. |
| VTA-0124 | `appstyle.chat.frame-protection` | Chat app resists clickjacking | low | probe | on | — | 0.7.0 | [Chat / messaging app] A framed chat UI can be tricked into sending/approving. |
| VTA-0125 | `appstyle.files.nosniff` | File app sends X-Content-Type-Options: nosniff | medium | probe | on | — | 0.7.0 | [File storage / sharing] Without nosniff, an uploaded file can be sniffed and executed as HTML/script. |
| VTA-0126 | `appstyle.files.csp` | File app ships a CSP | medium | probe | on | — | 0.7.0 | [File storage / sharing] A CSP (esp. sandbox / object-src) limits what an uploaded/served file can do. |
| VTA-0127 | `appstyle.admin.noindex` | Admin panel is not search-indexable | low | probe | on | — | 0.7.0 | [Admin / back-office panel] An admin panel showing up in search advertises the attack surface. |
| VTA-0128 | `appstyle.admin.frame-protection` | Admin panel resists clickjacking | medium | probe | on | — | 0.7.0 | [Admin / back-office panel] Admin actions are the highest-value clickjacking target. |
| VTA-0129 | `appstyle.docs.canonical` | Docs pages set a canonical URL | low | probe | on | — | 0.7.0 | [Documentation / knowledge base] Versioned/duplicated docs need canonicals to avoid SEO cannibalization. |
| VTA-0130 | `appstyle.docs.search` | Docs site has search | low | probe | on | — | 0.7.0 | [Documentation / knowledge base] Docs without search are hard to use at any size. |
| VTA-0131 | `appstyle.jobs.schema` | Job posts carry JobPosting schema | low | probe | on | — | 0.7.0 | [Job board / recruitment] JobPosting structured data is required for Google Jobs inclusion. |
| VTA-0132 | `appstyle.jobs.apply-https` | Job board is served over HTTPS | medium | probe | on | — | 0.7.0 | [Job board / recruitment] Applications carry résumés and personal data. |
| VTA-0133 | `appstyle.realestate.schema` | Listings carry structured data | low | probe | on | — | 0.7.0 | [Real estate / property listings] Property structured data drives rich real-estate search results. |
| VTA-0134 | `appstyle.realestate.og` | Listings unfurl when shared | low | probe | on | — | 0.7.0 | [Real estate / property listings] Property links are shared constantly — they should preview. |
| VTA-0135 | `appstyle.lms.csp` | LMS ships a CSP | medium | probe | on | — | 0.7.0 | [Education / LMS / courses] LMS platforms host user/instructor content and often minors' data. |
| VTA-0136 | `appstyle.lms.https` | LMS is served over HTTPS | medium | probe | on | — | 0.7.0 | [Education / LMS / courses] Student records and (often) minors' data require TLS. |
| VTA-0137 | `appstyle.crm.frame-protection` | CRM resists clickjacking | medium | probe | on | — | 0.7.0 | [CRM / sales tool] A framed CRM enables clickjacking of record edits/exports. |
| VTA-0138 | `appstyle.crm.no-cache` | CRM responses are non-cacheable | medium | probe | on | — | 0.7.0 | [CRM / sales tool] Customer records must not be cached by shared proxies. |
| VTA-0139 | `appstyle.support.csp` | Helpdesk ships a CSP | medium | probe | on | — | 0.7.0 | [Support / helpdesk / ticketing] Ticket bodies are attacker-controlled content shown to agents — stored XSS risk. |
| VTA-0140 | `appstyle.support.frame-protection` | Helpdesk resists clickjacking | low | probe | on | — | 0.7.0 | [Support / helpdesk / ticketing] A framed agent console can be clickjacked into actions. |

## AI/LLM attack surface (MITRE ATLAS)

| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VTA-0141 | `atlas.detected` | AI/LLM surface detected | info | passive | on | — | 0.7.0 | An AI/LLM surface was fingerprinted, so ATLAS checks ran (info). |
| VTA-0142 | `atlas.none` | No AI/LLM surface | info | passive | on | — | 0.7.0 | No AI surface detected — ATLAS checks skipped (clean-signal pass). |
| VTA-0143 | `atlas.model-artifact*` | Model artifact publicly downloadable | high | probe | on | AML.T0044 | 0.7.0 | Model weights/artifacts (.gguf/.safetensors/.onnx/.pt/.pkl/.bin) are web-served. |
| VTA-0144 | `atlas.inference-open` | AI inference endpoint reachable | low | probe | on | AML.T0040 | 0.7.0 | An inference/LLM endpoint answers — confirm it requires auth + rate limiting. |
| VTA-0148 | `atlas.model-enum*` | AI server lists models unauthenticated | medium | probe | on | AML.T0040 | 0.7.0 | An OpenAI/Ollama/vLLM-compatible server exposes its model catalogue (/v1/models, /api/tags) without auth. |
| VTA-0145 | `atlas.data-leak*` | AI endpoint leaks system prompt / provider key | high | probe | on | AML.T0057 AML.T0055 | 0.7.0 | An AI endpoint/error exposes the system prompt, model config, or a provider API key. |
| VTA-0146 | `atlas.cost-dos*` | No rate limiting on AI endpoint | high | active | opt-in | AML.T0034 AML.T0029 | 0.7.0 | An expensive AI route is not throttled (cost-harvesting / model-DoS). Opt-in burst (--rate-limit-scan). |
| VTA-0147 | `atlas.prompt-injection*` | LLM prompt injection | high | active | opt-in | AML.T0051 | 0.7.0 | A benign canary instruction overrides the system prompt on a chat endpoint. Opt-in (--ai-probe). |

## Custom plugins

| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VTA-0090 | `plugins` | Plugins base | info | probe | on | — | 0.5.0 | Base finding for user JSON plugin templates. |
| VTA-0091 | `plugins.none` | No plugin templates | info | probe | on | — | 0.5.0 | No custom templates were loaded. |
| VTA-0092 | `plugins.loaded` | Plugin templates loaded | info | probe | on | — | 0.5.0 | Count of custom templates executed. |

## White-box testkit helpers

| # | Check ID | Title | Severity | Class | Default | Standards | Since | What it detects |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VTA-0093 | `testkit.idorProbe` | IDOR / object-access probe | high | white-box | — | — | 0.2.0 | Diffs object access across two identities to catch IDOR/BOLA. |
| VTA-0094 | `testkit.rbacProbe` | RBAC enforcement probe | high | white-box | — | — | 0.6.0 | Confirms role-gated routes reject lower-privilege actors. |
| VTA-0095 | `testkit.dataIsolationProbe` | Tenant data-isolation probe | high | white-box | — | — | 0.6.0 | Confirms tenant A cannot read tenant B's data. |
| VTA-0096 | `testkit.massAssignmentProbe` | Mass-assignment probe | high | white-box | — | — | 0.6.0 | Detects privileged fields accepted from an untrusted body. |
| VTA-0097 | `testkit.findSensitiveFields` | Sensitive-field scan | medium | white-box | — | — | 0.6.0 | Flags PII/secret-looking fields leaking in API responses. |


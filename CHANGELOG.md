# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- npm package renamed from `@newsengine/vibetesting-agent` to the unscoped **`vibetesting-agent`**
  (version 0.6.1) so `npx vibetesting-agent <url>` and `npm install -g vibetesting-agent` work.
  Repository, issue and homepage links now point at `newsengine/vibe-testing-agent`.
- Cloudflare bypass headers are no longer tied to built-in hosts. `x-smoke-key` is sent only to hosts in
  `VTA_SMOKE_KEY_HOSTS` and Cloudflare Access headers only to hosts in `VTA_CF_ACCESS_HOSTS` (both empty
  by default). `isBetaAccessHost` / `BETA_ACCESS_HOST` are replaced by `isCfAccessHost`,
  `hostMatchesAllowlist` and `parseHostAllowlist`. The reusable `probe.yml` takes matching
  `smoke_key_hosts` / `cf_access_hosts` inputs.

### Removed
- A project-specific critical-path subcommand and its example that had been added to this repo; it now
  lives with the project it tested. Its catalog numbers (VTA-0155 to VTA-0164) stay reserved.

### Added
- **Active injection engine (`--authorized-active`, `inject.*`):** opt-in, authorized, **non-destructive**
  parameter-driven testing over the coverage map's real GET parameters — **SQL injection** (error /
  boolean / time-based), **server-side template injection** (7*7→49), **OS command injection**
  (time-based), and **path traversal** (/etc/passwd). GET-only (no writes/DoS/brute-force), bounded, with
  minimal evidence per hit and OWASP A03/CWE mappings. Off by default; prints an authorization notice;
  detectors are pure + unit-tested and the full scan is verified against a vulnerable fixture. [#43, epic #41]
- **Authenticated deep-crawl + coverage map (`--coverage <file.json>`):** a bounded, same-origin BFS that
  (optionally authenticated via `--cookie`/`--header`) discovers the real attack surface — reachable
  endpoints, query parameters, HTML forms (action/method/fields) and referenced `/api` routes — and
  reports how much it reached. Safe (GET navigation only, capped, never leaves the origin). This is the
  foundation the coming authenticated active-testing engines build on. [#42, epic #41]
- **Auto GitHub-issue feed (`--github-issues <owner/repo>`):** turns findings into an idempotent set of
  tracking issues — one per failing check, keyed by VTA number + target host + check id, so re-runs update
  the same issue instead of duplicating and auto-close it when the check passes again. Dry-run by default;
  `--apply` writes via `gh`. Multi-target-safe (never touches another host's issues). [#34]
- **Auto fix pack (`--fix-pack <file.md>`):** a PR-ready remediation doc — consolidated security-header
  config for Next.js / Netlify / nginx / Vercel, plus a per-finding checklist keyed by VTA number and
  grouped by severity. [#35]
- **Server/runtime CVE correlation (`components.server-cve.*`):** a disclosed `Server`/`X-Powered-By`
  version is matched against a curated, low-false-positive table of high-signal CVEs (Apache 2.4.49
  path-traversal/RCE, OpenSSH regreSSHion, OpenSSL X.509 overflow, PHP-FPM RCE, nginx smuggling). [#36]
- **ATLAS model-enumeration check (`atlas.model-enum.*`, AML.T0040):** flags an OpenAI/Ollama/vLLM-style
  server that lists its model catalogue (`/v1/models`, `/api/tags`) unauthenticated; plus a full ATLAS
  coverage matrix at [`docs/atlas.md`](docs/atlas.md). [#37]
- **Stable test numbering (`VTA-NNNN`):** every check/family now carries a permanent number from an
  append-only registry (`src/catalog-numbers.ts`, maintained by `npm run catalog`; numbers are never
  reused, even for retired checks). Numbers appear in `docs/CHECKS.md` and are the key the run-ledger,
  daily report, and (planned) GitHub-issue feed reference. A concrete finding inherits its family's
  number (`header.x-frame-options` → the `header.` family's `VTA-0008`).
- **`atlas` category — MITRE ATLAS AI/LLM attack surface:** when an AI/LLM surface is detected (chat/
  inference markers or endpoints), the scanner runs ATLAS-mapped checks, each citing its technique id —
  downloadable model artifacts (`AML.T0044`), reachable inference endpoint (`AML.T0040`), system-prompt/
  provider-key leakage (`AML.T0057`), unthrottled cost/DoS (`AML.T0034`/`AML.T0029`, opt-in
  `--rate-limit-scan`), and a benign prompt-injection canary (`AML.T0051`, opt-in `--ai-probe`). Only
  runs on a detected AI surface — no false-probing a non-AI app.
- **Run-ledger + Priority-Status report:** every scan produces a DB-ready run record — one row per
  sub-test, keyed by VTA number, with the target, actor, timestamps and a headline priority
  (critical/high/medium/low/clean). `--ledger <file.jsonl>` appends each run (monotonic per-target run
  numbers); `--priority` prints the daily-report cover page (status banner, ranked issues by number,
  trend vs the previous run, category roll-up). The record maps 1:1 to the planned hosted `test_runs` /
  `test_results` database tables.
- **`appstyle` category — app-type-aware rules for the top 20 business archetypes:** the scanner now
  fingerprints *what kind of app* it is from the homepage (e-commerce, SaaS dashboard, marketing site,
  blog/CMS, auth portal, headless API, marketplace, booking, fintech, healthcare, social/community,
  chat, file-sharing, admin panel, docs site, job board, real estate, LMS, CRM, helpdesk) and runs that
  type's extra rules — a store is checked for a card-skimmer CSP + payment HSTS + pinned third-party
  scripts, an auth portal for HTTPS + no-cache + a secure login form, fintech/healthcare for HSTS +
  no-store, and so on. Rules run **only** for a confidently-detected type (top match, or another type
  backed by a strong distinctive signal), mirroring the framework-detection discipline so a store's
  "Careers" link never gets job-board page rules. Detection is homepage-only (no extra requests); every
  rule is listed in `docs/CHECKS.md`.
- **Check catalog — a maintained list of every test (`docs/CHECKS.md`):** `src/catalog.ts` is now the
  single source of truth for every check the scanner runs. Each entry declares its id, category,
  severity, standards refs, the version it shipped in, and — so the tool is no longer a black box about
  its own coverage — how it reaches its verdict (`passive` reads the homepage only, `probe` makes extra
  safe GETs, `active` sends a crafted probe/burst/write, `authenticated` needs `--cookie/--header`,
  `white-box` needs source/tokens/two accounts). `npm run catalog` regenerates the doc, and
  `tests/catalog.test.ts` fails the build if the engine ever emits a finding id that isn't catalogued
  (new check → add its entry) or if the doc drifts. Adding/upgrading checks now keeps the list current.
- **API-surface checks (issue #24):** detections a homepage-only scan missed, all reachable black-box:
  - `api.unauth-data` (**on by default**, GET-only) — flags an `/api/*` route (built-in wordlist +
    routes discovered in the HTML) that answers `200` + a JSON data body with no auth challenge; graded
    high when the body looks like records/PII.
  - `api.cors` (**on by default**) — generalizes CORS-reflection testing to discovered API routes
    (any-origin reflection **with** credentials).
  - `api.unauth-write` (opt-in `--api-write`) — sends a benign no-op POST to write-suggestive routes and
    flags any `2xx`; destructive-sounding verbs are never touched and SPA HTML shells are ignored.
  - `api.rate-limit` (opt-in `--rate-limit-scan`) — autonomously bursts discovered expensive endpoints
    (`ai`, `search`, `export`, …) and expects a `429`; high on compute/LLM paths (budget-DoS).
  - `xss.reflected` (opt-in `--xss`) — injects an inert, non-executing marker into public query params
    and flags unencoded reflection (reflected XSS / HTML injection).
  - `cookie-secure.<name>` — the missing-`Secure`-flag check is now split into its own always-on finding,
    with a `getSetCookie()` fallback that parses the raw header on older runtimes so it never no-ops.
- **`plugins` category — custom JSON check templates:** point `--plugins <dir>` at a folder of JSON
  templates (request + status/header/body matchers with and/or conditions, invertible via `negative`)
  and they run as first-class findings — no code, no fork. Malformed templates are skipped (never fatal);
  GET/HEAD-only and a template cap keep it safe. Schema + examples in `plugins/`.
- **Auto-updating vulnerability feed** for `components`: `npm run update-vuln-db` refreshes the
  known-vulnerable-library table from the retire.js community feed (union-merged with the curated seed,
  currently 12 libraries / 200+ ranges), so it doesn't go stale. Table now lives in `src/vuln-data.ts`.
- **CSRF-protection heuristic** (in `security`): state-changing POST forms lacking an anti-CSRF token,
  SameSite-cookie-aware so it only flags genuinely-unprotected forms (CWE-352 / A01).
- **DOM-XSS** heuristic (in `security`): a URL/`referrer`/`window.name` source flowing directly into an
  `innerHTML`/`document.write`/`eval`/`insertAdjacentHTML` sink in inline script (CWE-79 / A03).
- **`components` category (OWASP A06 — Vulnerable & Outdated Components):** retire.js-style detection
  of vulnerable/outdated client-side JS libraries (jQuery, jQuery UI, Bootstrap, Lodash, AngularJS,
  Handlebars, Moment, axios, DOMPurify, Vue 2, Underscore, Select2), matched against a curated
  known-vulnerable version table. Detects current versions too (no false positives).
- **JWT hygiene** (in `security`): decodes (does not verify) any browser-exposed JWT and flags
  `alg:none`, missing `exp`, over-long lifetime, and non-HttpOnly-cookie storage.
- **Host-header injection** probe (in `security`): flags a spoofed `X-Forwarded-Host` reflected into
  redirects/URLs (password-reset-link / web-cache poisoning).
- **CSRF-protection heuristic** (in `security`): state-changing POST forms lacking an anti-CSRF token,
  SameSite-cookie-aware so it only flags genuinely-unprotected forms (CWE-352 / A01).
- **DOM-XSS** heuristic (in `security`): a URL/`referrer`/`window.name` source flowing directly into an
  `innerHTML`/`document.write`/`eval`/`insertAdjacentHTML` sink in inline script (CWE-79 / A03).
- **Render-health** checks (`browse`/`crawl`): detects rendered error boundaries, framework crash
  overlays, and blank app roots — client-side failures that return HTTP 200 with no console error.
- Open-source release scaffolding: `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, issue/PR templates, and an "authorized use only" disclaimer.

### Changed
- Compliance mapping extended for the new checks (A06/CWE-1104; A02/CWE-347 for `alg:none`;
  A03/CWE-644 for host-header).

## [0.6.0]

Baseline for the changelog. Prior work: 11-category black-box scan (security/secrets/exposure/dns/
reliability/seo/a11y/performance/agent/framework/host), OWASP ASVS L1 / Top 10 / WSTG / CWE mapping,
HTML/PDF report, SARIF + baseline output, opt-in `recon`/`browse`/`crawl`/`separation`/`cve` modes,
and importable white-box helpers (IDOR/RBAC/mass-assignment/data-isolation).

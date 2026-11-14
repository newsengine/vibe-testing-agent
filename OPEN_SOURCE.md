# Open-sourcing VibeTesting Agent / vibetesting-agent

## What is open source

| Package | License | Repo |
|---|---|---|
| **vibetesting-agent** (scanner engine, CLI, Gherkin/agent-report, CI helpers) | Apache-2.0 | https://github.com/newsengine/vibe-testing-agent |
| **vibetesting-agent** (docs, branding, OSS entry README) | Apache-2.0 | https://github.com/newsengine/vibe-testing-agent |

## What stays hosted / commercial

- Multi-tenant dashboard on **vibetestingagent.com**
- WorkOS authentication
- Stripe subscriptions ($25 / $100 / $250)
- Ownership verification orchestration, rate limits, audit storage as a service
- Deploy/commit webhook SaaS queue

The hosted app under `vibetesting-agent/` may be dual-licensed later; today treat production billing secrets and customer data as private.

## Pre-release checklist

- [x] Apache-2.0 LICENSE on scanner
- [x] SECURITY.md, CODE_OF_CONDUCT, CONTRIBUTING
- [x] Authorized-use warnings in CLI + docs
- [x] No customer PII in repo
- [x] npm package name `vibetesting-agent` (unscoped) prepared in package.json
- [ ] First `npm publish --access public` so `npx vibetesting-agent` works
- [x] Agent report + Gherkin + `review` / `init` subcommands
- [x] GitHub repo visibility is **public** (newsengine/vibe-testing-agent)
- [ ] Tag a release (e.g. `v0.7.0`)
- [ ] GitHub Pages for `docs/index.html` (optional)

## Publish steps

```bash
# From the repo root, on the merged main commit
npm login                      # once per machine
npm test
npm pack --dry-run             # sanity-check the tarball contents
npm publish --access public    # prepublishOnly rebuilds dist/
gh release create v$(node -p "require('./package.json').version") --generate-notes
```

Optional: create the `newsengine` organization on npmjs.com (Add Organization, free plan) to reserve
the scope for future scoped packages. The CLI itself is published unscoped as `vibetesting-agent`.

## Community message

> VibeTesting Agent is the hosted product. **vibetesting-agent** is the free forever CLI and library.
> Point it at deploys you own. Use `/security-review` for agent fix packs.

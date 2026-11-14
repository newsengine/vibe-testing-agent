# VibeTesting Agent

**https://vibetestingagent.com**

Free, open-source security scanning for **vibe-coded** apps: ship checks from a URL, agent fix packs, CI gates.

## Open-source scanner

The engine is **[vibetesting-agent](https://github.com/newsengine/vibe-testing-agent)** (Apache-2.0):

```bash
# Install: npx (zero install), or npm install -g vibetesting-agent
# Full black-box scan
npx vibetesting-agent https://your-app.example.com

# Security review → agent markdown + Gherkin
npx vibetesting-agent review https://your-app.example.com

# Scaffold suite into a new repo
npx vibetesting-agent init https://your-app.example.com --name my-app
```

### What it checks

Secrets · exposed config · security headers / TLS / CORS · DNS (SPF/DMARC/CAA) · framework misconfigs · vulnerable client libraries · reliability · SEO · a11y · performance · agent readiness · host intel · custom JSON plugins.

Plus white-box helpers: IDOR, RBAC, tenant isolation, mass assignment.

## License

Documentation and this meta-repo: Apache-2.0.  
Scanner: Apache-2.0 under [newsengine/vibe-testing-agent](https://github.com/newsengine/vibe-testing-agent).

## Authorized use only

Only test systems you own or have explicit written permission to test.

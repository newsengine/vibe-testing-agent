# Security

> Template from `vibetesting-agent`. Copy into a repo and fill in the status column.
> Status: ✅ done · ◻️ open · 🔒 needs infra/credentials.

## Reporting a vulnerability
Email **security@YOURDOMAIN** with steps to reproduce. We acknowledge within 3 business days and ask
you not to disclose publicly until remediated. See `/.well-known/security.txt`.

## Checklist (maps to OWASP ASVS / API Top 10, SOC 2, ISO 27001, CIS, NIST CSF)
### Identity & Access
- [ ] SSO + MFA enforced for staff; quarterly access reviews; same-day offboarding
- [ ] RBAC + least privilege; sensitive actions role-gated; branch protection + Code-Owner review

### Application security
- [ ] AuthZ checked on every request (object + function level)
- [ ] Parameterized queries; input validation/output encoding; no SSRF on outbound fetches
- [ ] Security headers (HSTS/nosniff/Referrer-Policy/Permissions-Policy) + enforced CSP
- [ ] Rate limiting + bot/abuse controls; honeypots on public forms
- [ ] SCA + SAST + tests gate deploy

### Multi-tenancy isolation
- [ ] Every query scoped to tenant at the data layer; cross-tenant (IDOR) tests in CI

### Data protection & key management
- [ ] TLS in transit; encryption at rest; secrets in KMS/secrets-manager (not in code)
- [ ] Envelope encryption / OAuth over stored keys; hash your own tokens
- [ ] Account deletion + full data export (GDPR/CCPA)

### SDLC & supply chain
- [ ] Required review on auth/crypto/billing/migrations; pinned deps + Dependabot + SBOM

### Logging / monitoring / IR
- [ ] Immutable audit logs; alerting on anomalies + silent-failure spikes; written IR plan

### Vuln management / resilience / governance
- [ ] Scheduled scanning + remediation SLAs; annual pen test; security.txt
- [ ] Tested backups/restore (RTO/RPO); SOC 2 / ISO 27001 when upmarket; vendor DPAs; training

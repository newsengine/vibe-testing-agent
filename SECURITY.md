# Security Policy

## Reporting a vulnerability in vibetesting-agent itself

vibetesting-agent is a security tool, so we take issues in the tool seriously. If you find a
vulnerability **in vibetesting-agent** (e.g. a way to make it exfiltrate data, a command-injection in
how it handles a target URL, an SSRF via a redirect, or a way its output leaks secrets it scanned):

- **Do not** open a public issue.
- Use **GitHub → Security → "Report a vulnerability"** (private advisory) on this repository.
- Include a proof-of-concept and the version (`vibetesting-agent --version`).

This is a beta project with no support commitment. Confirmed issues are fixed on a best-effort basis,
and we'll credit you in the release notes unless you prefer to stay anonymous. For anything else, open a
[GitHub issue](https://github.com/newsengine/vibe-testing-agent/issues).

## Reporting a vulnerability you found in *your own* site with vibetesting-agent

vibetesting-agent reports findings on the target you scan. Those belong to **you and the site's owner** —
please report them through that project's own disclosure process, not here.

## Supported versions

Only the latest published version is supported. Please upgrade before reporting.

## Scope & safe harbor

This policy covers the vibetesting-agent codebase. It does **not** authorize testing against any
third-party infrastructure. See [`DISCLAIMER`](README.md#-authorized-use-only) — you are
responsible for having permission to scan any target.

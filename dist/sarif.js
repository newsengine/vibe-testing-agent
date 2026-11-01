// src/sarif.ts
// Render findings as SARIF 2.1.0 so GitHub code scanning can ingest them (upload-sarif action) and show
// each issue in the repo's Security tab. Only FAILING findings become results; passing checks are noise
// in a scanning UI. Rules are de-duplicated by finding id so the Security tab groups them sensibly.
import { refsFor } from './compliance.js';
const LEVEL = {
    high: 'error',
    medium: 'warning',
    low: 'note',
    info: 'note',
};
export function toSarif(findings, opts = {}) {
    // Inconclusive / error results are not security findings — omit them from the Security tab.
    const failing = findings.filter((f) => !f.pass && !f.inconclusive);
    // One rule per distinct finding id — carries the fix as help text so it shows in the Security tab.
    const rules = new Map();
    for (const f of failing) {
        if (rules.has(f.id))
            continue;
        rules.set(f.id, {
            id: f.id,
            name: f.id.replace(/[^A-Za-z0-9]+/g, '_'),
            shortDescription: { text: f.title },
            ...(f.fix ? { help: { text: f.fix } } : {}),
            defaultConfiguration: { level: LEVEL[f.severity] },
            properties: (() => {
                const refs = refsFor(f.id);
                // GitHub code-scanning reads CWE from tags in the `external/cwe/cwe-NNN` form.
                const tags = [...new Set(['security', f.category, ...(refs.cwe ?? []).map((c) => `external/cwe/${c.toLowerCase()}`)])];
                return {
                    category: f.category,
                    tags,
                    ...(refs.cwe ? { cwe: refs.cwe } : {}),
                    ...(refs.owasp ? { owaspTop10: refs.owasp } : {}),
                    ...(refs.asvs ? { asvs: refs.asvs } : {}),
                    // GitHub uses this to bucket code-scanning alerts by security severity.
                    ...(f.severity === 'high' || f.severity === 'medium' ? { 'security-severity': f.severity === 'high' ? '8.0' : '5.0' } : {}),
                };
            })(),
        });
    }
    const results = failing.map((f) => ({
        ruleId: f.id,
        level: LEVEL[f.severity],
        message: { text: f.fix ? `${f.detail}\n\nFix: ${f.fix}` : f.detail },
        // No file coordinates for a black-box scan — anchor to the scanned URL so the alert has a location.
        ...(opts.url ? { locations: [{ physicalLocation: { artifactLocation: { uri: opts.url } } }] } : {}),
        properties: {
            category: f.category,
            severity: f.severity,
            retries: f.retries ?? 0,
            ...(f.quarantined ? { quarantined: true } : {}),
        },
    }));
    return {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [
            {
                tool: {
                    driver: {
                        name: 'vibetesting-agent',
                        informationUri: 'https://github.com/newsengine/vibetesting-agent',
                        version: opts.version || '0.0.0',
                        rules: [...rules.values()],
                    },
                },
                ...(opts.url ? { properties: { scannedUrl: opts.url } } : {}),
                results,
            },
        ],
    };
}

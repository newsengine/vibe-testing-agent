// src/pin.ts
// The exact npm spec that generated files (CI workflow, Gherkin steps, SECURITY.md, agent report) tell
// people to run. Pinned to the version that generated them, so a scaffolded workflow never floats to
// whatever a git default branch happens to hold on the day CI runs.
import { readFileSync } from 'node:fs';
export const NPM_PACKAGE = 'vibetesting-agent';
export const PACKAGE_VERSION = (() => {
    try {
        return JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
    }
    catch {
        return '0.0.0';
    }
})();
/** e.g. "vibetesting-agent@0.6.1" */
export const PINNED_SPEC = `${NPM_PACKAGE}@${PACKAGE_VERSION}`;

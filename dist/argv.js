// src/argv.ts
// Positional-safe argv parsing for the CLI. A token that is the VALUE of an option (e.g. the cookie in
// `--cookie "--authorized-active"`) is never read as a flag, and everything after a bare `--` is
// positional. Pure/testable.
/** Options that take the next token as their value. Everything else starting with "-" is a boolean flag. */
export const VALUE_OPTIONS = new Set([
    '--actor', '--agent-report', '--baseline', '--config', '--cookie', '--cors-path', '--coverage', '--crawl',
    '--cwd', '--fail-on', '--fix-pack', '--gherkin', '--github-issues', '--header', '--ledger', '--level',
    '--max-crawl', '--name', '--only', '--pages', '--pdf', '--plugins', '--ports', '--profile', '--project-name',
    '--rate-limit-path', '--report', '--skip', '--timeout', '--urls', '--write-baseline',
]);
export function parseArgs(argv, valueOptions = VALUE_OPTIONS) {
    const positionals = [];
    const flags = new Set();
    const values = new Map();
    for (let i = 0; i < argv.length; i++) {
        const tok = argv[i];
        if (tok === '--') {
            positionals.push(...argv.slice(i + 1));
            break;
        }
        if (tok.startsWith('-') && tok.length > 1) {
            if (valueOptions.has(tok)) {
                // The next token is this option's value even if it looks like a flag.
                if (i + 1 < argv.length) {
                    const list = values.get(tok) ?? [];
                    list.push(argv[i + 1]);
                    values.set(tok, list);
                }
                i++;
            }
            else {
                flags.add(tok);
            }
            continue;
        }
        positionals.push(tok);
    }
    return { positionals, flags, values };
}

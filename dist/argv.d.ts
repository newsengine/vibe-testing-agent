/** Options that take the next token as their value. Everything else starting with "-" is a boolean flag. */
export declare const VALUE_OPTIONS: ReadonlySet<string>;
export interface ParsedArgs {
    positionals: string[];
    flags: Set<string>;
    values: Map<string, string[]>;
}
export declare function parseArgs(argv: readonly string[], valueOptions?: ReadonlySet<string>): ParsedArgs;

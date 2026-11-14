// tests/argv.test.ts — CLI argv parsing must not read option values as flags.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseArgs } from '../dist/argv.js';

test('argv: an option value that looks like a flag stays a value', () => {
  const p = parseArgs(['https://x.example', '--cookie', '--authorized-active', '--header', 'X-A: --api-write', '--json']);
  assert.deepEqual(p.positionals, ['https://x.example']);
  assert.equal(p.flags.has('--authorized-active'), false);
  assert.equal(p.flags.has('--api-write'), false);
  assert.equal(p.flags.has('--json'), true);
  assert.deepEqual(p.values.get('--cookie'), ['--authorized-active']);
  assert.deepEqual(p.values.get('--header'), ['X-A: --api-write']);
});

test('argv: repeatable options and the -- terminator', () => {
  const p = parseArgs(['review', '--header', 'A: 1', '--header', 'B: 2', '--', '--authorized-active', 'u']);
  assert.deepEqual(p.values.get('--header'), ['A: 1', 'B: 2']);
  assert.deepEqual(p.positionals, ['review', '--authorized-active', 'u']);
  assert.equal(p.flags.has('--authorized-active'), false);
});

test('argv: trailing value option with no value is ignored', () => {
  const p = parseArgs(['u', '--cookie']);
  assert.equal(p.values.get('--cookie'), undefined);
  assert.deepEqual(p.positionals, ['u']);
});

test('cli: db-critical refuses a non-DB host without --i-know-the-host', () => {
  const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
  const r = spawnSync(process.execPath, [cli, 'db-critical', 'https://evil.example'], { encoding: 'utf8', timeout: 20_000 });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--i-know-the-host/);
});

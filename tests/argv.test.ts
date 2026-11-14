// tests/argv.test.ts — CLI argv parsing must not read option values as flags.
import { test } from 'node:test';
import assert from 'node:assert/strict';
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

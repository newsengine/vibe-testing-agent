// tests/pins.test.ts — every command we generate or ship for agents/CI runs an exact package version,
// never a moving git branch, and reusable workflows never interpolate inputs into shell scripts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { PINNED_SPEC, PACKAGE_VERSION } from '../dist/pin.js';
import { initRepo } from '../dist/init.js';
import { renderGherkinStepStub } from '../dist/gherkin.js';
import { renderAgentReport } from '../dist/agent-report.js';

const root = path.resolve(import.meta.dirname, '..');
const read = (p: string) => readFileSync(path.join(root, p), 'utf8');
const pkg = JSON.parse(read('package.json'));

test('pins: PINNED_SPEC is the exact package version', () => {
  assert.equal(PACKAGE_VERSION, pkg.version);
  assert.equal(PINNED_SPEC, `vibetesting-agent@${pkg.version}`);
});

const SHIPPED = [
  '.github/workflows/probe.yml',
  '.github/workflows/audit.yml',
  '.claude/commands/security-review.md',
  '.claude/skills/security-review/SKILL.md',
];

test('pins: shipped workflows and agent commands run an exact version', () => {
  for (const f of SHIPPED) {
    const text = read(f);
    assert.doesNotMatch(text, /npx[^\n]*github:/, `${f} runs a git branch via npx`);
    for (const m of text.matchAll(/npx --yes (vibetesting-agent\S*)/g)) {
      assert.equal(m[1], `vibetesting-agent@${pkg.version}`, `${f}: ${m[0]} is not pinned to ${pkg.version}`);
    }
  }
});

test('pins: reusable workflows keep inputs out of run scripts and set permissions', () => {
  for (const f of ['.github/workflows/probe.yml', '.github/workflows/audit.yml']) {
    const text = read(f);
    assert.match(text, /^permissions:/m, `${f} has no top-level permissions`);
    for (const block of text.split(/\n\s+run: \|/).slice(1)) {
      const script = block.split(/\n\s{0,6}- /)[0];
      assert.doesNotMatch(script, /\$\{\{/, `${f}: expression interpolated into run:`);
    }
  }
});

test('pins: generated files use the pinned spec', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'vta-init-pins-'));
  try {
    initRepo({ cwd: dir, url: 'https://app.example.com/"$(id)"', projectName: 'demo' });
    const wf = readFileSync(path.join(dir, '.github/workflows/security.yml'), 'utf8');
    const sec = readFileSync(path.join(dir, 'SECURITY.md'), 'utf8');
    for (const text of [wf, sec, renderGherkinStepStub(), renderAgentReport([{ id: 'x', category: 'security', title: 't', severity: 'high', pass: false, detail: 'd' }], { url: 'https://a.example' })]) {
      assert.doesNotMatch(text, /github:newsengine/);
      assert.ok(text.includes(PINNED_SPEC), 'pinned spec missing');
    }
    // The target URL reaches the shell via env, not the script body.
    assert.match(wf, /TARGET_URL: "https:\/\/app\.example\.com\/\\"\$\(id\)\\""/);
    assert.doesNotMatch(wf.split('run: |')[1], /\$\(id\)/);
    assert.match(wf, /^permissions:\n {2}contents: read/m);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

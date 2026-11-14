/** Public links for the open-source vibetesting-agent CLI and library. */
const repo = 'https://github.com/newsengine/vibe-testing-agent';

export const OSS_LINKS = {
  repo,
  npm: 'https://www.npmjs.com/package/vibetesting-agent',
  issues: `${repo}/issues`,
  checks: `${repo}/blob/main/docs/CHECKS.md`,
  contributing: `${repo}/blob/main/CONTRIBUTING.md`,
  license: `${repo}/blob/main/LICENSE`,
  security: `${repo}/blob/main/SECURITY.md`,
} as const;

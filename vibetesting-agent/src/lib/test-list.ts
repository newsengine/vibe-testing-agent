/**
 * Full test list derived from the scanner catalog.
 * This file generates the public-facing list of all test names for the landing page,
 * kept in sync with src/catalog.ts automatically.
 */

import { CATALOG, scannerSpecs } from '../../../src/catalog.js';

export interface TestListEntry {
  id: string;
  name: string;
  category: string;
}

/**
 * Generate the full list of test names from the catalog.
 * Dynamic checks (with trailing `.` or marked dynamic) are shown with a `*` suffix.
 */
export function generateTestList(): TestListEntry[] {
  const specs = scannerSpecs();
  return specs.map((spec) => ({
    id: spec.id,
    name: spec.dynamic ? `${spec.title}*` : spec.title,
    category: spec.category,
  }));
}

/**
 * Get unique test names (titles) for display on the landing page.
 * This is a simplified list showing just the human-readable names.
 */
export function getTestNames(): string[] {
  const specs = scannerSpecs();
  const names = new Set<string>();
  for (const spec of specs) {
    names.add(spec.title);
  }
  return Array.from(names).sort();
}

/**
 * Group tests by category for organized display.
 */
export function getTestsByCategory(): Record<string, string[]> {
  const specs = scannerSpecs();
  const byCategory: Record<string, string[]> = {};
  for (const spec of specs) {
    if (!byCategory[spec.category]) {
      byCategory[spec.category] = [];
    }
    byCategory[spec.category].push(spec.title);
  }
  return byCategory;
}

/**
 * Get the total count of tests in the catalog.
 */
export function getTestCount(): number {
  return scannerSpecs().length;
}

/**
 * Category display names for the landing page.
 */
export const CATEGORY_LABELS: Record<string, string> = {
  security: 'Security',
  secrets: 'Secrets',
  exposure: 'Exposure',
  dns: 'DNS & Email',
  reliability: 'Reliability',
  seo: 'SEO',
  a11y: 'Accessibility',
  performance: 'Performance',
  agent: 'Agent Readiness',
  framework: 'Framework',
  components: 'Components',
  host: 'Host & Infrastructure',
  appstyle: 'App-Type Rules',
  atlas: 'AI/LLM (ATLAS)',
  plugins: 'Custom Plugins',
};

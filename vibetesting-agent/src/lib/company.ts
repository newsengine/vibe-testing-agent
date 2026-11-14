/**
 * Operator details shown on the legal pages. Override with NEXT_PUBLIC_LEGAL_NAME /
 * NEXT_PUBLIC_ABN. There is no support email: requests go to GitHub issues.
 */
export const COMPANY = {
  legalName: process.env.NEXT_PUBLIC_LEGAL_NAME || 'Newsengine',
  productName: 'VibeTesting Agent',
  productDomain: 'vibetestingagent.com',
  issuesUrl: 'https://github.com/newsengine/vibe-testing-agent/issues',
  abn: process.env.NEXT_PUBLIC_ABN || '', // optional
} as const;

export function providedByLine(): string {
  return `${COMPANY.productName} is a product of ${COMPANY.legalName}.`;
}

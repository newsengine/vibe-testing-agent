/**
 * Operator details shown on the legal pages. Override with NEXT_PUBLIC_LEGAL_NAME /
 * NEXT_PUBLIC_SUPPORT_EMAIL / NEXT_PUBLIC_ABN.
 */
export const COMPANY = {
  legalName: process.env.NEXT_PUBLIC_LEGAL_NAME || 'Newsengine',
  productName: 'VibeTesting Agent',
  productDomain: 'vibetestingagent.com',
  supportEmail: process.env.NEXT_PUBLIC_SUPPORT_EMAIL || 'security@vibetestingagent.com',
  abn: process.env.NEXT_PUBLIC_ABN || '', // optional
} as const;

export function providedByLine(): string {
  return `${COMPANY.productName} is a product of ${COMPANY.legalName}.`;
}

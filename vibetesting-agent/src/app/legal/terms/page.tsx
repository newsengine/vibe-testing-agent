import Link from 'next/link';
import { COMPANY, providedByLine } from '@/lib/company';

export default function TermsPage() {
  return (
    <LegalLayout title="Terms of Service">
      <p>Last updated: 2026-08-01</p>
      <p>
        <strong>{COMPANY.productName}</strong> (&quot;Service&quot;) is a product of{' '}
        <strong>{COMPANY.legalName}</strong> (same legal entity as our other products — not a separate
        company). By using the Service you agree to these terms.
      </p>
      <h2>1. Authorized use only</h2>
      <p>
        You may only scan systems you own or have explicit written permission to test. You are solely
        responsible for compliance with applicable law (including CFAA, Computer Misuse Act, and local
        equivalents).
      </p>
      <h2>2. No warranty</h2>
      <p>
        The Service is provided AS IS. A clean scan is not a penetration test, security audit, or guarantee
        of safety. Do not rely on {COMPANY.productName} as your only security control.
      </p>
      <h2>3. Subscriptions</h2>
      <p>
        Paid plans renew monthly via Stripe until canceled through the billing portal:
      </p>
      <ul>
        <li>
          <strong>Casual Coding — $25/mo</strong> — about one full scan per week
        </li>
        <li>
          <strong>Business Prototyping — $100/mo</strong> — daily scans and deploy hooks
        </li>
        <li>
          <strong>Mission Critical — $250/mo</strong> — scan on each push/deploy
        </li>
      </ul>
      <p>Fees are non-refundable except where required by law. Invoices are issued by {COMPANY.legalName}.</p>
      <h2>4. Acceptable use</h2>
      <p>
        See our <Link href="/legal/acceptable-use">Acceptable Use Policy</Link>. We may suspend accounts
        that scan unauthorized targets, abuse quotas, or attempt to disrupt the Service.
      </p>
      <h2>5. Data</h2>
      <p>
        We store project URLs, scan findings (with secrets redacted by the scanner), and account metadata.
        See <Link href="/legal/privacy">Privacy</Link>.
      </p>
      <h2>6. Contact</h2>
      <p>
        The software is a beta provided as is, without warranty or support. To report a problem, open a{' '}
        <a href={COMPANY.issuesUrl}>GitHub issue</a>.
      </p>
      <p className="text-xs opacity-70">{providedByLine()}</p>
    </LegalLayout>
  );
}

function LegalLayout({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mx-auto max-w-2xl px-6 py-16">
      <Link href="/" className="mono text-[var(--lime)]">
        ← {COMPANY.productName}
      </Link>
      <h1 className="mono mt-6 text-3xl font-bold">{title}</h1>
      <div className="mt-6 space-y-4 text-sm leading-relaxed text-[var(--mut)] [&_h2]:mt-8 [&_h2]:font-semibold [&_h2]:text-[var(--ink)] [&_a]:text-[var(--lime)] [&_ul]:list-disc [&_ul]:pl-5 [&_strong]:text-[var(--ink)]">
        {children}
      </div>
    </div>
  );
}

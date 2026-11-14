import Link from 'next/link';
import { COMPANY, providedByLine } from '@/lib/company';

export default function PrivacyPage() {
  return (
    <div className="mx-auto max-w-2xl px-6 py-16">
      <Link href="/" className="mono text-[var(--lime)]">
        ← {COMPANY.productName}
      </Link>
      <h1 className="mono mt-6 text-3xl font-bold">Privacy Policy</h1>
      <div className="mt-6 space-y-4 text-sm leading-relaxed text-[var(--mut)]">
        <p>Last updated: 2026-08-01</p>
        <p>
          {COMPANY.productName} is operated by <strong className="text-[var(--ink)]">{COMPANY.legalName}</strong>{' '}
          under the same legal entity as our other products.
        </p>
        <p>
          We collect account information (email, name, auth provider profile), project URLs you configure,
          scan results, API key hashes, Stripe customer identifiers, and audit logs of scan activity.
        </p>
        <p>
          Scan findings may include security issue descriptions. The scanner redacts secret values in
          output. Do not paste production secrets into project names or notes.
        </p>
        <p>
          Processors include hosting, Stripe (payments), WorkOS (authentication), and optional email/Slack
          delivery. We do not sell personal data.
        </p>
        <p>
          Questions: open a <a className="text-[var(--lime)]" href={COMPANY.issuesUrl}>GitHub issue</a>.
        </p>
        <p className="text-xs opacity-70">{providedByLine()}</p>
      </div>
    </div>
  );
}

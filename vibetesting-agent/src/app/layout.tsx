import type { Metadata } from 'next';
import { headers } from 'next/headers';
import { IBM_Plex_Sans, JetBrains_Mono } from 'next/font/google';
import { OSS_LINKS } from '@/lib/oss';
import './globals.css';

const sans = IBM_Plex_Sans({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-sans',
});

const mono = JetBrains_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '700', '800'],
  variable: '--font-mono',
});

export const metadata: Metadata = {
  title: 'vibetesting-agent: open-source security scanner for deployed web apps',
  description:
    'Free, open-source (Apache-2.0) CLI and library that scans any deployed app from a URL: leaked API keys, exposed .env and .git, security headers, broken links, SEO, accessibility and performance. Run it with npx vibetesting-agent or in CI.',
  metadataBase: new URL('https://vibetestingagent.com'),
  alternates: {
    canonical: 'https://vibetestingagent.com',
  },
  openGraph: {
    title: 'vibetesting-agent',
    description: 'Open-source security scanner for deployed web apps. Point it at a URL, get fixes.',
    url: 'https://vibetestingagent.com',
    siteName: 'vibetesting-agent',
  },
};

const jsonLd = {
  '@context': 'https://schema.org',
  '@type': 'SoftwareApplication',
  name: 'vibetesting-agent',
  applicationCategory: 'SecurityApplication',
  operatingSystem: 'Linux, macOS, Windows (Node.js 20+)',
  url: 'https://vibetestingagent.com',
  downloadUrl: OSS_LINKS.npm,
  codeRepository: OSS_LINKS.repo,
  license: 'https://www.apache.org/licenses/LICENSE-2.0',
  isAccessibleForFree: true,
  description:
    'Open-source black-box security scanner and test library for deployed web apps. Zero install with npx.',
  offers: {
    '@type': 'Offer',
    price: '0',
    priceCurrency: 'USD',
  },
};

function OssFooter() {
  return (
    <footer className="mt-auto border-t border-[var(--edge)] bg-black/20">
      <div className="mx-auto flex max-w-6xl flex-col gap-4 px-4 py-8 sm:flex-row sm:items-center sm:justify-between sm:px-5">
        <div>
          <div className="mono text-sm font-bold text-[var(--ink)]">vibetesting-agent</div>
          <p className="mt-1 text-xs text-[var(--mut)]">Open-source security scanner. Apache-2.0. Authorized testing only.</p>
        </div>
        <nav className="flex flex-wrap gap-x-4 gap-y-2 text-xs text-[var(--mut)]">
          <a href={OSS_LINKS.repo} className="hover:text-[var(--lime)]" target="_blank" rel="noreferrer">
            GitHub
          </a>
          <a href={OSS_LINKS.npm} className="hover:text-[var(--lime)]" target="_blank" rel="noreferrer">
            npm
          </a>
          <a href={OSS_LINKS.issues} className="hover:text-[var(--lime)]" target="_blank" rel="noreferrer">
            Issues
          </a>
          <a href={OSS_LINKS.license} className="hover:text-[var(--lime)]" target="_blank" rel="noreferrer">
            License
          </a>
          <a href={OSS_LINKS.security} className="hover:text-[var(--lime)]" target="_blank" rel="noreferrer">
            Security policy
          </a>
        </nav>
      </div>
    </footer>
  );
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = (await headers()).get('x-nonce') ?? undefined;

  return (
    <html lang="en">
      <body className={`${sans.variable} ${mono.variable} antialiased flex min-h-screen flex-col`}>
        <script
          type="application/ld+json"
          nonce={nonce}
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
        <div className="flex flex-1 flex-col">{children}</div>
        <OssFooter />
      </body>
    </html>
  );
}

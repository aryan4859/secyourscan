import Link from 'next/link';
import { IBM_Plex_Mono, IBM_Plex_Sans } from 'next/font/google';
import Header from '../components/Header';
import { Providers } from '../components/motion';
import './globals.css';

const sans = IBM_Plex_Sans({ subsets: ['latin'], weight: ['400', '500', '600'], variable: '--font-sans', display: 'swap' });
const mono = IBM_Plex_Mono({ subsets: ['latin'], weight: ['400', '500'], variable: '--font-mono', display: 'swap' });

export const metadata = {
  metadataBase: new URL(process.env.SITE_URL || 'http://localhost:3000'),
  title: { default: 'SecYourScan: know what’s already out there', template: '%s · SecYourScan' },
  description: 'SecYourScan watches breach data, paste sites, the dark web and your internet-facing systems, and tells you what affects your organisation. Self-hosted. Check an email for free.',
  openGraph: { title: 'SecYourScan', description: 'Breach, dark-web and attack-surface monitoring you run yourself.', type: 'website' },
};

export const viewport = {
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#f7f6f2' },
    { media: '(prefers-color-scheme: dark)', color: '#121214' },
  ],
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body>
        <a className="skip" href="#main">Skip to content</a>
        <Providers>
          <Header />
          <main id="main">{children}</main>
          <footer className="site-foot">
            <div className="wrap">
              <span>© {new Date().getFullYear()} SecYourScan</span>
              <nav aria-label="Footer">
                <Link href="/check">Email check</Link>
                <Link href="/breaches">Breach directory</Link>
                <Link href="/#self-host">Self-host</Link>
              </nav>
            </div>
          </footer>
        </Providers>
      </body>
    </html>
  );
}

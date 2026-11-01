import { Suspense } from 'react';
import Link from 'next/link';
import Directory from './Directory';
import { Reveal, WordsUp } from '../../components/motion';
import { serverApi } from '../../lib/api';
import { big, comma, num } from '../../lib/format';

export const revalidate = 3600;
export const metadata = {
  title: 'Breach directory',
  description: 'Every data breach in the SecYourScan index: when it happened, how many accounts, and what was exposed.',
};

export default async function BreachesPage() {
  const data = await serverApi.allBreaches();
  // Only what the page shows, to keep the payload small.
  const rows = (data?.exposedBreaches || []).map((b) => ({
    id: b.breachID, domain: b.domain || '', industry: b.industry || '', type: b.breachType,
    breached: b.breachedDate, added: b.addedDate, records: num(b.exposedRecords), data: b.exposedData || [],
    description: b.exposureDescription || '', passwordRisk: b.passwordRisk, verified: !!b.verified,
    sensitive: !!b.sensitive, ref: b.referenceURL || '',
  }));
  const total = rows.reduce((n, b) => n + b.records, 0);

  return (
    <>
      <section className="page-top">
        <div className="wrap">
          <WordsUp text="Breach directory" />
          <Reveal as="p" className="lede" delay={0.2}>
            {rows.length ? `${comma(rows.length)} breaches, ${big(total)} records. ` : ''}
            When each happened, how many accounts it touched and what leaked. Click a row for the details.
          </Reveal>
          <Reveal delay={0.3}><Link className="btn quiet" href="/check">Check if you’re in one →</Link></Reveal>
        </div>
      </section>
      <div className="wrap report-end">
        {rows.length
          ? <Suspense fallback={null}><Directory rows={rows} /></Suspense>
          : <p className="muted" style={{ padding: '32px 0' }}>The directory is unavailable right now. Try again in a minute.</p>}
      </div>
    </>
  );
}

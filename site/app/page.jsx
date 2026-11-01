import Link from 'next/link';
import CheckForm from '../components/CheckForm';
import Radar from '../components/Radar';
import { CountUp, GrowBar, Reveal, WordsUp } from '../components/motion';
import { serverApi } from '../lib/api';
import { bigParts, comma, fmtDate, num, parseDate, tidySummary } from '../lib/format';

export const revalidate = 3600;

const CAPS = [
  ['01', 'Leaks', 'Breaches, pastes and the dark web',
    'Onion sites, Telegram channels, paste sites, GitHub and breach dumps, matched against your watchlist. Passwords and keys are masked before anyone sees them. The raw copy stays in your own storage.'],
  ['02', 'Surface', 'Your internet-facing systems',
    'Subdomains from certificate logs and passive DNS. Open ports, TLS grades, SPF/DMARC, expiring certificates. CVEs ranked by whether attackers are exploiting them right now.'],
  ['03', 'Brand', 'Lookalike domains and phishing',
    'Typosquats of your domains that are actually registered, with mail servers and certificates, and live phishing pages that use your name.'],
  ['04', 'Threats', 'Ransomware groups and threat actors',
    'An alert the moment a leak site names you. Profiles of the groups most likely to target your sector, with the MITRE ATT&CK techniques to defend against first.'],
  ['05', 'Suppliers', 'Third-party risk',
    'An outside-in A–F rating for each vendor from public data, and an alert when one of them turns up on a ransomware leak site.'],
  ['06', 'Response', 'Incidents, IOCs and your existing tools',
    'Findings become incidents with an owner and an SLA. Hunt indicators across seven intel sources and share them with your SIEM over STIX/TAXII.'],
];

// Placeholder prices: edit before launch.
const PLANS = [
  { name: 'Free', price: '$0', per: 'forever', blurb: 'For checking yourself.', cta: ['Check an email', '/check'],
    items: ['Unlimited single-email checks', 'Domain exposure summary', 'Full breach directory'] },
  { name: 'Team', price: '$99', per: 'per month', blurb: 'For a small company with one or two domains.', cta: ['Start monitoring', 'mailto:sales@secyourscan.com?subject=Team%20plan'], featured: true,
    items: ['2 verified domains, 250 staff emails', 'Breach, paste and dark-web alerts', 'Attack-surface scans and TLS/DNS checks', 'Lookalike-domain watch', 'Email and Slack alerts'] },
  { name: 'Business', price: '$399', per: 'per month', blurb: 'For security teams that need the full picture.', cta: ['Start monitoring', 'mailto:sales@secyourscan.com?subject=Business%20plan'],
    items: ['10 verified domains, 2,500 staff emails', 'Everything in Team', 'Ransomware leak-site and threat-actor alerts', 'Third-party ratings for 25 suppliers', 'Incidents with SLAs, IOC hunting, STIX/TAXII'] },
  { name: 'Enterprise', price: 'Custom', per: 'annual', blurb: 'For MSSPs and large organisations.', cta: ['Talk to us', 'mailto:sales@secyourscan.com?subject=Enterprise'],
    items: ['Unlimited domains and tenants', 'Signed PDF evidence packs', 'Tamper-evident audit log and SSO', 'MCP server and API access', 'Dedicated support'] },
];

export default async function Home() {
  const [m, pulse] = await Promise.all([serverApi.metricsDetailed(), serverApi.pulse()]);
  const metrics = m || (await serverApi.metrics());
  const recent = (m?.Recent_Breaches || []).slice(0, 6);
  const industries = Object.entries(m?.Industry_Breaches_Count || {}).sort((a, b) => b[1] - a[1]).slice(0, 10);
  const maxInd = industries[0]?.[1] || 1;
  const news = (pulse?.data || [])
    .map((x) => ({ ...x, d: parseDate(x.date) }))
    .filter((x) => x.d)
    .sort((a, b) => b.d - a.d)
    .slice(0, 5);
  const records = bigParts(metrics?.Breaches_Records);
  const pastes = bigParts(metrics?.Pastes_Count);

  return (
    <>
      <section className="hero">
        <div className="wrap hero-grid">
          <div>
            <Reveal as="p" className="label" y={6}>Breach &amp; exposure monitoring</Reveal>
            <WordsUp text="Find out what’s already out there." delay={0.1} />
            <Reveal as="p" className="lede" delay={0.45}>
              Every week somebody’s database ends up on a forum. SecYourScan reads breach dumps, paste sites, ransomware
              leak sites and the dark web, checks your own internet-facing systems, and tells you plainly which parts of it
              are about you.
            </Reveal>
            <Reveal delay={0.6}><CheckForm /></Reveal>
          </div>
          <Reveal delay={0.3} y={0}><Radar items={recent.map((b) => b.breachid)} /></Reveal>
        </div>

        <div className="wrap">
          {metrics ? (
            <Reveal className="stats-line" delay={0.8} y={0}>
              <span className="live">Live index</span>
              <span><b><CountUp value={num(metrics.Breaches_Count)} /></b> breaches</span>
              <span><b><CountUp value={records.value} decimals={records.unit ? 1 : 0} />{records.unit && ` ${records.unit}`}</b> breached records</span>
              <span><b><CountUp value={pastes.value} decimals={pastes.unit ? 1 : 0} />{pastes.unit && ` ${pastes.unit}`}</b> paste records</span>
              <span>last added <b>{fmtDate(metrics.Last_Breach_Added)}</b></span>
            </Reveal>
          ) : <p className="stats-line muted small">Live numbers are unavailable right now.</p>}
        </div>
      </section>

      <section className="block" id="product">
        <div className="wrap">
          <Reveal className="block-head">
            <p className="label">The platform</p>
            <div>
              <h2>One place to see how exposed you are, and what to do first.</h2>
              <p>The check above is the small version. The platform watches everything below for your domains, staff
                emails, brands and suppliers, around the clock.</p>
            </div>
          </Reveal>
          <ol className="caps">
            {CAPS.map(([n, tag, title, body], i) => (
              <Reveal as="li" key={n} delay={i * 0.05}>
                <span className="n">{n} — {tag}</span>
                <h3>{title}</h3>
                <p>{body}</p>
              </Reveal>
            ))}
          </ol>
        </div>
      </section>

      <section className="block">
        <div className="wrap">
          <Reveal className="block-head">
            <p className="label">Recently added</p>
            <div>
              <h2>The newest breaches in our index.</h2>
              <p>Every one of these is searchable. If your company or your staff were in them, the platform would already
                have told you.</p>
            </div>
          </Reveal>
          {recent.length ? (
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Breach</th><th className="num">Accounts</th></tr></thead>
                <tbody>
                  {recent.map((b, i) => (
                    <Reveal as="tr" key={b.breachid} delay={i * 0.05} y={8}>
                      <td><div>{b.breachid}</div><div className="desc">{b.description}</div></td>
                      <td className="num">{comma(b.count)}</td>
                    </Reveal>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <p className="muted small">Recent breaches are unavailable right now.</p>}
          <p className="more"><Link className="arrow-link" href="/breaches">Browse the whole directory <span>→</span></Link></p>
        </div>
      </section>

      <section className="block">
        <div className="wrap two-col">
          <div>
            <Reveal><p className="label">Who gets breached</p><h2 className="h-sub">Breaches by industry</h2></Reveal>
            {industries.length ? (
              <ul className="bars">
                {industries.map(([name, n], i) => (
                  <li key={name}>
                    <Link href={`/breaches?industry=${encodeURIComponent(name)}`}>{name}</Link>
                    <span className="track"><GrowBar pct={(n / maxInd) * 100} delay={i * 0.05} /></span>
                    <span className="v">{n}</span>
                  </li>
                ))}
              </ul>
            ) : <p className="muted small">Unavailable right now.</p>}
          </div>
          <div>
            <Reveal><p className="label">From the news</p><h2 className="h-sub">Breach pulse</h2></Reveal>
            <ul className="news">
              {news.map((x, i) => (
                <Reveal as="li" key={`${x.title}-${i}`} delay={i * 0.06}>
                  <time dateTime={x.d.toISOString().slice(0, 10)}>{fmtDate(x.date)}</time>
                  <div>
                    <h3>{x.url ? <a href={x.url} target="_blank" rel="noopener noreferrer">{x.title}</a> : x.title}</h3>
                    <p>{tidySummary(x.summary)}</p>
                  </div>
                </Reveal>
              ))}
              {!news.length && <li className="muted small">News is unavailable right now.</li>}
            </ul>
          </div>
        </div>
      </section>

      <section className="block" id="pricing">
        <div className="wrap">
          <Reveal className="block-head">
            <p className="label">Pricing</p>
            <div>
              <h2>Start free. Pay when you want it watching for you.</h2>
              <p>Every paid plan includes continuous monitoring, alerts and verified-domain detail. Prices are per
                organisation, billed monthly or yearly.</p>
            </div>
          </Reveal>
          <ol className="plans">
            {PLANS.map((p, i) => (
              <Reveal as="li" key={p.name} delay={i * 0.05} className={p.featured ? 'featured' : undefined}>
                <p className="label">{p.name}{p.featured && <span className="tag">Popular</span>}</p>
                <p className="price"><b>{p.price}</b> <span>{p.per}</span></p>
                <p className="blurb">{p.blurb}</p>
                <ul>{p.items.map((x) => <li key={x}>{x}</li>)}</ul>
                <Link className={p.featured ? 'btn' : 'btn quiet'} href={p.cta[1]}>{p.cta[0]}</Link>
              </Reveal>
            ))}
          </ol>
          <Reveal as="p" className="note">
            SecYourScan is for monitoring assets your organisation owns or is authorised to monitor. It matches what it
            finds against your watchlist and nothing else. There is no people-search and no profiling of individuals.
          </Reveal>
        </div>
      </section>

      <section className="cta">
        <div className="wrap">
          <WordsUp as="h2" text="Start with one address. Then watch all of them." onView />
          <Reveal as="p" className="muted" delay={0.2}>Check yourself now, or set the platform up for your team.</Reveal>
          <Reveal className="row" delay={0.3}>
            <Link className="btn" href="/check">Check an email</Link>
            <Link className="btn quiet" href="/#pricing">See pricing</Link>
          </Reveal>
        </div>
      </section>
    </>
  );
}

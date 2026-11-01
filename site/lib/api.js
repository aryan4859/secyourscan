// SecYourScan public breach API. Change the host here or with NEXT_PUBLIC_BREACH_API.
// It is a separate host from the website (secyourscan.shyenasec.com): /v1/* on
// the website itself is just the Next.js 404 page.
export const API = process.env.NEXT_PUBLIC_BREACH_API || 'https://secyourscanapi.shyenasec.com/v1';

async function get(path, init) {
  const res = await fetch(API + path, { headers: { Accept: 'application/json' }, ...init });
  if (!res.ok) throw new Error(`The breach API answered ${res.status}. Try again in a minute.`);
  return res.json();
}

// Server side: cached and refreshed hourly. A failure returns null so a page
// still renders and the section shows a quiet fallback.
const hourly = { next: { revalidate: 3600 } };
const safe = (p) => p.catch(() => null);

export const serverApi = {
  metricsDetailed: () => safe(get('/metrics/detailed', hourly)),
  metrics: () => safe(get('/metrics', hourly)),
  pulse: () => safe(get('/pulse', hourly)),
  allBreaches: () => safe(get('/all-breaches/', hourly)),
};

// Browser side: live, per search.
export const clientApi = {
  checkEmail: (email) => get(`/check-email/?email=${encodeURIComponent(email)}`, { cache: 'no-store' }),
  breachAnalytics: (email) => get(`/breach-analytics/?email=${encodeURIComponent(email)}`, { cache: 'no-store' }),
  domainSummary: (domain) => get(`/domain-breaches-summary?domain=${encodeURIComponent(domain)}`, { cache: 'no-store' }),
};

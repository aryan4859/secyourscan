# SecYourScan — marketing site

Next.js 16 (App Router) + [Motion](https://motion.dev) for animation. Plain CSS: no UI kit, no Tailwind.

| Route | What it does | API (`secyourscanapi.shyenasec.com/v1`) | Rendering |
|---|---|---|---|
| `/` | Landing page: email/domain check, live index numbers, radar of the newest breaches, recent breaches, breaches by industry, breach news | `/metrics/detailed` (falls back to `/metrics`), `/pulse` | Static, re-generated hourly |
| `/check?email=…` / `?domain=…` | Breach report for an email, summary for a domain | `/check-email/`, `/breach-analytics/`, `/domain-breaches-summary` | Client side, live |
| `/breaches` | Searchable directory of every indexed breach (`?q=`, `?industry=` deep links) | `/all-breaches/` | Static, re-generated hourly |

The API host is in `lib/api.js`. Override it with `NEXT_PUBLIC_BREACH_API` at build time.
The email/domain check runs in the visitor's browser, so the API has to send CORS
headers for the site's origin. It currently reflects the request `Origin`.

## Develop

```bash
cd site
npm install
npm run dev          # http://localhost:3000
```

## Deploy

```bash
npm run build
npm start            # Node server on :3000, or deploy to Vercel / any Node host
```

Set `SITE_URL` (for example `https://secyourscan.com`) so Open Graph URLs are absolute.

## Motion

All motion lives in `components/motion.jsx` and `components/Radar.jsx`. It uses
one easing curve (`EASE`), short durations, and plays once, except the radar
sweep and the "live" dot.

* `WordsUp`: headline rises in word by word.
* `Reveal`: fade and 14px rise as a block scrolls into view.
* `CountUp`: numbers count up when visible; the server HTML has the real value.
* `GrowBar`: bars grow to their value (industries, years, password storage).
* Radar: blips are the newest breaches and brighten as the sweep passes over them.
* Tabs and nav use a shared `layoutId` underline that slides between items.

`MotionConfig reducedMotion="user"` plus a CSS media query turn all of it off for
visitors whose OS asks for reduced motion.

## Writing rules

* API text is always rendered as text, never as HTML.
* Copy is plain and specific, and claims match what the product does. No invented
  customer logos, testimonials or numbers: every number on the site comes live
  from the API.
* One accent colour (`--accent`). Light and dark follow the OS setting.

# Dark Web Recon

Collectors fetch candidate documents from outside sources and hand each one to
[the pipeline](/guide/pipeline). They live in `backend/app/services/recon.py`;
`services/collect.py` runs them, feeds the results through `process_leak`, and
records a `SourceRun` for every collection.

## Legal and ethical use

SecYourScan is for monitoring **your own organisation's** exposure: the domains,
mailboxes, keywords, IPs and wallets that belong to you. Point it at those.

- Searching for, collecting, or storing personal data about people who are not
  part of your organisation's assets is outside what this tool is for, and may
  be unlawful where you operate. There is no identity or person-profiling
  feature, by design.
- Collected material frequently contains other people's personal data and
  credentials. Storing it makes you a controller of that data under GDPR and
  similar regimes. Have a lawful basis, a retention period and a deletion
  procedure before you run collectors against real sources.
- Do not use recovered credentials to log in anywhere, including your own
  systems, except through your normal incident-response process.
- Respect the terms of the services you query. GitHub and HIBP require API
  keys and have usage terms; Telegram's public preview and Ahmia are public
  web pages with rate expectations. The collectors pause between requests;
  they do not otherwise throttle.
- Accessing onion services may itself be regulated in your jurisdiction. Take
  advice first.

## Collectors

| Kind | Fetches | Network | Needs |
|---|---|---|---|
| `ahmia` | Ahmia search results for a term (first 100) | Tor if `TOR_PROXY` is set, **otherwise clearnet** | — |
| `onion` | breadth-first crawl of one `.onion` site, same host only | Tor only | `TOR_PROXY` |
| `telegram` | the last 30 messages of a public channel's web preview | clearnet | — |
| `github` | code search for an exact phrase, 20 results | clearnet | `GITHUB_TOKEN` |
| `hibp` | breaches for one email address | clearnet | `HIBP_API_KEY` |
| `feed` | up to 50 items from a JSON list or an RSS/Atom feed | Tor if the host is `.onion`, else clearnet | — |

### Ahmia

`recon.ahmia_search`. The query is sanitised to letters, digits, `@ . - + "
'` and spaces, 2–128 characters. The collector first loads Ahmia's landing page
to pick up the rotating hidden form field — without it the search endpoint
returns an empty page — then makes a single search request and parses the
`li.result` entries, keeping the first 100 (`total_hits` in the report is how
many Ahmia returned). Ahmia serves every hit on one page, and adding a `page`
parameter makes it answer `500` (observed October 2026), so there is no
pagination. Each result becomes a candidate with the title, the onion URL and
the description as its content.

When Tor is available, the first five `.onion` result URLs are also fetched (one
page each, through the onion crawler) and fed to the pipeline as their own
candidates.

`via_tor` is recorded on the run and on each candidate either way, so you can
tell afterwards which queries left your network in the clear.

::: warning The parser depends on Ahmia's markup
Selectors are `form#searchForm`, `li.result`, `cite`, `h4` and `p`. When Ahmia
changes its HTML, results silently drop to zero with run status `ok`.
:::

### Onion crawler

`recon.crawl_onion`. Refuses anything whose host does not end in `.onion`, and
refuses to run without `TOR_PROXY`. From the seed URL it follows links on the
**same host** only, breadth first, until it has visited `max_pages` pages (the
source's setting, or `CRAWL_MAX_PAGES`; never more than 50). Each response is
read up to `CRAWL_MAX_BYTES` (1 MiB) and skipped if it is not HTML. Script,
style and noscript elements are removed and the visible text becomes the
candidate. Two seconds between pages; 60-second timeout per request.

### Telegram

`recon.telegram_channel`. Fetches `https://t.me/s/<channel>` — the public web
preview Telegram serves to anyone — and parses the message widgets. No Bot API,
no account, no API ID or hash. It follows that it sees only channels Telegram
exposes publicly, only their most recent page of messages, and that it goes out
over the clearnet from your server's address. The channel name must be a valid
Telegram username (4–32 letters, digits or underscores, starting with a letter); `@name` and
`https://t.me/name` are accepted.

### GitHub

`recon.github_code_search`. GitHub's code search API with the term quoted as an
exact phrase and text-match fragments requested; each hit's repository, path
and matching fragments become the candidate. Needs `GITHUB_TOKEN`; without it
the run ends with status `error` and the message `GITHUB_TOKEN is not
configured`.

### Have I Been Pwned

`recon.hibp_breaches`. `GET /api/v3/breachedaccount/<email>` with the full
response. Each breach becomes a candidate naming the email, breach, date and
data classes, with HIBP's description as text. A `404` means no breaches. Needs
`HIBP_API_KEY`. Because each HIBP candidate contains the watched address, it
matches the watchlist and scores at least 25.

### Feeds

`recon.feed_items`. Any http(s) URL that resolves to a public address —
loopback, private, link-local and other non-global addresses are refused with
`422` when the source is created and again when it is fetched, and redirects are
not followed (see
[Server-side request protection](/guide/security#server-side-request-protection)).
A JSON response may be a list or an object
with `items` or `data`; each element's `content`, `text` or `body` becomes the
candidate. Anything else is parsed as RSS/Atom `item`/`entry` elements. A
`.onion` host is fetched through Tor.

## Sources and scheduling

A `Source` is a recurring collector. Sources are per tenant.

| Field | Meaning |
|---|---|
| `kind` | one of the six above |
| `target` | required for `onion` (must contain `.onion`), `telegram` and `feed` (must be a public http(s) URL or a `.onion` one); optional for `ahmia`, `github`, `hibp` |
| `interval_minutes` | 15 – 10,080 (one week); default 360 |
| `max_pages` | 1 – 50; used by the onion crawler; default 10 |
| `is_active` | inactive sources are not scheduled |

**Sweeps.** An `ahmia`, `github` or `hibp` source **without** a target runs
once per matching active watch item:

| Kind | Watch item types swept |
|---|---|
| `ahmia` | `domain`, `keyword`, `email` |
| `github` | `domain`, `keyword` |
| `hibp` | `email` |

Bootstrap creates one Ahmia sweep source (every 720 minutes) for the first
tenant. Tenants created later through `POST /tenants` start with none.

**Scheduling.** Celery beat runs `dispatch_due_sources` every five minutes. It
selects active sources whose `last_run_at` is empty or older than their
interval, stamps `last_run_at` immediately so the next tick does not dispatch
them again, and queues `run_source_task` for each on the `osint` queue. The
effective granularity is therefore five minutes.

::: warning Scheduling needs a broker and beat
Without `RABBITMQ_URL` there is no beat, and no source ever runs on its own.
`POST /sources/{id}/run` still works inline. In both modes, a source that is
inactive is skipped, including by "run now".
:::

## SourceRun provenance

Every collection writes a `SourceRun` row before it starts and updates it when
it ends, whether it succeeded or not:

| Field | Meaning |
|---|---|
| `kind`, `query` | what was asked — the target, or the swept watch value |
| `source_id` | the source, or empty for a one-off probe |
| `status` | `running`, `ok` or `error`; bulk jobs can also end `truncated` |
| `results` | candidates returned by the collector |
| `new_leaks` (`queued` in the table) | candidates that created a new leak rather than a sighting |
| `via_tor` | whether the request went through Tor |
| `error` | the exception text, up to 1,000 characters |
| `report` | for Ahmia, the raw result list (up to 100); for bulk jobs, the scan statistics |
| `started_at`, `finished_at` | timestamps |

`GET /sources/runs` lists runs (optionally `?source_id=`), and
`GET /sources/runs/{id}` includes the `report`. A run that returned results but
`new_leaks: 0` found only material already seen in this tenant.

## One-off probes

| Endpoint | Does | Scope | Audited as |
|---|---|---|---|
| `GET /recon/darkweb?q=` | queues an Ahmia query (`osint`) | `recon` | `DARK_WEB_RECON` |
| `GET /recon/telegram?channel=` | queues a Telegram read (`osint`) | `recon` | `TELEGRAM_RECON` |
| `GET /recon/shodan?ip=` | synchronous Shodan InternetDB lookup, see [CTI](/guide/soar-and-cti#shodan-internetdb) | `recon` | `SHODAN_RECON` |
| `POST /sources/{id}/run` | queues a source now | `recon` | `RUN_SOURCE` |

The Ahmia and Telegram probes answer `202` with `{"mode": "queued", "task_id":
…}` and their output arrives as leaks and as a `SourceRun`. The audit entry is
written **when the probe is queued**, before it runs, so the audit log records
attempts; the run records outcomes. These probes are `GET` requests with side effects, so the CSRF check — which
covers only non-`GET` methods — does not apply to them. What stops a
cross-site page from triggering one through a logged-in browser is the session
cookie's `SameSite=Strict`, not the CSRF token. See
[Known gaps](/guide/security#known-gaps).

## What goes through Tor

| Request | Route |
|---|---|
| Ahmia search, with `TOR_PROXY` set | Tor |
| Ahmia search, without it | **clearnet** |
| Onion crawl, and the follow-up fetch of Ahmia results | Tor (refuses otherwise) |
| Feed with a `.onion` host | Tor |
| Feed with a clearnet host, Telegram, GitHub, HIBP | clearnet |
| Bulk ingestion from a URL | clearnet |
| mempool.space, ThreatFox, Shodan InternetDB | clearnet |
| SOAR webhook, model server | direct |

Tor requests use `socks5h://`, so name resolution happens inside Tor and the
`.onion` name never reaches your resolver.

## Errors

A collector failure — Tor down, Ahmia answering 403, a missing API key — sets
the run's `status` to `error` with the message, and the task itself succeeds.
Look at `GET /sources/runs` rather than worker logs first.

# Search

Three search surfaces: the leak search API (Elasticsearch, falling back to
SQL), the Ctrl+K palette in the web app, and the search box on this site.

## Leak search: `GET /leaks/search`

Scope `read`. Parameters:

| Parameter | Type | Notes |
|---|---|---|
| `q` | string, ≤ 256 | free text; empty or absent means "everything" |
| `min_severity`, `max_severity` | 0–100 | inclusive range |
| `source` | string, repeatable | `?source=paste&source=telegram` |
| `status` | repeatable | `new`, `reviewing`, `escalated`, `resolved`, `false_positive` |
| `category` | string | `CREDENTIALS`, `FINANCIAL`, `PII`, `SOURCE`, `OTHER` |
| `limit` | 1–100, default 25 | |
| `offset` | 0–10,000 | Elasticsearch's default result window |

The response says which engine answered:

```json
{
  "engine": "elasticsearch",
  "total": 3,
  "items": [
    {
      "id": "…", "source": "paste", "severity": 100, "category": "CREDENTIALS",
      "status": "new", "watch_matches": [ … ], "yara_rules": ["combo_list"],
      "snippet": "user0@acme.example.com:S**********!", "…": "…",
      "score": 7.41,
      "highlights": ["user0@<mark>acme.example.com</mark>:S**********!"]
    }
  ],
  "facets": {
    "sources": {"paste": 2, "telegram": 1},
    "categories": {"CREDENTIALS": 3},
    "severity": {"critical": 2, "high": 1, "medium": 0, "low": 0}
  }
}
```

### With Elasticsearch

`services/search_index.search`:

- **Tenant filter on every query.** A `term` filter on `tenant_id` is the first
  clause of every search, and the ids Elasticsearch returns are re-read from
  PostgreSQL with the tenant checked again. A document that somehow carried
  the wrong tenant would still not be returned.
- **Query.** `simple_query_string` with `default_operator: and` and
  `lenient: true`, so operators like `"exact phrase"`, `-exclude` and `prefix*`
  work and malformed syntax does not error. Fields and boosts:

  | Field | Boost |
  |---|---|
  | `emails`, `watch_matches` | 4 |
  | `title`, `domains` | 3 |
  | `ips`, `wallets` | 2 |
  | `content`, `source_url` | 1 |

- **Highlights.** Up to three 160-character fragments of `content`, plus
  `title`, wrapped in `<mark>…</mark>` with the HTML encoder, so markup in leak
  text is escaped before the tags are added.
- **Facets.** `sources` (top 20), `categories` (top 10) and `severity` in fixed
  buckets: critical ≥ 80, high 60–79, medium 30–59, low < 30. These buckets
  are hard-coded and do **not** follow `CRITICAL_THRESHOLD`.
- **Order.** By relevance when `q` is given; otherwise by severity, then
  discovery time, both descending.

Only **masked** text is indexed, so a highlight never shows a secret.

::: warning The index is written once
A leak's document is indexed when the leak is created. Afterwards only two
things update it: a status change (through `PATCH /leaks/{id}/status` or the
Co-Analyst's `flag_leak` tool) updates `status`, and a near-duplicate re-match
updates `severity` and `watch_matches`. Each update is best-effort: if it fails,
the document keeps its old values and nothing retries. Leaks whose initial
indexing failed are never re-indexed.
:::

### Without Elasticsearch — the SQL fallback

Used when `ES_URL` or `ES_PASSWORD` is unset, and on **any** Elasticsearch
error, including an open circuit breaker. The same parameters apply:

- `q` is matched with `ILIKE '%q%'` against the masked **snippet** (the first
  4,000 characters only), the title and the source URL. `%`, `_` and `\` in the
  query are escaped and match literally — verified by
  `test_sql_search_fallback_escapes_wildcards`.
- Order is severity, then discovery time, both descending. `score` is `null`
  and `highlights` is empty.
- `facets` contains only `sources`, counted over the whole tenant, ignoring the
  other filters.

If your search tooling depends on facets or relevance, check `engine` in the
response rather than assuming.

## Listing without full text: `GET /leaks/`

Filters by `source`, `status`, severity range and `watch_item_id`, ordered by
discovery time, newest first, `limit` up to 500. It never touches Elasticsearch.
The `watch_item_id` filter has caveats, described on
[Watchlist & Alerting](/guide/watchlist#listing-leaks-for-one-item).

## The Ctrl+K palette

The web app has a global command palette on **Ctrl+K** (⌘K on macOS), or the
search button in the header. It is `frontend/src/CommandMenu.jsx`, built on
`cmdk` like naso's, with one difference: naso's palette filters only what is
already in memory, while this one also queries the API.

- **On open, with no query,** it lists up to eight open critical leaks —
  `GET /leaks/search?min_severity=80&status=new&status=reviewing&status=escalated&limit=8`.
- **After two characters** (debounced 200 ms) it calls
  `GET /leaks/search?q=…&limit=10`, so leaks outside the page on screen are
  reachable. Each remote hit carries the query as a `cmdk` keyword, so the
  client-side fuzzy filter never hides a server-side match. Results inherit
  whichever engine answered, and the same tenant scoping.
- **Navigation** entries for every page, fuzzy-matched on label and keywords.
- **Quick actions:** verify the audit chain, acknowledge all critical leaks
  (with a confirmation; `min_severity=80`), export the signed dossier, export
  the CSV, add a watch item, show critical leaks, and "search all leaks for …"
  which opens the Leaks page with the query.

| Key | Action |
|---|---|
| `Ctrl`/`⌘` + `K` | open or close |
| `↑` `↓` | move |
| `Enter` | run the selected item |
| `Esc` | close |

The palette's "critical" is a fixed 80; it does not read `CRITICAL_THRESHOLD`.

## Searching these docs

Press <kbd>/</kbd> or <kbd>Ctrl</kbd>+<kbd>K</kbd> on this site. It is VitePress
local search, configured in `docs/.vitepress/config.js` exactly as naso does
it: at build time each page is split at its headings and every section becomes a
MiniSearch document; the index ships as a lazy-loaded chunk and is searched in
the browser. No server and no third-party service. The tuning is written out
explicitly:

```js
search: {
  provider: 'local',
  options: {
    miniSearch: {
      searchOptions: { fuzzy: 0.2, prefix: true, boost: { title: 4, text: 2, titles: 1 } },
    },
  },
},
```

`fuzzy: 0.2` tolerates a typo in roughly one character in five, `prefix: true`
matches as you type, and the boosts rank a hit in a heading above one in body
text.

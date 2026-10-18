# Watchlist & Alerting

The watchlist is the list of things your organisation owns and wants to hear
about. Every leak is matched against it, the scheduled sweeps query sources for
it, and the bulk ingester uses it as a pre-filter. It is the closest thing
SecYourScan has to naso's Identity Hub, and it is deliberately not one: there
are no people, no profiles, no merging and no identity graph. A watch item is an
asset, and a match is a fact about one leak.

The **Topology** page (`GET /leaks/topology`) draws watch items and the leaks
that matched them as a force-directed graph, so assets that share a leak
cluster together. Its edges are watch matches only: entities extracted from
leak text (other people's addresses, names, wallets) never become nodes, and
nothing is merged.

## Watch item types

| Type | Accepted value | Normalised on save |
|---|---|---|
| `domain` | a hostname with a TLD of 2–24 letters | NFKC, lower-cased, trailing `.` and leading `www.` removed |
| `email` | `local@domain.tld` | NFKC, lower-cased; for `gmail.com`/`googlemail.com`, dots and `+tag` removed from the local part and the domain set to `gmail.com` |
| `keyword` | any text, 3–255 characters | trimmed only |
| `ip` | an IPv4 address | must parse as IPv4; IPv6 is rejected |
| `wallet` | any text, 3–255 characters | trimmed only; no address validation |

`(tenant, type, value)` is unique — adding the same item twice answers `409`.
Each item has `is_vip` and `is_active` flags.

## Matching rules

`pipeline.match_watchlist`. Only **active** items are matched. Values are
normalised again at match time as above (keywords and IPs lower-cased).

| Type | Matches when | `hits` recorded |
|---|---|---|
| `domain` | an extracted email ends in `@<domain>` or `.<domain>` (so `ceo@mail.acme.com` matches `acme.com`); otherwise, the domain or a subdomain appears in the extracted domains | up to 20 matching emails, or the domain itself |
| `email` | the address is among the extracted emails, **or** is the identifier of a credential line | the address |
| `ip` | the address is among the extracted IPv4s | the address |
| `wallet` | the value is among the extracted Bitcoin or Monero addresses, compared case-sensitively | the value |
| `keyword` | the lower-cased value is a **substring** of the lower-cased content | the keyword |

Things this implies, which are worth knowing before you add items:

- **Keywords are substrings, not words.** `acme` matches `acmeplumbing` and
  `macmeal`. Prefer distinctive keywords — a project codename, an internal
  hostname — over a short brand name.
- **Domain matching is suffix-based on a dot boundary.** `acme.com` does not
  match `notacme.com`, and does match `vpn.eu.acme.com`.
- **A domain match relies on extraction.** A domain inside a URL path or
  concatenated with other text that the domain regex does not isolate will not
  match; a keyword with the same value would.
- **Gmail variants match.** On save, `john.doe+news@gmail.com` is stored as
  `johndoe@gmail.com`; at match time the emails extracted from the leak (and
  credential identifiers containing `@`) are normalised the same way, so
  `john.doe@gmail.com` and `johndoe+x@googlemail.com` in a leak both match.
  Verified by `test_gmail_watch_item_matches_dotted_variant`. (Earlier only the
  watch item was folded, and dotted forms in leaks did not match.) The `hits`
  recorded for a domain match show the normalised form.

## VIP items

`is_vip` does three things, and only these:

1. **+15 to the score** of any leak that matches a VIP item (on top of the +25
   for any match). See [Scoring](/guide/pipeline#_6-scoring).
2. **A notification below the critical threshold.** A VIP match that scores
   under `CRITICAL_THRESHOLD` still produces a `vip`-level notification titled
   `[VIP] exposure (<score>) from <source>`.
3. **A webhook below the SOAR threshold.** A VIP match that scores under
   `SOAR_THRESHOLD` still fires the SOAR webhook, as `alert_type:
   VIP_EXPOSURE`, `tag: "[VIP]"`.

Use it for the handful of assets where any sighting matters — the CEO's
mailbox, the domain of a payment system — not as a general priority flag.

## Alerting

Alerting is the tail of the pipeline:

| Condition | Notification | SOAR webhook |
|---|---|---|
| score ≥ `SOAR_THRESHOLD` (90) | `critical` | `CRITICAL_EXPOSURE` |
| `CRITICAL_THRESHOLD` (80) ≤ score < 90 | `critical` | — unless VIP |
| score < 80, VIP match | `vip` | `VIP_EXPOSURE` |
| score < 80, no VIP match | — | — |

A near copy that gains new matches can also raise a `critical` or `vip`
notification (titled `Re-posted leak now matches …`), but never fires the
webhook.

Notifications are rows, listed by `GET /notifications` (`?unacknowledged=true`
to filter) and acknowledged with `POST /notifications/{id}/ack`. There is no
email, Slack or push delivery; to get alerts out of the box, point the
[SOAR webhook](/guide/soar-and-cti) at whatever you use. Acknowledging a
notification is not audited.

Leaks themselves have a separate acknowledgement and a triage status:

| Endpoint | Effect | Audited as |
|---|---|---|
| `PATCH /leaks/{id}/status` | `new`, `reviewing`, `escalated`, `resolved` or `false_positive`. `reviewing`, `resolved` and `false_positive` also set `acknowledged_at` if unset. | `UPDATE_LEAK_STATUS` |
| `POST /leaks/{id}/ack` | sets `acknowledged_at` | `ACKNOWLEDGE_LEAK` |
| `POST /leaks/ack-all?min_severity=80` | acknowledges every unacknowledged leak at or above the given score | `ACKNOWLEDGE_ALL_CRITICAL` |

`GET /leaks/stats` reports `critical_open`: leaks at or above
`CRITICAL_THRESHOLD` that are unacknowledged and not `resolved` or
`false_positive`.

::: info `ack-all`'s `min_severity` is not the SOAR threshold
`POST /leaks/ack-all` defaults to 80 and decides which stored leaks are marked
acknowledged. It has nothing to do with the webhook, whose threshold is
`SOAR_THRESHOLD`. naso's docs once confused the two.
:::

## Changing the watchlist does not re-score

Matching happens when a leak is processed, and again when a **near** copy of it
arrives later (see [Deduplication](/guide/pipeline#_2-deduplication)) — a
re-post is matched against the watchlist as it is at that moment, and new
matches are added. Otherwise, adding `acme.com` today does not mark last
month's leaks that mention it; removing an item does not clear old
matches; flipping VIP does not re-score. To find older material for a new
item, search for it — [Search](/guide/search) covers stored leaks regardless
of what was on the watchlist when they arrived.

## Listing leaks for one item

`GET /leaks/?watch_item_id=<id>` filters by a watch item. The filter is applied
in Python over the most recent `limit × 4` leaks (at most 2,000), so older
matches can be missed, and `total` in the response is the count **before** the
watch-item filter. For anything exhaustive, search by the value instead.

## API

| Endpoint | Scope | Audited as |
|---|---|---|
| `GET /watchlist` | `read` | — |
| `POST /watchlist` — `{type, value, is_vip}` | `write` | `CREATE_WATCH_ITEM` |
| `PATCH /watchlist/{id}` — `{is_vip?, is_active?}` | `write` | `UPDATE_WATCH_ITEM` |
| `DELETE /watchlist/{id}` | `write` | `DELETE_WATCH_ITEM` |
| `GET /notifications` | `read` | — |
| `POST /notifications/{id}/ack` | `write` | — |

```bash
curl -X POST http://localhost:8000/watchlist \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"type": "domain", "value": "acme.example.com", "is_vip": true}'
```

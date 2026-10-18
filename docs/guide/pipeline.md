# The Leak Pipeline

Every candidate document, from every source, goes through one function:
`process_leak` in `backend/app/services/pipeline.py`. The webhook, the bulk
ingester (one call per chunk), and every collector call it with the same
arguments — tenant, source name, content, optional URL, title and metadata. If
you want to know why a leak got the score it did, this page and that file are
the whole answer.

```
sha256 ─► exact dedup ─► SimHash near-dup ─► Babel extraction ─► YARA
  ─► watchlist match ─► score ─► LLM triage (optional, can only raise)
  ─► raw evidence to MinIO ─► row in PostgreSQL ─► masked text to ES
  ─► notification / SOAR webhook
```

## 0. Input limits

Empty or whitespace-only content is rejected with `ValueError` (the Celery task
logs and drops it; it is not retried). Content is truncated to the first
5 × 1024 × 1024 **characters** (`MAX_CONTENT_BYTES` — the name says bytes; the
slice is on the Python string).

## 1. Fingerprints

- **SHA-256** of the content, UTF-8 encoded with undecodable characters
  ignored. This is the hash recorded on the leak, in the dossier and in the
  evidence object name.
- **SimHash.** The content is normalised — NFKC, lower-cased, everything other
  than word characters and `@ . - +` replaced by spaces, whitespace collapsed —
  then fingerprinted with a 64-bit Charikar SimHash over word **trigrams**, each
  hashed with BLAKE2b-64. Texts with fewer than three words use single words as
  features. The value is stored signed so it fits a `BIGINT`.

## 2. Deduplication

Both checks are **per tenant**:

1. **Exact.** A leak in the same tenant with the same SHA-256.
2. **Near-duplicate.** Otherwise, every stored fingerprint in the tenant is
   compared and the first with a Hamming distance **≤ `NEAR_DUP_THRESHOLD`**
   (default 3 bits) wins.

Either way the duplicate is folded into the existing leak: its `seen_count`
is incremented, `last_seen_at` set, and a sighting `{source, url, at}` appended
to `metadata.sightings` (up to 50). The call returns the existing leak with
`created: false`. What happens next depends on which check matched.

**An exact copy** (same SHA-256) stops there. The text is byte-identical, so
there is nothing new to find.

**A near copy** (within the SimHash threshold, different SHA-256) is
re-examined by `_rematch_near_duplicate`, because a re-posted dump with a few
lines added is exactly how a new exposure of one of your mailboxes can arrive:

1. The new text is re-extracted, YARA is re-run, and the tenant's active watch
   items are matched against it.
2. Watch matches not already on the leak are **appended** to its
   `watch_matches`. Existing matches are never removed.
3. Severity is recomputed with `score()` over the new text's YARA score and
   entities and the combined matches, and the leak keeps the **higher** of the
   old and new values. It can rise; it never falls.
4. If there are new matches and the leak is now at or above
   `CRITICAL_THRESHOLD`, or one of the new matches is VIP, a notification is
   created (`critical` or `vip`), titled `Re-posted leak now matches …`.
5. The Elasticsearch document's `severity` and `watch_matches` are updated.

What the re-match does **not** do: run AI triage, fire the SOAR webhook,
replace the stored snippet, entities or YARA matches, or store the new text as
evidence. The leak still shows the first version's content. Verified by
`test_near_duplicate_with_new_watched_address_alerts`.

::: info History
Before this, a near copy was folded in without any analysis, so a watched
address added to a list already seen produced no match and no alert.
:::

::: warning The near-dup scan is O(n) per tenant
Each new leak loads every fingerprint in the tenant and compares them in Python.
That is fine for thousands of leaks and slow for millions. The comment in the
code names the fix — band the fingerprint into four 16-bit segments for an LSH
index — and it has not been done.
:::

## 3. Babel extraction

`services/babel.py`. Regex extraction over the raw content, each list
deduplicated and capped at 500 entries:

| Field | What is matched |
|---|---|
| `emails` | RFC-ish addresses, lower-cased |
| `domains` | the email domains, plus bare domains — excluding file-extension "TLDs" (`txt`, `csv`, `sql`, `zip`, `json`, `php`, …) and dotted IPs |
| `ips` | IPv4, excluding `0.0.0.0` and loopback |
| `btc_wallets` | `bc1…` bech32 and legacy `1…`/`3…` addresses |
| `xmr_wallets` | 95-character Monero addresses starting with `4` |
| `onions` | v3 `.onion` hostnames |
| `phones` | international numbers starting with `+` |
| `cards` | 13–19 digit numbers that pass Luhn and are not one repeated digit, **stored masked** as first six + `*` + last four |
| `credentials` | one per line, `identifier:password`, `identifier;password` or `identifier\|password`; URLs skipped. Stored as `{identifier, password_masked, password_length}` |
| `credential_count` | the number of credential lines (uncapped) |
| `has_private_key` | whether a PEM `PRIVATE KEY` block is present |
| `scripts` | the top five Unicode scripts among the first 20,000 letters, as fractions — a cheap hint about where a dump came from |

### Masking

`mask_text` produces the copy that is stored in PostgreSQL, indexed in
Elasticsearch, shown in the UI and sent to the model:

- PEM private key blocks become `[redacted]`;
- values after `password`, `passwd`, `pwd`, `secret`, `token`, `api_key` /
  `api-key` followed by `:` or `=` are masked;
- the password half of every credential line is masked;
- Luhn-valid card numbers become `411111******1111`.

A masked secret keeps its first and last character and up to twelve asterisks
between them (four characters or fewer are fully starred). The **unmasked**
original exists only in object storage. That is the whole of the masking — a
secret in a shape none of these patterns recognise is stored as it appears.

## 4. YARA

`services/analyzer.py`. One compiled ruleset made of:

- **Static rules** from `backend/app/rules/*.yar`, namespace `static_<file>`.
  The shipped `secrets.yar` contains:

  | Rule | `score` | `category` |
  |---|---|---|
  | `private_key` | 60 | SOURCE |
  | `cloud_credentials` (AWS, GCP, GitHub, Slack, Stripe live keys) | 55 | SOURCE |
  | `combo_list` (five or more `email:password` pairs) | 50 | CREDENTIALS |
  | `database_dump` (`CREATE TABLE`/`INSERT INTO` users-like tables, or three bcrypt hashes) | 40 | PII |
  | `generic_api_key` | 30 | SOURCE |
  | `leak_marketplace_language` ("fresh dump", "combolist", "stealer logs", …) | 15 | OTHER |

- **Custom rules** from the `yara_rules` table, namespace
  `dyn_<tenant_id without dashes>_<name>`, or `dyn_global_<name>` for a rule
  with no tenant.

**Score meta.** Each matching rule adds its `score` meta (default **10** if it
has none). The sum is capped at 100. The `category` meta feeds the leak's
category (below).

**Per-tenant namespacing.** All tenants' rules are compiled into one ruleset
and run against every leak, but results are kept only from namespaces starting
`static_`, `dyn_global_` or the current tenant's `dyn_<tenant>_` prefix. One
tenant's rule can never produce a match on another tenant's leak. This is
verified by `test_custom_yara_rule_applies_only_to_its_tenant`.

**No includes.** Every compile — the static set, saved rules, and
`POST /yara/test` — passes `includes=False`, so a rule containing
`include "<path>"` does not compile and is refused with `422`. This stops a rule
author from making the API read files from its own filesystem (verified by
`test_yara_include_is_rejected`).

**Failure behaviour.** A rule must compile to be saved (`422` otherwise). If the
combined set still fails to compile, the analyzer falls back to the static rules
alone and logs an error, so a bad custom rule disables custom rules — for every
tenant — rather than all rules. Matching has a 30-second timeout and scans at
most 8 MiB.

**Propagation delay.** The database rules are reloaded at most every 60 seconds
per process. Creating or deleting a rule forces a reload in the API process
that handled the request; workers pick it up within a minute.

## 5. Watchlist matching

Every **active** watch item of the tenant is checked against the extracted
entities. Extracted emails, and credential identifiers that contain `@`, are
normalised with the same function as watch items before comparison, so Gmail
dot and `+tag` variants match. The rules per type are on
[Watchlist & Alerting](/guide/watchlist#matching-rules); in short, domains match
mailboxes and subdomains, emails match exactly (including as a credential
identifier), IPs and wallets match exactly, and keywords match as a
case-insensitive substring anywhere in the content.

A match is stored as `{id, type, value, vip, hits}`, with up to 20 hits for a
domain.

## 6. Scoring

`pipeline.score()`, exactly:

```python
def score(yara_score: int, entities: dict, watch_matches: list[dict]) -> int:
    s = yara_score                                  # sum of rule scores, already capped at 100
    if entities.get("credential_count"):
        s += min(40, 10 + entities["credential_count"])
    if entities.get("cards"):
        s += 30
    if watch_matches:
        s += 25
        if any(m["vip"] for m in watch_matches):
            s += 15
    return max(0, min(100, s))
```

| Signal | Points |
|---|---|
| YARA | sum of matching rules' `score` (10 if unset), capped at 100 |
| Credential lines present | 10 + count, at most 40 |
| At least one Luhn-valid card | 30 |
| At least one watchlist match | 25 |
| … and one of them is VIP | 15 more |
| Final | clamped to 0–100 |

Worked example, from the test suite: six `user@acme.example.com:password` lines
plus "fresh dump, full db", with `acme.example.com` on the watchlist as VIP.
YARA: `combo_list` 50 + `leak_marketplace_language` 15 = 65. Credentials:
10 + 6 = 16. Watchlist 25, VIP 15. Total 121, clamped to **100**.

Note that a leak with no watchlist match can still score high — a large combo
list or a private key scores on YARA and credentials alone. The watchlist adds
weight; it does not gate ingestion.

### Category

`CREDENTIALS` if there is any credential line, else `FINANCIAL` if there is a
card, else the `category` meta of the highest-scoring YARA match that has one,
else `OTHER`. The AI verdict may then replace it (next section).

## 7. AI triage (optional)

Runs only when `AI_ENDPOINT` is set and the call site did not disable it.
`services/triage.py` sends the **masked** content, truncated to 3,000
characters, fenced between `<<<CONTENT` and `CONTENT>>>` with an instruction to
treat it as data. The answer is parsed for four fields and nothing else:
`VALID` (YES/NO), `SEVERITY` (0–100), `CATEGORY`, `RATIONALE`. `<think>` blocks
are split off and stored as `thought`.

Then:

```python
if ai:
    if ai["is_valid"]:
        severity = max(severity, ai["severity"] or 0, 60)
        category = ai["category"] or category
```

- **It can only raise severity.** A `VALID: NO` leaves the rule score as it
  was; a `VALID: YES` lifts it to at least 60, or to the model's number if
  higher. A leak YARA scored 70 stays at 70 when the model says NO.
  Verified by `test_ai_can_raise_but_not_lower_severity`.
- **It can change the category only on a `VALID: YES` verdict.** A model that
  calls the leak fake does not get to relabel it. (Earlier, the category was
  taken from any verdict.)
- **It triggers nothing by itself.** The verdict is stored in `ai_analysis`;
  any notification or webhook follows from the resulting score.
- If the model is unreachable, or the `ai` breaker is open, triage returns
  nothing and the rule score stands.

## 8. Enrichment

`cti.enrich` looks up the **first** Bitcoin wallet on mempool.space and the
**first** IPv4 on ThreatFox (only if `THREATFOX_AUTH_KEY` is set). Each call has
a six-second timeout and a failure is simply left out. See
[SOAR & CTI](/guide/soar-and-cti#cti-enrichment).

## 9. Evidence storage

The raw, unmasked content is written to `s3://tenant-<id>/leaks/<sha256>.txt`.
If MinIO is not configured the step is skipped; if it fails (or its breaker is
open) a warning is logged and the leak is stored **without** a raw copy. Its
`storage_path` stays empty and the evidence endpoint will answer `404` for it
forever — there is no back-fill.

## 10. The database row

The leak row gets the masked snippet (first 4,000 characters), SHA-256,
fingerprint, severity, category, entities, YARA matches, watch matches, AI
verdict, CTI, and the caller's metadata plus `content_length`. Status starts as
`new`.

## 11. Notifications

In the same transaction as the leak:

| Condition | Notification `level` | Title |
|---|---|---|
| severity ≥ `CRITICAL_THRESHOLD` (80) | `critical` | `Critical exposure (<score>) from <source>` |
| otherwise, any VIP match | `vip` | `[VIP] exposure (<score>) from <source>` |

At most one notification per leak. The body lists the matched watch values (for
`vip`, only the VIP ones). Notifications are rows read through
`GET /notifications`; nothing is emailed or pushed. The `info` level exists in
the model and is never written.

## 12. Indexing

After the commit, the masked full content is indexed into Elasticsearch. A
failure is logged and the leak remains findable through the SQL fallback,
which searches only the 4,000-character snippet.

## 13. SOAR webhook

If severity ≥ `SOAR_THRESHOLD` (90), **or** any match is VIP, the webhook in
`SOAR_WEBHOOK_URL` is called. A VIP leak below the threshold is sent as
`VIP_EXPOSURE` tagged `[VIP]`; anything at or above it is `CRITICAL_EXPOSURE`.
The call is awaited with a three-second timeout, not retried, and a failure is
only logged. Payload: [SOAR & CTI](/guide/soar-and-cti#the-payload).

## Degradation

| Component | When it is missing or failing | The leak |
|---|---|---|
| Broker | pipeline runs in the API process | processed the same way |
| YARA (`yara-python` absent) | no matches, YARA score 0 | scored on entities and watchlist only |
| Model server | triage skipped; `ai` breaker opens after 3 failures for 120 s | rule-based severity, `ai_analysis` null |
| mempool.space / ThreatFox | entry omitted from `cti` | unaffected |
| MinIO | raw copy skipped | stored without evidence, permanently |
| Elasticsearch | indexing skipped; `elasticsearch` breaker opens after 5 failures for 60 s | found by SQL search only, on its first 4,000 masked characters, and not re-indexed later |
| SOAR endpoint | logged | no retry, no record on the leak |

What does fail the pipeline: PostgreSQL. A database error raises, and the Celery
task retries it up to three times.

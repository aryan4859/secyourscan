# Introduction

SecYourScan is a self-hosted exposure-monitoring tool. An organisation lists the
assets it owns — domains, email addresses, keywords, IPv4 addresses and
cryptocurrency wallets — and SecYourScan reads breach dumps, paste sites,
dark-web pages, public Telegram channels, GitHub code search, Have I Been Pwned
and arbitrary feeds for them. Each candidate document is deduplicated, mined for
entities, matched against YARA rules and the watchlist, scored, optionally
triaged by a local LLM, stored with its secrets masked, and indexed. A high
score raises a notification and, above a second threshold, fires a webhook to a
SIEM or SOAR.

It is modelled on [naso](https://fabriziosalmi.github.io/naso/), and borrows its
architecture: FastAPI publishing to RabbitMQ, Celery workers, PostgreSQL,
Elasticsearch and MinIO, a Tor pool behind HAProxy, and an OpenAI-compatible
model server you run yourself.

## What it is not

SecYourScan deliberately has **no identity hub**. It does not build profiles of
people, correlate or merge identities across leaks, or draw an identity graph.
naso has an Identity Hub page; the corresponding page here is
[Watchlist & Alerting](/guide/watchlist), because the unit of interest is an
asset your organisation owns, not a person.

Extracted entities — email addresses, domains, IPs, wallets, phone numbers,
masked card numbers, credential pairs — are stored on the leak they came from so
an analyst can see what was exposed. They are not aggregated into anything
outside that leak.

It is also not a vulnerability scanner. An earlier version of these docs
described network, web, TLS and DNS scanning; none of that exists in the
current code, and those pages have been removed.

## Threat model in brief

The full version is in [Security Model](/guide/security). In short:

**What a SecYourScan instance holds.** Breach material that mentions your
organisation, with the unmasked originals in object storage. That makes the
instance itself a concentrated copy of exactly what an attacker would want, and
the first thing to protect.

**Assets, in order.** The raw evidence; tenant isolation; the audit trail; and
the outbound connections (Tor, Telegram, GitHub, HIBP, mempool.space,
ThreatFox, Shodan InternetDB, the SOAR webhook, the model server), each of which
reaches the network from inside your perimeter.

**Assumed adversaries.** An authenticated analyst trying to exceed their tenant
or role; an unauthenticated caller who can reach the API; hostile content in
ingested material, including prompt injection aimed at the AI Co-Analyst and
spreadsheet formulas aimed at whoever opens a CSV export; and a leaked API key.

**Not in the model.** A compromised host, a malicious administrator, and
denial of service by volume. There are also gaps inside the model that are not
closed; they are listed under [Known gaps](/guide/security#known-gaps).

## Where to go next

| If you want to | Read |
|---|---|
| See how the pieces connect | [Architecture](/guide/architecture) |
| Understand why a leak got the score it did | [The Leak Pipeline](/guide/pipeline) |
| Decide what to put on the watchlist | [Watchlist & Alerting](/guide/watchlist) |
| Feed it data from your own scrapers | [Ingestion](/guide/ingestion) |
| Run it | [Deployment](/guide/deployment) and [Configuration](/guide/configuration) |
| Know what it does not protect against | [Security Model](/guide/security) |
| Fix it at 3 a.m. | [Operator Runbook](/guide/runbook) |

::: info There are no screenshots
naso's documentation carries screenshots and a demo video. These docs carry
none yet, and the web frontend in the repository was being rewritten at the
time of writing. Everything on these pages is described from the backend code,
which is the source of truth.
:::

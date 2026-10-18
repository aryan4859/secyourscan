---
layout: home

hero:
  name: "SecYourScan"
  text: "Exposure monitoring for what you own."
  tagline: "Put your domains, emails, keywords, IPs and wallets on a watchlist. SecYourScan reads breach, paste and dark-web material for them, scores what it finds, masks the secrets, and tells you. It runs on your infrastructure."
  actions:
    - theme: brand
      text: Documentation
      link: /guide/
    - theme: alt
      text: API Reference
      link: /api/

features:
  - title: Your assets, not people
    details: "The watchlist holds what your organisation owns: domains, mailboxes, keywords, IPv4 addresses and wallets. There is no identity hub, no person profiling and no identity graph. A leak is matched against the watchlist and nothing else."
  - title: One pipeline for every source
    details: "Webhook, bulk dump, Ahmia, onion crawl, Telegram, GitHub, HIBP and feeds all feed the same function: SHA-256 and SimHash dedup, Babel extraction, YARA, watchlist match, a published scoring formula, then optional LLM triage that can raise a score and never lower it."
  - title: Secrets never displayed
    details: "Passwords, card numbers and private keys are masked before anything is stored in PostgreSQL or indexed in Elasticsearch. The unmasked original lives only in object storage, and downloading it is restricted to analyst sessions and audited."
  - title: Search that answers
    details: "Elasticsearch with BM25 relevance, highlights and facets, tenant-filtered on every query. With Elasticsearch absent or failing, the same endpoint answers from SQL and says so in its response."
  - title: Audit you can verify
    details: "33 action types are written to a per-tenant SHA-256 hash chain, sign-ins included. An edit or a deletion in the middle breaks the chain where the verifier reports it. It detects tampering; it does not prevent it."
  - title: Degrades instead of failing
    details: "No RabbitMQ: the pipeline runs in-process. No MinIO: no raw evidence. No Elasticsearch: SQL search. No model: rule-based severity. /system/health says which of these you are running without."
---

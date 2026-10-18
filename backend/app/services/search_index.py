"""Elasticsearch: the full-text index the leak search actually queries.

naso indexes into Elasticsearch and never reads it back; here ``search`` is
what ``GET /leaks/search`` calls, with BM25 relevance, highlighting and
facets. Every query carries a ``tenant_id`` term filter. Only the masked text
is indexed, so a search hit never displays a secret.

When Elasticsearch is not configured or its circuit is open, the API falls
back to a SQL ``ILIKE`` search (see ``routers/leaks.py``).
"""

import logging

from ..config import settings
from .breaker import es_breaker

logger = logging.getLogger("secyourscan.es")

MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "dynamic": False,
        "properties": {
            "tenant_id": {"type": "keyword"},
            "source": {"type": "keyword"},
            "source_url": {"type": "keyword", "ignore_above": 1024},
            "title": {"type": "text"},
            "content": {"type": "text"},
            "status": {"type": "keyword"},
            "category": {"type": "keyword"},
            "severity": {"type": "integer"},
            "emails": {"type": "keyword"},
            "domains": {"type": "keyword"},
            "ips": {"type": "keyword"},
            "wallets": {"type": "keyword"},
            "watch_matches": {"type": "keyword"},
            "yara_rules": {"type": "keyword"},
            "discovered_at": {"type": "date"},
        },
    },
}

_FIELDS = ["title^3", "content", "emails^4", "domains^3", "ips^2", "wallets^2", "watch_matches^4", "source_url"]


def make_client():
    from elasticsearch import AsyncElasticsearch

    kwargs = {"basic_auth": (settings.ES_USER, settings.ES_PASSWORD), "request_timeout": 10}
    if settings.ES_URL.startswith("https"):
        kwargs["verify_certs"] = settings.ES_VERIFY_CERTS
    return AsyncElasticsearch(settings.ES_URL, **kwargs)


def to_document(leak, content: str) -> dict:
    ents = leak.entities or {}
    return {
        "tenant_id": leak.tenant_id,
        "source": leak.source,
        "source_url": leak.source_url,
        "title": leak.title,
        "content": content[:200_000],
        "status": leak.status,
        "category": leak.category,
        "severity": leak.severity,
        "emails": ents.get("emails", [])[:200],
        "domains": ents.get("domains", [])[:200],
        "ips": ents.get("ips", [])[:200],
        "wallets": (ents.get("btc_wallets", []) + ents.get("xmr_wallets", []))[:200],
        "watch_matches": [m["value"] for m in (leak.watch_matches or [])],
        "yara_rules": [m["rule"] for m in (leak.yara_matches or [])],
        "discovered_at": leak.discovered_at.isoformat(),
    }


async def ensure_index(es) -> None:
    if not await es.indices.exists(index=settings.ES_INDEX):
        await es.indices.create(index=settings.ES_INDEX, **MAPPING)


async def index_leak(leak, masked_content: str) -> None:
    if not settings.es_enabled:
        return

    async def _do():
        es = make_client()
        try:
            await ensure_index(es)
            await es.index(index=settings.ES_INDEX, id=leak.id, document=to_document(leak, masked_content))
        finally:
            await es.close()

    await es_breaker.call(_do)


async def update_fields(leak_id: str, fields: dict) -> None:
    if not settings.es_enabled:
        return

    async def _do():
        es = make_client()
        try:
            await es.update(index=settings.ES_INDEX, id=leak_id, doc=fields)
        finally:
            await es.close()

    try:
        await es_breaker.call(_do)
    except Exception as exc:
        logger.warning("ES update for %s failed: %s", leak_id, exc)


async def search(
    tenant_id: str,
    q: str | None,
    *,
    severity_min: int | None = None,
    severity_max: int | None = None,
    sources: list[str] | None = None,
    statuses: list[str] | None = None,
    category: str | None = None,
    limit: int = 25,
    offset: int = 0,
) -> dict:
    filters: list[dict] = [{"term": {"tenant_id": tenant_id}}]
    if severity_min is not None or severity_max is not None:
        rng = {}
        if severity_min is not None:
            rng["gte"] = severity_min
        if severity_max is not None:
            rng["lte"] = severity_max
        filters.append({"range": {"severity": rng}})
    if sources:
        filters.append({"terms": {"source": sources}})
    if statuses:
        filters.append({"terms": {"status": statuses}})
    if category:
        filters.append({"term": {"category": category}})

    must = (
        [{"simple_query_string": {"query": q, "fields": _FIELDS, "default_operator": "and", "lenient": True}}]
        if q
        else [{"match_all": {}}]
    )
    body = {
        "query": {"bool": {"must": must, "filter": filters}},
        "from": offset,
        "size": limit,
        "track_total_hits": True,
        "_source": False,
        "highlight": {
            "pre_tags": ["<mark>"],
            "post_tags": ["</mark>"],
            "encoder": "html",
            "fields": {"content": {"fragment_size": 160, "number_of_fragments": 3}, "title": {}},
        },
        "aggs": {
            "sources": {"terms": {"field": "source", "size": 20}},
            "categories": {"terms": {"field": "category", "size": 10}},
            "severity": {"range": {"field": "severity", "ranges": [
                {"key": "critical", "from": 80}, {"key": "high", "from": 60, "to": 80},
                {"key": "medium", "from": 30, "to": 60}, {"key": "low", "to": 30},
            ]}},
        },
    }
    if not q:
        body["sort"] = [{"severity": "desc"}, {"discovered_at": "desc"}]

    async def _do():
        es = make_client()
        try:
            await ensure_index(es)
            return await es.search(index=settings.ES_INDEX, **body)
        finally:
            await es.close()

    resp = await es_breaker.call(_do)
    hits = resp["hits"]["hits"]
    aggs = resp.get("aggregations", {})
    return {
        "total": resp["hits"]["total"]["value"],
        "hits": [
            {"id": h["_id"], "score": h.get("_score"), "highlights": [f for fr in h.get("highlight", {}).values() for f in fr]}
            for h in hits
        ],
        "facets": {name: {b["key"]: b["doc_count"] for b in agg.get("buckets", [])} for name, agg in aggs.items()},
    }


async def delete_tenant(tenant_id: str) -> int:
    if not settings.es_enabled:
        return 0
    es = make_client()
    try:
        if not await es.indices.exists(index=settings.ES_INDEX):
            return 0
        resp = await es.delete_by_query(
            index=settings.ES_INDEX, query={"term": {"tenant_id": tenant_id}}, wait_for_completion=True, refresh=True
        )
        return resp.get("deleted", 0)
    finally:
        await es.close()


async def ping() -> bool:
    es = make_client()
    try:
        return bool(await es.ping())
    finally:
        await es.close()

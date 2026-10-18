"""Run a collector, push what it finds through the pipeline, record provenance.

Shared by the Celery tasks and the inline (no-broker) path.
"""

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import Source, SourceRun, WatchItem, utcnow
from . import recon
from .pipeline import process_leak

logger = logging.getLogger("secyourscan.collect")

AHMIA_PAGE_FETCH = 5  # onion pages fetched per Ahmia query when Tor is available


async def _watch_values(db: AsyncSession, tenant_id: str, types: set[str]) -> list[WatchItem]:
    rows = await db.execute(
        select(WatchItem).where(WatchItem.tenant_id == tenant_id, WatchItem.is_active.is_(True), WatchItem.type.in_(types))
    )
    return list(rows.scalars())


async def _feed(db: AsyncSession, tenant_id: str, candidates: list[recon.Candidate], run: SourceRun) -> None:
    for c in candidates:
        try:
            _, created = await process_leak(db, tenant_id=tenant_id, source=c.source, content=c.content,
                                            source_url=c.url, title=c.title, metadata=c.metadata)
            run.queued += int(created)
        except ValueError:
            continue
    run.results += len(candidates)


async def run_query(db: AsyncSession, tenant_id: str, kind: str, query: str, *, source_id: str | None = None,
                    max_pages: int = 10, run_id: str | None = None) -> SourceRun:
    """``run_id`` picks up a run the API created when it queued the probe, so
    the caller can poll it; otherwise a new run is recorded."""
    run = await db.get(SourceRun, run_id) if run_id else None
    if run is None or run.tenant_id != tenant_id:
        run = SourceRun(tenant_id=tenant_id, source_id=source_id, kind=kind, query=query[:512],
                        via_tor=bool(settings.TOR_PROXY) and kind in {"ahmia", "onion"})
        db.add(run)
        await db.commit()
    try:
        if kind == "ahmia":
            report = await recon.ahmia_search(query)
            run.via_tor = report["via_tor"]
            run.report = {"results": report["results"][:100]}
            candidates = recon.ahmia_candidates(report)
            if report["via_tor"]:
                for r in report["results"][:AHMIA_PAGE_FETCH]:
                    if ".onion" in r["url"]:
                        try:
                            candidates += await recon.crawl_onion(r["url"], max_pages=1)
                        except recon.ReconError:
                            pass
            await _feed(db, tenant_id, candidates, run)
        elif kind == "onion":
            run.via_tor = True
            await _feed(db, tenant_id, await recon.crawl_onion(query, max_pages=max_pages), run)
        elif kind == "telegram":
            await _feed(db, tenant_id, await recon.telegram_channel(query), run)
        elif kind == "github":
            await _feed(db, tenant_id, await recon.github_code_search(query), run)
        elif kind == "hibp":
            await _feed(db, tenant_id, await recon.hibp_breaches(query), run)
        elif kind == "feed":
            await _feed(db, tenant_id, await recon.feed_items(query), run)
        else:
            raise recon.ReconError(f"unknown source kind {kind!r}")
        run.status = "ok"
    except Exception as exc:
        logger.warning("%s run for %r failed: %s", kind, query, exc)
        run.status = "error"
        run.error = str(exc)[:1000]
    run.finished_at = utcnow()
    await db.commit()
    return run


async def run_source(db: AsyncSession, source: Source) -> list[SourceRun]:
    """A source with a target runs once; a sweep source (ahmia/github/hibp
    with no target) runs once per matching watch item."""
    runs = []
    if source.target:
        runs.append(await run_query(db, source.tenant_id, source.kind, source.target, source_id=source.id,
                                    max_pages=source.max_pages))
    else:
        types = {"hibp": {"email"}, "github": {"domain", "keyword"}, "ahmia": {"domain", "keyword", "email"}}.get(source.kind, set())
        for item in await _watch_values(db, source.tenant_id, types):
            runs.append(await run_query(db, source.tenant_id, source.kind, item.value, source_id=source.id))
    source.last_run_at = utcnow()
    await db.commit()
    return runs

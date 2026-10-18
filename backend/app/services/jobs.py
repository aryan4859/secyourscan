"""Queue work for the workers, or run it in-process when there is no broker.

``enqueue`` returns ``{"mode": "queued", "task_id": …}`` when a message went
to RabbitMQ, or ``{"mode": "inline", "result": …}`` when the work ran here.
Inline mode exists for development and tests; production sets RABBITMQ_URL.
"""

import logging

from sqlalchemy import select

from ..config import settings
from ..database import SessionLocal
from ..models import Source, SourceRun, WatchItem, utcnow
from . import broker, collect, intel, massive, storage
from .pipeline import process_leak

logger = logging.getLogger("secyourscan.jobs")


async def _inline_process(tenant_id, source, content, source_url=None, title=None, metadata=None):
    async with SessionLocal() as db:
        leak, created = await process_leak(db, tenant_id=tenant_id, source=source, content=content,
                                           source_url=source_url, title=title, metadata=metadata)
        return {"id": leak.id, "created": created, "severity": leak.severity}


async def _inline_source(source_id):
    async with SessionLocal() as db:
        source = await db.get(Source, source_id)
        runs = await collect.run_source(db, source) if source and source.is_active else []
        return [{"id": r.id, "status": r.status, "results": r.results, "new": r.queued} for r in runs]


async def _inline_probe(tenant_id, query, kind="ahmia", run_id=None):
    async with SessionLocal() as db:
        run = await collect.run_query(db, tenant_id, kind, query, run_id=run_id)
        return {"id": run.id, "status": run.status, "results": run.results, "new": run.queued}


async def _inline_massive(tenant_id, location, source="bulk", job_id=None):
    async with SessionLocal() as db:
        run = await db.get(SourceRun, job_id) if job_id else None
        watch = (await db.execute(select(WatchItem.value).where(WatchItem.tenant_id == tenant_id,
                                                                  WatchItem.is_active.is_(True)))).scalars().all()
        keep = massive.build_filter(list(watch))
        lines = storage.stream_lines(location) if location.startswith("s3://") else massive.iter_url_lines(location)
        created_total = chunks = 0
        stats = {}
        try:
            for chunk, stats in massive.chunk_matching(lines, keep):
                _, created = await process_leak(db, tenant_id=tenant_id, source=source, content=chunk,
                                                title=f"{source} chunk {stats['chunk']}",
                                                metadata={"bulk_location": location, **stats})
                created_total += int(created)
                chunks = stats["chunk"]
            if run:
                run.status = "truncated" if stats.get("truncated") else "ok"
                run.results, run.queued = chunks, created_total
        except Exception as exc:
            if run:
                run.status, run.error = "error", str(exc)[:1000]
        if run:
            run.finished_at = utcnow()
            await db.commit()
        return {"chunks": chunks, "new_leaks": created_total}


async def _inline_intel(tenant_id, module):
    async with SessionLocal() as db:
        try:
            if module == "surface":
                return await intel.run_surface_then_vulns(db, tenant_id)
            return await intel.run_module(db, tenant_id, module)
        except Exception as exc:  # noqa: BLE001 — status already records it
            logger.warning("intel %s scan failed: %s", module, exc)
            return {"error": str(exc)}


_INLINE = {
    broker.TASK_PROCESS: _inline_process,
    broker.TASK_RECON: _inline_source,
    broker.TASK_AHMIA: _inline_probe,
    broker.TASK_MASSIVE: _inline_massive,
    broker.TASK_INTEL: _inline_intel,
}


async def enqueue(task: str, *args, background=None) -> dict:
    """``background`` is a FastAPI ``BackgroundTasks``; when given, inline
    work runs after the response is sent instead of before it."""
    if not settings.inline_pipeline:
        return {"mode": "queued", "task_id": await broker.publish(task, list(args))}
    fn = _INLINE.get(task)
    if fn is None:
        raise RuntimeError(f"{task} cannot run inline; configure RABBITMQ_URL")
    if background is not None:
        background.add_task(fn, *args)
        return {"mode": "inline-background"}
    return {"mode": "inline", "result": await fn(*args)}

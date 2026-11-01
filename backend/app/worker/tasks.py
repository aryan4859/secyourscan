"""Celery tasks.

Each task runs its coroutine on a fresh event loop with a NullPool engine
(see ``database.make_engine``): asyncio objects never cross task boundaries.
"""

import asyncio
import logging
from datetime import timedelta

from celery.utils.log import get_task_logger
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..audit import log_action
from ..database import make_engine
from ..models import (
    ApiKey,
    AuditLog,
    DnsRecord,
    Incident,
    IncidentEvent,
    IntelCache,
    InvestigationPlan,
    InvestigationTask,
    Ioc,
    Leak,
    Lookalike,
    Notification,
    PhishingUrl,
    RansomwareHit,
    RevokedToken,
    Source,
    SourceRun,
    SurfaceEvent,
    SurfaceHost,
    Tenant,
    ThreatActor,
    TlsGrade,
    User,
    Vendor,
    VerifiedDomain,
    VulnFinding,
    WatchItem,
    YaraRule,
    utcnow,
)
from ..services import collect, intel, massive, search_index, storage
from ..services.pipeline import process_leak
from .celery_app import celery_app

logger = get_task_logger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)


def run_async(coro_fn):
    async def _wrapped():
        engine = make_engine(worker=True)
        try:
            async with async_sessionmaker(engine, expire_on_commit=False)() as db:
                return await coro_fn(db)
        finally:
            await engine.dispose()

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_wrapped())
    finally:
        loop.close()


@celery_app.task(bind=True, max_retries=3, name="app.worker.tasks.process_leak_task")
def process_leak_task(self, tenant_id: str, source: str, content: str, source_url=None, title=None, metadata=None):
    async def _run(db):
        leak, created = await process_leak(db, tenant_id=tenant_id, source=source, content=content,
                                           source_url=source_url, title=title, metadata=metadata)
        return {"id": leak.id, "created": created, "severity": leak.severity}

    try:
        return run_async(_run)
    except ValueError as exc:
        logger.info("rejected candidate: %s", exc)
        return None
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60)


@celery_app.task(name="app.worker.tasks.massive_ingest_task", time_limit=6 * 3600, soft_time_limit=6 * 3600 - 60)
def massive_ingest_task(tenant_id: str, location: str, source: str = "bulk", job_id: str | None = None):
    """``location`` is an ``s3://`` object or an http(s) URL."""

    async def _run(db):
        run = await db.get(SourceRun, job_id) if job_id else None
        if run is None:
            run = SourceRun(tenant_id=tenant_id, kind="massive", query=location[:512])
            db.add(run)
            await db.commit()
        watch = (await db.execute(select(WatchItem.value).where(WatchItem.tenant_id == tenant_id,
                                                                  WatchItem.is_active.is_(True)))).scalars().all()
        keep = massive.build_filter(list(watch))
        lines = storage.stream_lines(location) if location.startswith("s3://") else massive.iter_url_lines(location)
        stats = {}
        try:
            for chunk, stats in massive.chunk_matching(lines, keep):
                _, created = await process_leak(db, tenant_id=tenant_id, source=source, content=chunk,
                                                source_url=location if not location.startswith("s3://") else None,
                                                title=f"{source} chunk {stats['chunk']}",
                                                metadata={"bulk_location": location, **stats})
                run.queued += int(created)
                run.results = stats["chunk"]
                run.report = stats
                await db.commit()
            run.status = "truncated" if stats.get("truncated") else "ok"
            if stats.get("truncated"):
                run.error = f"stopped after {massive.MAX_CHUNKS} chunks"
        except Exception as exc:
            run.status, run.error = "error", str(exc)[:1000]
        run.finished_at = utcnow()
        await db.commit()
        return {"chunks": run.results, "new_leaks": run.queued, **stats}

    return run_async(_run)


@celery_app.task(name="app.worker.tasks.run_source_task")
def run_source_task(source_id: str):
    async def _run(db):
        source = await db.get(Source, source_id)
        if source is None or not source.is_active:
            return None
        runs = await collect.run_source(db, source)
        return [{"id": r.id, "status": r.status, "results": r.results, "new": r.queued} for r in runs]

    return run_async(_run)


@celery_app.task(name="app.worker.tasks.ahmia_probe_task")
def ahmia_probe_task(tenant_id: str, query: str, kind: str = "ahmia", run_id: str | None = None):
    async def _run(db):
        run = await collect.run_query(db, tenant_id, kind, query, run_id=run_id)
        return {"id": run.id, "status": run.status, "results": run.results, "new": run.queued}

    return run_async(_run)


@celery_app.task(name="app.worker.tasks.dispatch_due_sources")
def dispatch_due_sources():
    async def _run(db):
        now = utcnow()
        sources = (await db.execute(select(Source).where(Source.is_active.is_(True)))).scalars().all()
        due = [s for s in sources if s.last_run_at is None or now - s.last_run_at >= timedelta(minutes=s.interval_minutes)]
        for s in due:
            s.last_run_at = now  # claim it so the next tick does not re-dispatch
        await db.commit()
        return [s.id for s in due]

    for source_id in run_async(_run):
        run_source_task.delay(source_id)


@celery_app.task(name="app.worker.tasks.intel_scan_task", time_limit=3600, soft_time_limit=3540)
def intel_scan_task(tenant_id: str, module: str):
    """One external-risk module for one tenant; ``surface`` refreshes ``vulns`` after."""

    async def _run(db):
        if module == "surface":
            return await intel.run_surface_then_vulns(db, tenant_id)
        return await intel.run_module(db, tenant_id, module)

    return run_async(_run)


@celery_app.task(name="app.worker.tasks.intel_sweep")
def intel_sweep():
    """Scheduled: every tenant with something to watch gets all modules."""

    async def _run(db):
        return (await db.execute(select(WatchItem.tenant_id).where(WatchItem.is_active.is_(True)).distinct())).scalars().all()

    from ..services import license

    ok, reason = license.can_scan()
    if not ok:
        logger.warning("Scheduled intel sweep skipped: %s", reason)
        return
    for tenant_id in run_async(_run):
        for module in ("surface", "brand", "ransomware"):
            intel_scan_task.delay(tenant_id, module)

    # Vendors are rated even for a tenant with an empty watchlist.
    async def _vendor_tenants(db):
        return (await db.execute(select(Vendor.tenant_id).distinct())).scalars().all()

    for tenant_id in run_async(_vendor_tenants):
        intel_scan_task.delay(tenant_id, "vendors")


@celery_app.task(name="app.worker.tasks.ioc_refresh")
def ioc_refresh():
    """Daily: re-enrich indicators not looked at for a week, then open
    incidents for any that turned malicious while sighted on our assets."""

    async def _run(db):
        from ..services import incidents, ioc

        done = {}
        for tenant_id in (await db.execute(select(Ioc.tenant_id).distinct())).scalars().all():
            done[tenant_id] = await ioc.refresh_stale(db, tenant_id)
            await incidents.sync(db, tenant_id)
        return done

    return run_async(_run)


@celery_app.task(name="app.worker.tasks.purge_revoked_tokens")
def purge_revoked_tokens():
    async def _run(db):
        await db.execute(delete(RevokedToken).where(RevokedToken.expires_at < utcnow()))
        await db.commit()

    run_async(_run)


@celery_app.task(bind=True, max_retries=5, name="app.worker.tasks.delete_tenant_saga")
def delete_tenant_saga(self, tenant_id: str, actor: str | None = None):
    """Elasticsearch → object storage → PostgreSQL. Not a transaction: each
    step is idempotent, so a failure part-way is retried, not rolled back."""

    async def _run(db):
        es_deleted = await search_index.delete_tenant(tenant_id)
        objects = await storage.delete_bucket(tenant_id)
        plan_ids = select(InvestigationPlan.id).where(InvestigationPlan.tenant_id == tenant_id)
        await db.execute(delete(InvestigationTask).where(InvestigationTask.plan_id.in_(plan_ids)))
        incident_ids = select(Incident.id).where(Incident.tenant_id == tenant_id)
        await db.execute(delete(IncidentEvent).where(IncidentEvent.incident_id.in_(incident_ids)))
        for model in (Leak, Notification, SourceRun, Source, WatchItem, ApiKey, InvestigationPlan, YaraRule,
                      SurfaceHost, Lookalike, PhishingUrl, RansomwareHit, VulnFinding, TlsGrade, DnsRecord,
                      SurfaceEvent, VerifiedDomain, Incident, ThreatActor, Ioc, Vendor, User):
            await db.execute(delete(model).where(model.tenant_id == tenant_id))
        await db.execute(delete(IntelCache).where(IntelCache.key.like(f"scan:{tenant_id}:%")))
        await db.execute(delete(IntelCache).where(IntelCache.key.in_([f"posture:{tenant_id}", f"profile:{tenant_id}"])))
        await db.execute(delete(AuditLog).where(AuditLog.tenant_id == tenant_id))
        await db.execute(delete(Tenant).where(Tenant.id == tenant_id))
        await db.commit()
        await log_action(db, action="DELETE_TENANT_COMPLETED", tenant_id=None, user_id=actor,
                         resource_type="tenant", resource_id=tenant_id,
                         details={"es_documents": es_deleted, "objects": objects})
        return {"es_documents": es_deleted, "objects": objects}

    try:
        return run_async(_run)
    except Exception as exc:
        raise self.retry(exc=exc, countdown=300)

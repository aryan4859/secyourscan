import csv
import io
import logging
import uuid
from typing import Literal

import orjson
from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..config import settings
from ..database import get_db
from ..deps import Principal, client_ip, get_principal, require_scope
from ..limiter import limiter
from ..models import Leak, SourceRun, Tenant, utcnow
from ..services import broker, dossier, jobs, recon, search_index, storage
from ..services.breaker import CircuitOpen
from . import serializers as ser

router = APIRouter(prefix="/leaks", tags=["leaks"])
logger = logging.getLogger("secyourscan.leaks")

Status = Literal["new", "reviewing", "escalated", "resolved", "false_positive"]
MAX_WEBHOOK_BYTES = 5 * 1024 * 1024
_CSV_FORMULA = ("=", "+", "-", "@", "\t", "\r")


class WebhookPayload(BaseModel):
    source: str = Field("webhook", min_length=1, max_length=64, description="Name of the tool that found it")
    content: str = Field(min_length=1, description="Raw text discovered")
    source_url: str | None = Field(None, max_length=1024)
    title: str | None = Field(None, max_length=512)
    metadata: dict = Field(default_factory=dict)


class BulkUrl(BaseModel):
    url: str = Field(pattern=r"^https?://", max_length=2048)
    source: str = Field("bulk", max_length=64)


class StatusUpdate(BaseModel):
    status: Status


def _escape_like(term: str) -> str:
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _csv_safe(v):
    return "'" + v if isinstance(v, str) and v.startswith(_CSV_FORMULA) else v


async def _get_leak(db: AsyncSession, principal: Principal, leak_id: str) -> Leak:
    leak = await db.get(Leak, leak_id)
    # 404, not 403, for another tenant's id: existence is not disclosed.
    if leak is None or leak.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Leak not found")
    return leak


# ── Ingestion ────────────────────────────────────────────────────────────────


@router.post(
    "/ingest/webhook",
    status_code=202,
    openapi_extra={"requestBody": {"required": True, "content": {"application/json": {"schema": WebhookPayload.model_json_schema()}}}},
)
@limiter.limit("60/minute")
async def ingest_webhook(request: Request, principal: Principal = Depends(require_scope("ingest"))):
    """Accept one externally discovered item and hand it to the pipeline.

    The body is parsed with orjson and validated; the API then publishes to
    RabbitMQ and returns 202 without analysing anything itself.
    """
    raw = await request.body()
    if len(raw) > MAX_WEBHOOK_BYTES:
        raise HTTPException(413, "Payload too large; use /leaks/ingest/bulk")
    try:
        payload = orjson.loads(raw)
    except orjson.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON")
    try:
        body = WebhookPayload.model_validate(payload)
    except ValidationError as exc:
        # include_input=False: never echo a multi-megabyte body back.
        raise HTTPException(422, exc.errors(include_url=False, include_input=False, include_context=False))
    result = await jobs.enqueue(broker.TASK_PROCESS, principal.tenant_id, body.source, body.content,
                                body.source_url, body.title, body.metadata)
    return {"status": "accepted", **result}


@router.post("/ingest/bulk", status_code=202)
async def ingest_bulk(
    background: BackgroundTasks,
    request: Request,
    file: UploadFile | None = File(None),
    url: str | None = Form(None),
    source: str = Form("bulk"),
    principal: Principal = Depends(require_scope("ingest")),
    db: AsyncSession = Depends(get_db),
):
    """Stream a large dump through the pre-filter on the ``massive`` worker.
    Send a file (stored in object storage first) or an http(s) URL."""
    if bool(file) == bool(url):
        raise HTTPException(422, "Send exactly one of 'file' or 'url'")
    if url:
        BulkUrl(url=url, source=source)
        try:
            recon.ensure_public_url(url)
        except recon.ReconError as exc:
            raise HTTPException(422, str(exc))
        location = url
    else:
        if not settings.minio_enabled:
            raise HTTPException(503, "File uploads need object storage (MINIO_*); send a URL instead")
        name = f"bulk/{uuid.uuid4().hex}-{(file.filename or 'upload')[-80:]}"
        location = await storage.put_stream(principal.tenant_id, name, file.file, "text/plain")
    run = SourceRun(tenant_id=principal.tenant_id, kind="massive", query=location[:512])
    db.add(run)
    await db.flush()
    await log_action(db, action="BULK_INGEST", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="source_run", resource_id=run.id, details={"location": location[:512]},
                     ip_address=client_ip(request))
    result = await jobs.enqueue(broker.TASK_MASSIVE, principal.tenant_id, location, source[:64], run.id, background=background)
    return {"status": "accepted", "job_id": run.id, **result}


# ── Reading ──────────────────────────────────────────────────────────────────


@router.get("/")
async def list_leaks(
    source: str | None = None,
    status: Status | None = None,
    min_severity: int | None = Query(None, ge=0, le=100),
    max_severity: int | None = Query(None, ge=0, le=100),
    watch_item_id: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    principal: Principal = Depends(require_scope("read")),
    db: AsyncSession = Depends(get_db),
):
    q = select(Leak).where(Leak.tenant_id == principal.tenant_id)
    if source:
        q = q.where(Leak.source == source)
    if status:
        q = q.where(Leak.status == status)
    if min_severity is not None:
        q = q.where(Leak.severity >= min_severity)
    if max_severity is not None:
        q = q.where(Leak.severity <= max_severity)
    rows = (await db.execute(q.order_by(Leak.discovered_at.desc()).limit(min(limit * 4, 2000) if watch_item_id else limit)
                             .offset(0 if watch_item_id else offset))).scalars().all()
    if watch_item_id:
        rows = [r for r in rows if any(m.get("id") == watch_item_id for m in r.watch_matches or [])][offset:offset + limit]
    total = await db.scalar(select(func.count()).select_from(q.subquery()))
    return {"total": total, "items": [ser.leak_summary(r) for r in rows]}


@router.get("/search")
async def search_leaks(
    q: str | None = Query(None, max_length=256),
    min_severity: int | None = Query(None, ge=0, le=100),
    max_severity: int | None = Query(None, ge=0, le=100),
    source: list[str] | None = Query(None),
    status: list[Status] | None = Query(None),
    category: str | None = None,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0, le=10_000),
    principal: Principal = Depends(require_scope("read")),
    db: AsyncSession = Depends(get_db),
):
    """Full-text search. Elasticsearch (relevance, highlights, facets) when
    configured; otherwise — or if its circuit is open — SQL ILIKE over the
    masked snippet. ``engine`` in the response says which one answered."""
    q = (q or "").strip() or None
    if settings.es_enabled:
        try:
            res = await search_index.search(principal.tenant_id, q, severity_min=min_severity, severity_max=max_severity,
                                            sources=source, statuses=status, category=category, limit=limit, offset=offset)
            ids = [h["id"] for h in res["hits"]]
            rows = {r.id: r for r in (await db.execute(select(Leak).where(Leak.id.in_(ids),
                                                                         Leak.tenant_id == principal.tenant_id))).scalars()}
            items = [{**ser.leak_summary(rows[h["id"]]), "score": h["score"], "highlights": h["highlights"]}
                     for h in res["hits"] if h["id"] in rows]
            return {"engine": "elasticsearch", "total": res["total"], "items": items, "facets": res["facets"]}
        except (CircuitOpen, Exception) as exc:  # noqa: BLE001 — any ES failure falls back
            logger.warning("ES search failed, falling back to SQL: %s", exc)

    stmt = select(Leak).where(Leak.tenant_id == principal.tenant_id)
    if q:
        pat = _escape_like(q)
        stmt = stmt.where(or_(Leak.snippet.ilike(pat, escape="\\"), Leak.title.ilike(pat, escape="\\"),
                              Leak.source_url.ilike(pat, escape="\\")))
    if min_severity is not None:
        stmt = stmt.where(Leak.severity >= min_severity)
    if max_severity is not None:
        stmt = stmt.where(Leak.severity <= max_severity)
    if source:
        stmt = stmt.where(Leak.source.in_(source))
    if status:
        stmt = stmt.where(Leak.status.in_(status))
    if category:
        stmt = stmt.where(Leak.category == category)
    total = await db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = (await db.execute(stmt.order_by(Leak.severity.desc(), Leak.discovered_at.desc()).limit(limit).offset(offset))).scalars()
    facet_rows = await db.execute(select(Leak.source, func.count()).where(Leak.tenant_id == principal.tenant_id).group_by(Leak.source))
    return {"engine": "sql", "total": total, "items": [{**ser.leak_summary(r), "score": None, "highlights": []} for r in rows],
            "facets": {"sources": dict(facet_rows.all())}}


@router.get("/stats")
async def stats(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    t = principal.tenant_id
    base = select(func.count()).select_from(Leak).where(Leak.tenant_id == t)
    by_source = dict((await db.execute(select(Leak.source, func.count()).where(Leak.tenant_id == t).group_by(Leak.source))).all())
    by_status = dict((await db.execute(select(Leak.status, func.count()).where(Leak.tenant_id == t).group_by(Leak.status))).all())
    by_category = dict((await db.execute(select(Leak.category, func.count()).where(Leak.tenant_id == t).group_by(Leak.category))).all())
    day = func.date(Leak.discovered_at)
    timeline = [{"day": str(d), "count": c, "max_severity": m} for d, c, m in (await db.execute(
        select(day, func.count(), func.max(Leak.severity)).where(Leak.tenant_id == t).group_by(day).order_by(day.desc()).limit(30)
    )).all()][::-1]
    return {
        "total": await db.scalar(base),
        "critical_open": await db.scalar(base.where(Leak.severity >= settings.CRITICAL_THRESHOLD, Leak.acknowledged_at.is_(None),
                                                    Leak.status.notin_(["resolved", "false_positive"]))),
        "by_source": by_source,
        "by_status": by_status,
        "by_category": {k or "OTHER": v for k, v in by_category.items()},
        "timeline": timeline,
    }


INSIGHT_ROW_CAP = 20_000  # leaks scanned per insights call (current + previous window)
STALE_CRITICAL_HOURS = 6
_OPEN = ("new", "reviewing", "escalated")


def _band(sev: int) -> str:
    if sev >= settings.CRITICAL_THRESHOLD:
        return "critical"
    return "high" if sev >= 60 else "medium" if sev >= 30 else "low"


@router.get("/insights")
async def insights(days: int = Query(30, description="7, 30 or 90"), principal: Principal = Depends(require_scope("read")),
                   db: AsyncSession = Depends(get_db)):
    """Everything the dashboard shows for one window, with the window before
    it for comparison. Aggregated here rather than in SQL so it runs the same
    on Postgres and SQLite; at most ``INSIGHT_ROW_CAP`` leaks are scanned and
    ``truncated`` says when that cap was hit."""
    from datetime import timedelta
    from statistics import median

    from ..models import WatchItem

    if days not in (7, 30, 90):
        raise HTTPException(422, "days must be 7, 30 or 90")
    t = principal.tenant_id
    now = utcnow()
    start, prev_start = now - timedelta(days=days), now - timedelta(days=2 * days)
    rows = (await db.execute(
        select(Leak.id, Leak.source, Leak.severity, Leak.category, Leak.status, Leak.watch_matches,
               Leak.discovered_at, Leak.acknowledged_at)
        .where(Leak.tenant_id == t, Leak.discovered_at >= prev_start)
        .order_by(Leak.discovered_at.desc()).limit(INSIGHT_ROW_CAP)
    )).all()
    cur = [r for r in rows if r.discovered_at >= start]
    prev = [r for r in rows if r.discovered_at < start]

    def crit(rs):
        return sum(1 for r in rs if r.severity >= settings.CRITICAL_THRESHOLD)

    # Daily series by severity band, every day present.
    daily = {(now - timedelta(days=days - 1 - i)).date().isoformat(): {"critical": 0, "high": 0, "medium": 0, "low": 0}
             for i in range(days)}
    severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_source: dict[str, list[int]] = {}
    by_category: dict[str, int] = {}
    by_status = {s: 0 for s in ("new", "reviewing", "escalated", "resolved", "false_positive")}
    assets: dict[str, dict] = {}
    for r in cur:
        band = _band(r.severity)
        severity[band] += 1
        if (day := r.discovered_at.date().isoformat()) in daily:
            daily[day][band] += 1
        by_source.setdefault(r.source, [0, 0])[0] += 1
        by_category[r.category or "OTHER"] = by_category.get(r.category or "OTHER", 0) + 1
        by_status[r.status] = by_status.get(r.status, 0) + 1
        for m in r.watch_matches or []:
            a = assets.setdefault(m.get("id") or m.get("value"), {
                "id": m.get("id"), "type": m.get("type"), "value": m.get("value"), "vip": bool(m.get("vip")),
                "hits": 0, "open": 0, "exposure": 0, "last_seen": None})
            a["hits"] += 1
            if r.status in _OPEN:
                a["open"] += 1
                a["exposure"] = max(a["exposure"], r.severity)
            if a["last_seen"] is None or r.discovered_at > a["last_seen"]:
                a["last_seen"] = r.discovered_at
    for r in prev:
        by_source.setdefault(r.source, [0, 0])[1] += 1
    prev_assets = {m.get("id") or m.get("value") for r in prev for m in r.watch_matches or []}

    watched = await db.scalar(select(func.count()).select_from(WatchItem).where(WatchItem.tenant_id == t,
                                                                                WatchItem.is_active.is_(True)))
    open_crit = (select(func.count()).select_from(Leak)
                 .where(Leak.tenant_id == t, Leak.severity >= settings.CRITICAL_THRESHOLD,
                        Leak.acknowledged_at.is_(None), Leak.status.in_(_OPEN)))
    awaiting = await db.scalar(open_crit)
    stale = await db.scalar(open_crit.where(Leak.discovered_at < now - timedelta(hours=STALE_CRITICAL_HOURS)))

    ack_hours = [(r.acknowledged_at - r.discovered_at).total_seconds() / 3600 for r in cur
                 if r.acknowledged_at and r.acknowledged_at >= r.discovered_at]

    run_rows = (await db.execute(select(SourceRun.kind, SourceRun.status, func.count())
                                 .where(SourceRun.tenant_id == t, SourceRun.started_at >= start)
                                 .group_by(SourceRun.kind, SourceRun.status))).all()
    runs: dict[str, dict] = {}
    for kind, status, n in run_rows:
        runs.setdefault(kind, {"ok": 0, "error": 0, "running": 0})[status] = n

    # Callouts: only the ones that currently apply.
    callouts = []
    surges = [(s, c, p) for s, (c, p) in by_source.items() if c >= 5 and c >= 1.5 * max(p, 1)]
    if surges:
        s, c, p = max(surges, key=lambda x: x[1] / max(x[2], 1))
        callouts.append({"kind": "source_surge", "source": s, "count": c, "prev": p})
    if stale:
        callouts.append({"kind": "stale_critical", "count": stale, "hours": STALE_CRITICAL_HOURS})
    vip_hot = [a for a in assets.values() if a["vip"] and a["exposure"] >= 70]
    if vip_hot:
        callouts.append({"kind": "vip_at_risk", "count": len(vip_hot), "threshold": 70})
    failing = sum(v["error"] for v in runs.values())
    if failing:
        callouts.append({"kind": "collector_errors", "count": failing})

    top = sorted(assets.values(), key=lambda a: (a["exposure"], a["open"], a["hits"]), reverse=True)[:10]
    return {
        "days": days,
        "generated_at": ser.iso(now),
        "truncated": len(rows) >= INSIGHT_ROW_CAP,
        "kpis": {
            "leaks": {"value": len(cur), "prev": len(prev)},
            "critical": {"value": crit(cur), "prev": crit(prev)},
            "exposed_assets": {"value": len(assets), "prev": len(prev_assets), "watched": watched},
            "awaiting_triage": {"value": awaiting, "stale": stale},
            "mtta_hours": round(median(ack_hours), 1) if ack_hours else None,
        },
        "daily": [{"day": d, **v} for d, v in daily.items()],
        "severity": severity,
        "by_source": sorted(({"source": s, "count": c, "prev": p} for s, (c, p) in by_source.items() if c),
                            key=lambda x: -x["count"]),
        "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
        "by_status": by_status,
        "top_assets": [{**a, "last_seen": ser.iso(a["last_seen"])} for a in top],
        "runs": runs,
        "callouts": callouts,
    }


CHANNELS = {"ahmia": "Tor / onion", "onion": "Tor / onion", "telegram": "Telegram", "paste": "Paste sites",
            "pastebin": "Paste sites", "feed": "Feeds", "github": "Code repositories", "hibp": "Breach catalogues"}


def channel_of(source: str) -> str:
    return CHANNELS.get((source or "").lower(), "Ingested")


@router.get("/darkweb")
async def darkweb_overview(days: int = Query(30, description="7, 30 or 90"), principal: Principal = Depends(require_scope("read")),
                           db: AsyncSession = Depends(get_db)):
    """Mentions collected from dark-web and underground-adjacent channels:
    volume per channel and day, the sites they came from, which watched
    terms they hit, and how much of the collection is actually running."""
    from datetime import timedelta
    from urllib.parse import urlsplit

    from ..models import Source

    if days not in (7, 30, 90):
        raise HTTPException(422, "days must be 7, 30 or 90")
    t = principal.tenant_id
    now = utcnow()
    start = now - timedelta(days=days)
    rows = (await db.execute(
        select(Leak.id, Leak.title, Leak.source, Leak.source_url, Leak.severity, Leak.status, Leak.watch_matches,
               Leak.discovered_at)
        .where(Leak.tenant_id == t, Leak.discovered_at >= start - timedelta(days=days))
        .order_by(Leak.discovered_at.desc()).limit(INSIGHT_ROW_CAP))).all()
    cur = [r for r in rows if r.discovered_at >= start]
    prev = [r for r in rows if r.discovered_at < start]

    by_channel: dict[str, dict] = {}
    daily = {(now - timedelta(days=days - 1 - i)).date().isoformat(): {} for i in range(days)}
    sites: dict[str, dict] = {}
    terms: dict[str, dict] = {}
    for r in cur:
        ch = channel_of(r.source)
        c = by_channel.setdefault(ch, {"channel": ch, "count": 0, "matched": 0, "critical": 0, "prev": 0})
        c["count"] += 1
        c["matched"] += 1 if r.watch_matches else 0
        c["critical"] += 1 if r.severity >= settings.CRITICAL_THRESHOLD else 0
        day = r.discovered_at.date().isoformat()
        if day in daily:
            daily[day][ch] = daily[day].get(ch, 0) + 1
        host = ""
        if r.source_url:
            try:
                host = (urlsplit(r.source_url).hostname or "").lower()
            except ValueError:
                host = ""
        if host:
            s = sites.setdefault(host, {"site": host, "channel": ch, "count": 0, "max_severity": 0, "last_seen": r.discovered_at})
            s["count"] += 1
            s["max_severity"] = max(s["max_severity"], r.severity)
            s["last_seen"] = max(s["last_seen"], r.discovered_at)
        for m in r.watch_matches or []:
            k = m.get("value") or "?"
            tm = terms.setdefault(k, {"term": k, "type": m.get("type"), "vip": bool(m.get("vip")), "count": 0, "max_severity": 0})
            tm["count"] += 1
            tm["max_severity"] = max(tm["max_severity"], r.severity)
    for r in prev:
        ch = channel_of(r.source)
        by_channel.setdefault(ch, {"channel": ch, "count": 0, "matched": 0, "critical": 0, "prev": 0})["prev"] += 1

    sources = (await db.execute(select(Source).where(Source.tenant_id == t))).scalars().all()
    coverage: dict[str, dict] = {}
    for s in sources:
        ch = channel_of(s.kind)
        cv = coverage.setdefault(ch, {"channel": ch, "sources": 0, "active": 0, "last_run": None})
        cv["sources"] += 1
        cv["active"] += 1 if s.is_active else 0
        if s.last_run_at and (cv["last_run"] is None or s.last_run_at > cv["last_run"]):
            cv["last_run"] = s.last_run_at
    matched = [r for r in cur if r.watch_matches]
    return {
        "days": days,
        "tor": bool(settings.TOR_PROXY),
        "totals": {"mentions": len(cur), "prev": len(prev), "matched": len(matched),
                   "critical": sum(1 for r in cur if r.severity >= settings.CRITICAL_THRESHOLD),
                   "sites": len(sites)},
        "channels": sorted(by_channel.values(), key=lambda c: -c["count"]),
        "daily": [{"day": d, **v} for d, v in daily.items()],
        "sites": [{**s, "last_seen": ser.iso(s["last_seen"])} for s in sorted(sites.values(), key=lambda s: (-s["max_severity"], -s["count"]))[:12]],
        "terms": sorted(terms.values(), key=lambda x: (-x["max_severity"], -x["count"]))[:12],
        "latest": [{"id": r.id, "title": r.title or r.source, "source": r.source, "channel": channel_of(r.source),
                    "severity": r.severity, "status": r.status, "discovered_at": ser.iso(r.discovered_at),
                    "matches": [m.get("value") for m in r.watch_matches or []][:3]}
                   for r in sorted(matched or cur, key=lambda r: (-r.severity, -r.discovered_at.timestamp()))[:15]],
        "coverage": [{**c, "last_run": ser.iso(c["last_run"])} for c in coverage.values()],
    }


@router.get("/topology")
async def topology(days: int = Query(30, description="7, 30 or 90"), min_severity: int = Query(0, ge=0, le=100),
                   limit: int = Query(300, ge=1, le=1000), principal: Principal = Depends(require_scope("read")),
                   db: AsyncSession = Depends(get_db)):
    """Graph of the tenant's watched assets and the leaks that matched them.
    Only watch matches make edges — entities extracted from leak text never
    become nodes — so this maps your assets' exposure, not people. Leaks are
    the ``limit`` most severe in the window; ``truncated`` says when more
    matched."""
    from datetime import timedelta

    from ..models import WatchItem

    if days not in (7, 30, 90):
        raise HTTPException(422, "days must be 7, 30 or 90")
    t = principal.tenant_id
    rows = (await db.execute(
        select(Leak.id, Leak.title, Leak.source, Leak.severity, Leak.status, Leak.watch_matches, Leak.discovered_at)
        .where(Leak.tenant_id == t, Leak.discovered_at >= utcnow() - timedelta(days=days), Leak.severity >= min_severity)
        .order_by(Leak.severity.desc(), Leak.discovered_at.desc()).limit(min(limit * 4, INSIGHT_ROW_CAP))
    )).all()
    matched = [r for r in rows if r.watch_matches]
    leaks = matched[:limit]

    assets: dict[str, dict] = {}
    for w in (await db.execute(select(WatchItem).where(WatchItem.tenant_id == t, WatchItem.is_active.is_(True)))).scalars():
        assets[w.id] = {"id": f"a:{w.id}", "kind": "asset", "label": w.value, "type": w.type, "vip": w.is_vip,
                        "hits": 0, "exposure": 0}
    nodes, links = [], []
    for r in leaks:
        nodes.append({"id": f"l:{r.id}", "kind": "leak", "label": r.title or r.source, "source": r.source,
                      "severity": r.severity, "status": r.status, "discovered_at": ser.iso(r.discovered_at)})
        for m in r.watch_matches:
            key = m.get("id") or m.get("value")
            a = assets.setdefault(key, {"id": f"a:{key}", "kind": "asset", "label": m.get("value"), "type": m.get("type"),
                                        "vip": bool(m.get("vip")), "hits": 0, "exposure": 0})
            a["hits"] += 1
            if r.status in _OPEN:
                a["exposure"] = max(a["exposure"], r.severity)
            links.append({"source": f"l:{r.id}", "target": a["id"]})
    return {"nodes": list(assets.values()) + nodes, "links": links, "truncated": len(matched) > limit}


@router.get("/export/dossier")
async def export_dossier(
    request: Request,
    min_severity: int = Query(0, ge=0, le=100),
    principal: Principal = Depends(require_scope("read")),
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(select(Leak).where(Leak.tenant_id == principal.tenant_id, Leak.severity >= min_severity)
                             .order_by(Leak.severity.desc(), Leak.discovered_at.desc()).limit(5000))).scalars().all()
    if not rows:
        raise HTTPException(404, "No records to export")
    tenant = await db.get(Tenant, principal.tenant_id)
    pdf, digest, signature = dossier.build_pdf(tenant.name, rows, principal.email or principal.actor)
    await log_action(db, action="GENERATE_DOSSIER", tenant_id=principal.tenant_id, user_id=principal.actor,
                     details={"records": len(rows), "sha256": digest, "min_severity": min_severity},
                     ip_address=client_ip(request))
    return Response(pdf, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="dossier-{utcnow():%Y%m%d-%H%M}.pdf"',
        "X-Dossier-SHA256": digest,
        "X-Dossier-Signature": signature,
        "Access-Control-Expose-Headers": "X-Dossier-SHA256, X-Dossier-Signature",
    })


@router.get("/export/public-key", response_class=Response)
async def dossier_public_key(principal: Principal = Depends(get_principal)):
    return Response(dossier.public_key_pem(), media_type="application/x-pem-file")


@router.get("/export/csv")
async def export_csv(request: Request, principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(Leak).where(Leak.tenant_id == principal.tenant_id).order_by(Leak.discovered_at.desc()).limit(50_000))).scalars()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "discovered_at", "severity", "category", "status", "source", "source_url", "watch_matches", "yara_rules", "sha256"])
    for r in rows:
        # Every field originates somewhere hostile; neutralise spreadsheet formulas (CWE-1236).
        w.writerow([_csv_safe(v) for v in [r.id, ser.iso(r.discovered_at), r.severity, r.category, r.status, r.source,
                                           r.source_url, "; ".join(m["value"] for m in r.watch_matches or []),
                                           "; ".join(m["rule"] for m in r.yara_matches or []), r.sha256]])
    await log_action(db, action="EXPORT_CSV", tenant_id=principal.tenant_id, user_id=principal.actor, ip_address=client_ip(request))
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="leaks.csv"'})


@router.get("/{leak_id}")
async def get_leak(leak_id: str, principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    return ser.leak_detail(await _get_leak(db, principal, leak_id))


@router.get("/{leak_id}/evidence")
async def get_evidence(leak_id: str, request: Request, principal: Principal = Depends(get_principal),
                       db: AsyncSession = Depends(get_db)):
    """The unmasked original. Analyst sessions only (not API keys); every
    download is audited."""
    if principal.via == "api_key":
        raise HTTPException(403, "Evidence download requires an analyst session")
    leak = await _get_leak(db, principal, leak_id)
    if not leak.storage_path:
        raise HTTPException(404, "No raw evidence stored for this leak")
    data = await storage.get_bytes(leak.storage_path)
    if data is None:
        raise HTTPException(503, "Object storage unavailable")
    await log_action(db, action="VIEW_EVIDENCE", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="leak", resource_id=leak.id, ip_address=client_ip(request))
    return Response(data, media_type="text/plain; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="evidence-{leak.sha256[:12]}.txt"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    })


# ── Triage ───────────────────────────────────────────────────────────────────


@router.patch("/{leak_id}/status")
async def set_status(leak_id: str, body: StatusUpdate, request: Request, principal: Principal = Depends(require_scope("write")),
                     db: AsyncSession = Depends(get_db)):
    leak = await _get_leak(db, principal, leak_id)
    old = leak.status
    leak.status = body.status
    if body.status in {"resolved", "false_positive", "reviewing"} and leak.acknowledged_at is None:
        leak.acknowledged_at = utcnow()
    await log_action(db, action="UPDATE_LEAK_STATUS", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="leak", resource_id=leak.id, details={"from": old, "to": body.status},
                     ip_address=client_ip(request))
    await search_index.update_fields(leak.id, {"status": body.status})
    return ser.leak_summary(leak)


@router.post("/{leak_id}/ack")
async def acknowledge(leak_id: str, request: Request, principal: Principal = Depends(require_scope("write")),
                      db: AsyncSession = Depends(get_db)):
    leak = await _get_leak(db, principal, leak_id)
    leak.acknowledged_at = leak.acknowledged_at or utcnow()
    await log_action(db, action="ACKNOWLEDGE_LEAK", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="leak", resource_id=leak.id, ip_address=client_ip(request))
    return ser.leak_summary(leak)


@router.post("/ack-all")
async def acknowledge_all(request: Request, min_severity: int = Query(80, ge=0, le=100),
                          principal: Principal = Depends(require_scope("write")), db: AsyncSession = Depends(get_db)):
    result = await db.execute(update(Leak).where(Leak.tenant_id == principal.tenant_id, Leak.severity >= min_severity,
                                                 Leak.acknowledged_at.is_(None)).values(acknowledged_at=utcnow()))
    await log_action(db, action="ACKNOWLEDGE_ALL_CRITICAL", tenant_id=principal.tenant_id, user_id=principal.actor,
                     details={"count": result.rowcount, "min_severity": min_severity}, ip_address=client_ip(request))
    return {"acknowledged": result.rowcount}

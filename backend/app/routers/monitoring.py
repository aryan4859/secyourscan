"""Watchlist, sources, recon probes, YARA rules, notifications."""

import ipaddress
import re
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..config import settings
from ..database import get_db
from ..deps import Principal, client_ip, require_scope
from ..models import Leak, Notification, Source, SourceRun, WatchItem, YaraRule, utcnow
from ..services import broker, cti, jobs, recon
from ..services.analyzer import validate_rule
from ..services.normalization import normalize_identifier
from ..services.pipeline import force_yara_refresh
from . import serializers as ser

router = APIRouter()

_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[a-z]{2,24}$")
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


# ── Watchlist ────────────────────────────────────────────────────────────────


class WatchCreate(BaseModel):
    type: Literal["domain", "email", "keyword", "ip", "wallet"]
    value: str = Field(min_length=3, max_length=255)
    is_vip: bool = False

    @model_validator(mode="after")
    def _check(self):
        v = self.value.strip()
        if self.type in {"domain", "email"}:
            v = normalize_identifier(v, self.type)
        if self.type == "domain" and not _DOMAIN_RE.match(v):
            raise ValueError("not a valid domain")
        if self.type == "email" and not _EMAIL_RE.match(v):
            raise ValueError("not a valid email")
        if self.type == "ip":
            ipaddress.IPv4Address(v)
        self.value = v
        return self


class WatchUpdate(BaseModel):
    is_vip: bool | None = None
    is_active: bool | None = None


@router.get("/watchlist", tags=["watchlist"])
async def list_watch(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    rows = await db.execute(select(WatchItem).where(WatchItem.tenant_id == principal.tenant_id).order_by(WatchItem.type, WatchItem.value))
    return [ser.watch_item(w) for w in rows.scalars()]


@router.post("/watchlist", status_code=201, tags=["watchlist"])
async def add_watch(body: WatchCreate, request: Request, principal: Principal = Depends(require_scope("write")),
                    db: AsyncSession = Depends(get_db)):
    item = WatchItem(tenant_id=principal.tenant_id, type=body.type, value=body.value, is_vip=body.is_vip)
    db.add(item)
    try:
        await db.flush()
    except IntegrityError:
        raise HTTPException(409, "Already on the watchlist")
    await log_action(db, action="CREATE_WATCH_ITEM", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="watch_item", resource_id=item.id, details={"type": item.type, "value": item.value, "vip": item.is_vip},
                     ip_address=client_ip(request))
    return ser.watch_item(item)


async def _watch(db, principal, item_id) -> WatchItem:
    item = await db.get(WatchItem, item_id)
    if item is None or item.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Watch item not found")
    return item


EXPOSURE_ROW_CAP = 20_000
_OPEN = ("new", "reviewing", "escalated")


async def _matched_leaks(db, tenant_id: str):
    """Most recent leaks that matched any watch item. Filtered in Python so it
    runs the same on Postgres and SQLite."""
    rows = (await db.execute(
        select(Leak.id, Leak.title, Leak.snippet, Leak.source, Leak.category, Leak.severity, Leak.status,
               Leak.watch_matches, Leak.discovered_at, Leak.acknowledged_at)
        .where(Leak.tenant_id == tenant_id).order_by(Leak.discovered_at.desc()).limit(EXPOSURE_ROW_CAP)
    )).all()
    return [r for r in rows if r.watch_matches]


def _exposure_of(leaks) -> dict:
    open_ = [r for r in leaks if r.status in _OPEN]
    bands = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in leaks:
        bands["critical" if r.severity >= 80 else "high" if r.severity >= 60 else "medium" if r.severity >= 30 else "low"] += 1
    return {
        "hits": len(leaks),
        "open": len(open_),
        # Threat exposure = the worst leak still open against this asset.
        "exposure": max((r.severity for r in open_), default=0),
        "max_severity": max((r.severity for r in leaks), default=0),
        "unacked_critical": sum(1 for r in open_ if r.severity >= 80 and r.acknowledged_at is None),
        "bands": bands,
        "first_seen": ser.iso(min((r.discovered_at for r in leaks), default=None)),
        "last_seen": ser.iso(max((r.discovered_at for r in leaks), default=None)),
    }


@router.get("/watchlist/exposure", tags=["watchlist"])
async def watch_exposure(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    """Every watch item with its threat exposure, worst first."""
    items = (await db.execute(select(WatchItem).where(WatchItem.tenant_id == principal.tenant_id))).scalars().all()
    by_item: dict[str, list] = {w.id: [] for w in items}
    for r in await _matched_leaks(db, principal.tenant_id):
        for m in r.watch_matches:
            if m.get("id") in by_item:
                by_item[m["id"]].append(r)
    rows = [{**ser.watch_item(w), **_exposure_of(by_item[w.id])} for w in items]
    rows.sort(key=lambda x: (x["exposure"], x["open"], x["hits"]), reverse=True)
    return rows


@router.get("/watchlist/{item_id}/insights", tags=["watchlist"])
async def watch_insights(item_id: str, principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    """One asset's exposure: daily hits for 90 days, sources, categories and
    its most severe leaks."""
    from datetime import timedelta

    item = await _watch(db, principal, item_id)
    leaks = [r for r in await _matched_leaks(db, principal.tenant_id) if any(m.get("id") == item.id for m in r.watch_matches)]
    today = utcnow().date()
    daily = {(today - timedelta(days=89 - i)).isoformat(): 0 for i in range(90)}
    sources: dict[str, int] = {}
    categories: dict[str, int] = {}
    for r in leaks:
        if (d := r.discovered_at.date().isoformat()) in daily:
            daily[d] += 1
        sources[r.source] = sources.get(r.source, 0) + 1
        categories[r.category or "OTHER"] = categories.get(r.category or "OTHER", 0) + 1
    top = sorted(leaks, key=lambda r: (r.severity, r.discovered_at), reverse=True)[:15]
    return {
        **ser.watch_item(item),
        **_exposure_of(leaks),
        "daily": [{"day": d, "count": c} for d, c in daily.items()],
        "sources": dict(sorted(sources.items(), key=lambda kv: -kv[1])),
        "categories": dict(sorted(categories.items(), key=lambda kv: -kv[1])),
        "leaks": [{"id": r.id, "title": r.title or (r.snippet or "")[:120], "source": r.source, "severity": r.severity,
                   "status": r.status, "discovered_at": ser.iso(r.discovered_at)} for r in top],
    }


@router.patch("/watchlist/{item_id}", tags=["watchlist"])
async def update_watch(item_id: str, body: WatchUpdate, request: Request, principal: Principal = Depends(require_scope("write")),
                       db: AsyncSession = Depends(get_db)):
    item = await _watch(db, principal, item_id)
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(item, k, v)
    await log_action(db, action="UPDATE_WATCH_ITEM", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="watch_item", resource_id=item.id, details=changes, ip_address=client_ip(request))
    return ser.watch_item(item)


@router.delete("/watchlist/{item_id}", status_code=204, tags=["watchlist"])
async def delete_watch(item_id: str, request: Request, principal: Principal = Depends(require_scope("write")),
                       db: AsyncSession = Depends(get_db)):
    item = await _watch(db, principal, item_id)
    await db.delete(item)
    await log_action(db, action="DELETE_WATCH_ITEM", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="watch_item", resource_id=item_id, details={"value": item.value}, ip_address=client_ip(request))


# ── Sources ──────────────────────────────────────────────────────────────────

_NEEDS_TARGET = {"onion", "telegram", "feed"}


class SourceCreate(BaseModel):
    kind: Literal["ahmia", "onion", "telegram", "feed", "github", "hibp"]
    target: str | None = Field(None, max_length=512)
    interval_minutes: int = Field(360, ge=15, le=10080)
    max_pages: int = Field(10, ge=1, le=50)

    @model_validator(mode="after")
    def _check(self):
        if self.kind in _NEEDS_TARGET and not self.target:
            raise ValueError(f"{self.kind} sources need a target")
        if self.kind == "onion" and ".onion" not in (self.target or ""):
            raise ValueError("onion target must be a .onion URL")
        if self.kind == "feed":
            try:
                recon.ensure_public_url(self.target or "")
            except recon.ReconError as exc:
                raise ValueError(f"feed target: {exc}")
        return self


class SourceUpdate(BaseModel):
    is_active: bool | None = None
    interval_minutes: int | None = Field(None, ge=15, le=10080)
    max_pages: int | None = Field(None, ge=1, le=50)


@router.get("/sources", tags=["sources"])
async def list_sources(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    rows = await db.execute(select(Source).where(Source.tenant_id == principal.tenant_id).order_by(Source.created_at))
    return [ser.source(s) for s in rows.scalars()]


@router.post("/sources", status_code=201, tags=["sources"])
async def add_source(body: SourceCreate, request: Request, principal: Principal = Depends(require_scope("write")),
                     db: AsyncSession = Depends(get_db)):
    src = Source(tenant_id=principal.tenant_id, **body.model_dump())
    db.add(src)
    await db.flush()
    await log_action(db, action="CREATE_SOURCE", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="source", resource_id=src.id, details=body.model_dump(), ip_address=client_ip(request))
    return ser.source(src)


async def _source(db, principal, source_id) -> Source:
    src = await db.get(Source, source_id)
    if src is None or src.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Source not found")
    return src


@router.patch("/sources/{source_id}", tags=["sources"])
async def update_source(source_id: str, body: SourceUpdate, request: Request,
                        principal: Principal = Depends(require_scope("write")), db: AsyncSession = Depends(get_db)):
    src = await _source(db, principal, source_id)
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(src, k, v)
    await log_action(db, action="UPDATE_SOURCE", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="source", resource_id=src.id, details=changes, ip_address=client_ip(request))
    return ser.source(src)


@router.delete("/sources/{source_id}", status_code=204, tags=["sources"])
async def delete_source(source_id: str, request: Request, principal: Principal = Depends(require_scope("write")),
                        db: AsyncSession = Depends(get_db)):
    src = await _source(db, principal, source_id)
    await db.delete(src)
    await log_action(db, action="DELETE_SOURCE", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="source", resource_id=source_id, ip_address=client_ip(request))


@router.post("/sources/{source_id}/run", status_code=202, tags=["sources"])
async def run_source_now(source_id: str, request: Request, background: BackgroundTasks,
                         principal: Principal = Depends(require_scope("recon")), db: AsyncSession = Depends(get_db)):
    src = await _source(db, principal, source_id)
    await log_action(db, action="RUN_SOURCE", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="source", resource_id=src.id, details={"kind": src.kind}, ip_address=client_ip(request))
    return await jobs.enqueue(broker.TASK_RECON, src.id, background=background)


@router.get("/sources/runs", tags=["sources"])
async def list_runs(source_id: str | None = None, kind: list[str] | None = Query(None),
                    adhoc: bool = Query(False, description="only one-off probes (runs with no source)"),
                    limit: int = Query(50, ge=1, le=200),
                    principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    q = select(SourceRun).where(SourceRun.tenant_id == principal.tenant_id)
    if source_id:
        q = q.where(SourceRun.source_id == source_id)
    if kind:
        q = q.where(SourceRun.kind.in_(kind))
    if adhoc:
        q = q.where(SourceRun.source_id.is_(None))
    rows = await db.execute(q.order_by(SourceRun.started_at.desc()).limit(limit))
    return [ser.source_run(r) for r in rows.scalars()]


@router.get("/sources/runs/{run_id}", tags=["sources"])
async def get_run(run_id: str, principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    run = await db.get(SourceRun, run_id)
    if run is None or run.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Run not found")
    return ser.source_run(run, with_report=True)


# ── Recon probes (one-off) ───────────────────────────────────────────────────


async def _queue_probe(db: AsyncSession, background: BackgroundTasks, tenant_id: str, kind: str, query: str) -> dict:
    """Record the run before queueing so the caller gets an id to poll at
    ``GET /sources/runs/{run_id}``."""
    run = SourceRun(tenant_id=tenant_id, kind=kind, query=query[:512],
                    via_tor=bool(settings.TOR_PROXY) and kind == "ahmia")
    db.add(run)
    await db.commit()
    return {**await jobs.enqueue(broker.TASK_AHMIA, tenant_id, query, kind, run.id, background=background), "run_id": run.id}


@router.get("/recon/darkweb", status_code=202, tags=["recon"])
async def darkweb_probe(request: Request, background: BackgroundTasks, q: str = Query(..., min_length=2, max_length=128),
                        principal: Principal = Depends(require_scope("recon")), db: AsyncSession = Depends(get_db)):
    """Queue an Ahmia search through the Tor pool. Results land as leaks and
    in the run report (``GET /sources/runs/{id}``); every probe is audited
    when queued, success or not."""
    try:
        query = recon.sanitize_query(q)
    except recon.ReconError as exc:
        raise HTTPException(422, str(exc))
    await log_action(db, action="DARK_WEB_RECON", tenant_id=principal.tenant_id, user_id=principal.actor,
                     details={"query": query}, ip_address=client_ip(request))
    return await _queue_probe(db, background, principal.tenant_id, "ahmia", query)


@router.get("/recon/telegram", status_code=202, tags=["recon"])
async def telegram_probe(request: Request, background: BackgroundTasks, channel: str = Query(..., min_length=4, max_length=64),
                         principal: Principal = Depends(require_scope("recon")), db: AsyncSession = Depends(get_db)):
    await log_action(db, action="TELEGRAM_RECON", tenant_id=principal.tenant_id, user_id=principal.actor,
                     details={"channel": channel}, ip_address=client_ip(request))
    return await _queue_probe(db, background, principal.tenant_id, "telegram", channel)


@router.get("/recon/shodan", tags=["recon"])
async def shodan_probe(request: Request, ip: str = Query(...), principal: Principal = Depends(require_scope("recon")),
                       db: AsyncSession = Depends(get_db)):
    """Exposure of one of your IPs via Shodan InternetDB (keyless)."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        raise HTTPException(422, "not an IPv4 address")
    if addr.is_private or addr.is_loopback or addr.is_reserved:
        raise HTTPException(422, "private or reserved address")
    await log_action(db, action="SHODAN_RECON", tenant_id=principal.tenant_id, user_id=principal.actor,
                     details={"ip": ip}, ip_address=client_ip(request))
    try:
        return await cti.shodan_internetdb(str(addr))
    except Exception as exc:
        raise HTTPException(502, f"InternetDB unavailable: {type(exc).__name__}")


# ── YARA rules ───────────────────────────────────────────────────────────────


class YaraCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    content: str = Field(min_length=10, max_length=50_000)

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        if not _NAME_RE.match(v):
            raise ValueError("name must be an identifier (letters, digits, underscore)")
        return v


@router.get("/yara/rules", tags=["yara"])
async def list_rules(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    rows = await db.execute(select(YaraRule).where((YaraRule.tenant_id == principal.tenant_id) | YaraRule.tenant_id.is_(None)))
    return [ser.yara_rule(r) for r in rows.scalars()]


@router.post("/yara/rules", status_code=201, tags=["yara"])
async def create_rule(body: YaraCreate, request: Request, principal: Principal = Depends(require_scope("write")),
                      db: AsyncSession = Depends(get_db)):
    if err := validate_rule(body.content):
        raise HTTPException(422, f"YARA compile error: {err}")
    rule = YaraRule(tenant_id=principal.tenant_id, name=body.name, content=body.content)
    db.add(rule)
    try:
        await db.flush()
    except IntegrityError:
        raise HTTPException(409, "A rule with that name exists")
    await log_action(db, action="CREATE_YARA_RULE", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="yara_rule", resource_id=rule.id, details={"name": rule.name}, ip_address=client_ip(request))
    force_yara_refresh()
    return ser.yara_rule(rule)


@router.delete("/yara/rules/{rule_id}", status_code=204, tags=["yara"])
async def delete_rule(rule_id: str, request: Request, principal: Principal = Depends(require_scope("write")),
                      db: AsyncSession = Depends(get_db)):
    rule = await db.get(YaraRule, rule_id)
    if rule is None or rule.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Rule not found")
    await db.delete(rule)
    await log_action(db, action="DELETE_YARA_RULE", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="yara_rule", resource_id=rule_id, details={"name": rule.name}, ip_address=client_ip(request))
    force_yara_refresh()


@router.post("/yara/test", tags=["yara"])
async def test_rule(body: dict, principal: Principal = Depends(require_scope("read"))):
    """Compile a rule and run it against sample text, without saving."""
    source, sample = str(body.get("content", ""))[:50_000], str(body.get("sample", ""))[:200_000]
    if err := validate_rule(source):
        return {"valid": False, "error": err, "matches": []}
    import yara

    matches = yara.compile(source=source, includes=False).match(data=sample.encode(), timeout=10)
    return {"valid": True, "error": None, "matches": [m.rule for m in matches]}


# ── Notifications ────────────────────────────────────────────────────────────


@router.get("/notifications", tags=["notifications"])
async def list_notifications(unacknowledged: bool = False, limit: int = Query(50, ge=1, le=200),
                             principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    q = select(Notification).where(Notification.tenant_id == principal.tenant_id)
    if unacknowledged:
        q = q.where(Notification.acknowledged_at.is_(None))
    rows = await db.execute(q.order_by(Notification.created_at.desc()).limit(limit))
    return [ser.notification(n) for n in rows.scalars()]


@router.post("/notifications/{notification_id}/ack", tags=["notifications"])
async def ack_notification(notification_id: str, principal: Principal = Depends(require_scope("write")),
                           db: AsyncSession = Depends(get_db)):
    n = await db.get(Notification, notification_id)
    if n is None or n.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Notification not found")
    n.acknowledged_at = n.acknowledged_at or utcnow()
    await db.commit()
    return ser.notification(n)

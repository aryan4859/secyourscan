import asyncio
import csv
import io
import json
import time

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import verify_chain
from ..config import settings
from ..database import get_db
from ..deps import Principal, require_scope
from ..models import AuditLog, VerifiedDomain
from ..services import broker, license, search_index, storage
from ..services.breaker import ai_breaker, es_breaker, minio_breaker
from . import serializers as ser

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/status")
async def status(db: AsyncSession = Depends(get_db)):
    """Can the API reach its database? Always 200; read the body."""
    start = time.perf_counter()
    try:
        await db.execute(text("SELECT 1"))
        ok = True
    except Exception:
        ok = False
    return {"status": "operational" if ok else "degraded", "latency_ms": {"total": round((time.perf_counter() - start) * 1000, 2)}}


async def _probe(enabled: bool, fn) -> str:
    if not enabled:
        return "disabled"
    try:
        return "ok" if await asyncio.wait_for(fn(), timeout=3.0) else "degraded"
    except Exception:
        return "degraded"


@router.get("/health")
async def health(db: AsyncSession = Depends(get_db)):
    """Which backing services are up. 503 if anything configured is down.
    Never names hosts or errors — those go to the log."""

    async def _db():
        await db.execute(text("SELECT 1"))
        return True

    checks = dict(zip(
        ["database", "elasticsearch", "object_storage", "broker"],
        await asyncio.gather(
            _probe(True, _db),
            _probe(settings.es_enabled, search_index.ping),
            _probe(settings.minio_enabled, storage.ping),
            _probe(not settings.inline_pipeline, broker.ping),
        ),
    ))
    checks["ai"] = "enabled" if settings.ai_enabled else "disabled"
    checks["tor"] = "configured" if settings.TOR_PROXY else "disabled"
    breakers = {b.name: b.state for b in (es_breaker, minio_breaker, ai_breaker)}
    healthy = all(v in {"ok", "disabled", "enabled", "configured"} for v in checks.values())
    return JSONResponse({"status": "ok" if healthy else "degraded", "components": checks, "circuits": breakers},
                        status_code=200 if healthy else 503)


@router.get("/license")
async def license_status(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    st = license.status()
    return {**st, "domains_used": await db.scalar(select(func.count()).select_from(VerifiedDomain))}


@router.get("/audit")
async def audit_log(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), action: str | None = None,
                    principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    q = select(AuditLog).where(AuditLog.tenant_id == principal.tenant_id)
    if action:
        q = q.where(AuditLog.action == action)
    rows = await db.execute(q.order_by(AuditLog.id.desc()).limit(limit).offset(offset))
    return [ser.audit(a) for a in rows.scalars()]


@router.get("/audit/verify")
async def audit_verify(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    return await verify_chain(db, principal.tenant_id)


@router.get("/audit/export.csv")
async def audit_csv(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(AuditLog).where(AuditLog.tenant_id == principal.tenant_id).order_by(AuditLog.id))).scalars()
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL)
    w.writerow(["id", "timestamp", "user_id", "action", "resource_type", "resource_id", "ip_address", "details", "prev_hash", "row_hash"])
    for a in rows:
        cells = [a.id, ser.iso(a.timestamp), a.user_id, a.action, a.resource_type, a.resource_id, a.ip_address,
                 json.dumps(a.details, default=str), a.prev_hash, a.row_hash]
        w.writerow(["'" + c if isinstance(c, str) and c.startswith(("=", "+", "-", "@", "\t", "\r")) else c for c in cells])
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="audit.csv"'})

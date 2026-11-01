"""Identity & access intelligence and vulnerability intelligence."""

from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..database import SessionLocal, get_db
from ..deps import Principal, client_ip, require_scope
from ..services import identity, intel, vulnintel
from ..models import utcnow

router = APIRouter()


# ── Identity ─────────────────────────────────────────────────────────────────


@router.get("/identity/summary", tags=["identity"])
async def identity_summary(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    return identity.summary(await identity.collect(db, principal.tenant_id))


@router.get("/identity/identities", tags=["identity"])
async def identity_list(q: str | None = Query(None, max_length=255),
                        kind: Literal["all", "stealer", "corporate", "vip", "reused"] = "all",
                        limit: int = Query(200, ge=1, le=1000),
                        principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    return identity.identities(await identity.collect(db, principal.tenant_id), q=q, kind=kind, limit=limit)


@router.get("/identity/identity", tags=["identity"])
async def identity_detail(login: str = Query(min_length=1, max_length=255),
                          principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    out = identity.identity(await identity.collect(db, principal.tenant_id), login)
    if out is None:
        raise HTTPException(404, "No exposure recorded for this identity")
    return out


@router.get("/identity/machines", tags=["identity"])
async def identity_machines(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    data = await identity.collect(db, principal.tenant_id)
    rows = [identity.machine_out(m) for m in data["machines"]]
    rows.sort(key=lambda m: (-len(m["corporate_apps"]), -m["accounts"], m["last_seen"]), reverse=False)
    return rows


# ── Vulnerability intelligence ───────────────────────────────────────────────


@router.get("/vuln-intel/feed", tags=["vuln intel"])
async def vuln_feed(days: int = Query(30, ge=1, le=120), affecting: bool = False, q: str | None = Query(None, max_length=120),
                    principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    data = await vulnintel.feed(db, principal.tenant_id, days=days, only_affecting=affecting, q=q)
    status = (await intel.statuses(db, principal.tenant_id)).get("vulnintel", {})
    return {**data, "refresh": status}


class StackItem(BaseModel):
    vendor: str = Field("", max_length=80)
    product: str = Field(min_length=1, max_length=80)
    version: str = Field("", max_length=40)
    critical: bool = False


class StackBody(BaseModel):
    items: list[StackItem] = Field(default_factory=list, max_length=vulnintel.MAX_STACK)


@router.get("/vuln-intel/stack", tags=["vuln intel"])
async def get_stack(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    return {"declared": await vulnintel.declared_stack(db, principal.tenant_id),
            "detected": await vulnintel.detected_stack(db, principal.tenant_id)}


@router.put("/vuln-intel/stack", tags=["vuln intel"])
async def put_stack(body: StackBody, request: Request, principal: Principal = Depends(require_scope("write")),
                    db: AsyncSession = Depends(get_db)):
    items = await vulnintel.save_stack(db, principal.tenant_id, [i.model_dump() for i in body.items])
    await log_action(db, action="UPDATE_TECH_STACK", tenant_id=principal.tenant_id, user_id=principal.actor,
                     details={"items": len(items)}, ip_address=client_ip(request))
    return {"declared": items}


async def _refresh(tenant_id: str) -> None:
    async with SessionLocal() as db:
        await intel.set_status(db, tenant_id, "vulnintel", status="running", started_at=utcnow().isoformat())
        try:
            result = await vulnintel.refresh_feeds(db)
            result["incidents"] = await vulnintel.open_incidents(db, tenant_id)
            await intel.set_status(db, tenant_id, "vulnintel", status="ok", finished_at=utcnow().isoformat(), result=result)
        except Exception as exc:  # noqa: BLE001 — reported to the UI
            await db.rollback()
            await intel.set_status(db, tenant_id, "vulnintel", status="error", finished_at=utcnow().isoformat(),
                                   error=str(exc)[:300])


@router.post("/vuln-intel/refresh", status_code=202, tags=["vuln intel"])
async def refresh(background: BackgroundTasks, request: Request, principal: Principal = Depends(require_scope("recon")),
                  db: AsyncSession = Depends(get_db)):
    """Refresh KEV, NVD and EPSS now (they also refresh every 6 hours)."""
    current = (await intel.statuses(db, principal.tenant_id)).get("vulnintel", {})
    if current.get("status") in ("queued", "running"):
        raise HTTPException(409, "A refresh is already running")
    await intel.set_status(db, principal.tenant_id, "vulnintel", status="queued", queued_at=utcnow().isoformat(), error=None)
    await log_action(db, action="VULN_INTEL_REFRESH", tenant_id=principal.tenant_id, user_id=principal.actor,
                     ip_address=client_ip(request))
    background.add_task(_refresh, principal.tenant_id)
    return {"status": "queued"}

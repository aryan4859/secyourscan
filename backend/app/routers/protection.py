"""Executive protection and takedown requests."""

import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..database import get_db
from ..deps import Principal, client_ip, require_scope
from ..models import Executive, TakedownRequest, Tenant, utcnow
from ..services import executives, takedown

router = APIRouter()
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[a-z]{2,24}$", re.I)


# ── Executives ───────────────────────────────────────────────────────────────


class ExecBody(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    title: str | None = Field(None, max_length=120)
    emails: list[str] = Field(default_factory=list, max_length=20)
    usernames: list[str] = Field(default_factory=list, max_length=20)
    phones: list[str] = Field(default_factory=list, max_length=10)
    notes: str = Field("", max_length=4000)

    @field_validator("emails")
    @classmethod
    def _emails(cls, v):
        out = []
        for e in v:
            e = e.strip().lower()
            if e and not _EMAIL_RE.match(e):
                raise ValueError(f"not a valid email: {e}")
            if e:
                out.append(e)
        return list(dict.fromkeys(out))

    @field_validator("usernames", "phones")
    @classmethod
    def _strip(cls, v):
        return list(dict.fromkeys(x.strip()[:64] for x in v if x.strip()))


class ExecUpdate(ExecBody):
    name: str | None = Field(None, min_length=3, max_length=120)


@router.get("/executives", tags=["executives"])
async def list_execs(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    profs = await executives.profiles(db, principal.tenant_id)
    # The list view carries counts, not every mention.
    return [{k: v for k, v in p.items() if k not in ("mentions", "accounts", "impersonation")} for p in profs]


@router.get("/executives/{exec_id}", tags=["executives"])
async def get_exec(exec_id: str, principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    profs = await executives.profiles(db, principal.tenant_id, only=exec_id)
    if not profs:
        raise HTTPException(404, "Executive not found")
    return profs[0]


@router.post("/executives", status_code=201, tags=["executives"])
async def create_exec(body: ExecBody, request: Request, principal: Principal = Depends(require_scope("write")),
                      db: AsyncSession = Depends(get_db)):
    x = Executive(tenant_id=principal.tenant_id, name=body.name.strip(), title=body.title, emails=body.emails,
                  usernames=body.usernames, phones=body.phones, notes=body.notes)
    db.add(x)
    try:
        await db.flush()
    except IntegrityError:
        raise HTTPException(409, "An executive with this name already exists")
    added = await executives.sync_watchlist(db, x)
    await log_action(db, action="CREATE_EXECUTIVE", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="executive", resource_id=x.id, details={"name": x.name, "watch_items": added},
                     ip_address=client_ip(request))
    return (await executives.profiles(db, principal.tenant_id, only=x.id))[0]


async def _exec(db, principal, exec_id) -> Executive:
    x = await db.get(Executive, exec_id)
    if x is None or x.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Executive not found")
    return x


@router.patch("/executives/{exec_id}", tags=["executives"])
async def update_exec(exec_id: str, body: ExecUpdate, request: Request, principal: Principal = Depends(require_scope("write")),
                      db: AsyncSession = Depends(get_db)):
    x = await _exec(db, principal, exec_id)
    for f in body.model_fields_set:
        val = getattr(body, f)
        if val is not None:
            setattr(x, f, val.strip() if isinstance(val, str) and f == "name" else val)
    try:
        await db.flush()
    except IntegrityError:
        raise HTTPException(409, "An executive with this name already exists")
    await executives.sync_watchlist(db, x)
    await log_action(db, action="UPDATE_EXECUTIVE", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="executive", resource_id=x.id, details={"fields": sorted(body.model_fields_set)},
                     ip_address=client_ip(request))
    return (await executives.profiles(db, principal.tenant_id, only=x.id))[0]


@router.delete("/executives/{exec_id}", tags=["executives"])
async def delete_exec(exec_id: str, request: Request, principal: Principal = Depends(require_scope("write")),
                      db: AsyncSession = Depends(get_db)):
    """Removes the profile. Its VIP watch items stay; delete them on the Watchlist if no longer wanted."""
    x = await _exec(db, principal, exec_id)
    await db.delete(x)
    await log_action(db, action="DELETE_EXECUTIVE", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="executive", resource_id=exec_id, details={"name": x.name}, ip_address=client_ip(request))
    return {"deleted": exec_id}


# ── Takedowns ────────────────────────────────────────────────────────────────


class TakedownCreate(BaseModel):
    source_type: Literal["lookalike", "phishing", "leak", "manual"] = "manual"
    source_id: str | None = Field(None, max_length=64)
    target: str | None = Field(None, max_length=1024)
    kind: Literal["domain", "url", "content", "social"] | None = None
    reason: Literal[tuple(takedown.REASONS)] = "phishing"  # type: ignore[valid-type]
    lookup: bool = True


class TakedownUpdate(BaseModel):
    status: Literal[takedown.STATUSES] | None = None  # type: ignore[valid-type]
    note: str = Field("", max_length=2000)
    notice: str | None = Field(None, max_length=20000)
    contacts: list[dict] | None = Field(None, max_length=20)


async def _org(db, tenant_id) -> str:
    t = await db.get(Tenant, tenant_id)
    return t.name if t else "our organisation"


@router.get("/takedowns", tags=["takedowns"])
async def list_takedowns(status: str | None = Query(None, max_length=16), principal: Principal = Depends(require_scope("read")),
                         db: AsyncSession = Depends(get_db)):
    q = select(TakedownRequest).where(TakedownRequest.tenant_id == principal.tenant_id)
    if status == "open":
        q = q.where(TakedownRequest.status.in_(takedown.OPEN))
    elif status:
        q = q.where(TakedownRequest.status == status)
    rows = (await db.execute(q.order_by(TakedownRequest.created_at.desc()))).scalars()
    return [takedown.serialize(t) for t in rows]


@router.get("/takedowns/stats", tags=["takedowns"])
async def takedown_stats(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    return await takedown.stats(db, principal.tenant_id)


@router.get("/takedowns/{td_id}", tags=["takedowns"])
async def get_takedown(td_id: str, principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    return takedown.serialize(await _td(db, principal, td_id), full=True)


async def _td(db, principal, td_id) -> TakedownRequest:
    td = await db.get(TakedownRequest, td_id)
    if td is None or td.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Takedown request not found")
    return td


async def _apply_lookup(td: TakedownRequest) -> None:
    info = await takedown.lookup(td.target)
    td.registrar, td.hosting = info["registrar"], info["hosting"]
    keep = [c for c in td.contacts or [] if c.get("source") == "manual"]
    td.contacts = keep + [c for c in info["contacts"] if c["email"].lower() not in {k["email"].lower() for k in keep}]
    td.evidence = {**(td.evidence or {}), "resolved_ips": info["ips"], "lookup_errors": info["errors"] or None,
                   "looked_up_at": utcnow().isoformat()}


@router.post("/takedowns", status_code=201, tags=["takedowns"])
async def create_takedown(body: TakedownCreate, request: Request, principal: Principal = Depends(require_scope("write")),
                          db: AsyncSession = Depends(get_db)):
    evidence, target, kind = await takedown.evidence_for(db, principal.tenant_id, body.source_type, body.source_id)
    if body.source_type != "manual" and not evidence:
        raise HTTPException(404, f"{body.source_type} not found")
    target = (body.target or target or "").strip()
    if not target:
        raise HTTPException(422, "target is required (the domain or URL to take down)")
    if body.source_type != "manual" and body.source_id:
        dup = await db.scalar(select(TakedownRequest.id).where(
            TakedownRequest.tenant_id == principal.tenant_id, TakedownRequest.source_type == body.source_type,
            TakedownRequest.source_id == body.source_id, TakedownRequest.status.in_(takedown.OPEN)))
        if dup:
            raise HTTPException(409, "An open takedown request already exists for this finding")
    td = TakedownRequest(tenant_id=principal.tenant_id, number=await takedown.next_number(db, principal.tenant_id),
                         kind=body.kind or kind, target=target[:1024], source_type=body.source_type,
                         source_id=body.source_id, reason=body.reason, evidence=evidence,
                         created_by=principal.email or principal.actor,
                         history=[{"at": utcnow().isoformat(), "actor": principal.email or principal.actor,
                                   "status": "draft", "note": "Request drafted"}])
    if body.lookup:
        await _apply_lookup(td)
    td.notice = takedown.draft_notice(await _org(db, principal.tenant_id), td)
    db.add(td)
    await db.flush()
    await takedown.write_back(db, td)
    await log_action(db, action="CREATE_TAKEDOWN", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="takedown", resource_id=td.id, details={"target": td.target, "reason": td.reason},
                     ip_address=client_ip(request))
    return takedown.serialize(td, full=True)


@router.post("/takedowns/{td_id}/lookup", tags=["takedowns"])
async def relookup(td_id: str, principal: Principal = Depends(require_scope("write")), db: AsyncSession = Depends(get_db)):
    td = await _td(db, principal, td_id)
    await _apply_lookup(td)
    if td.status == "draft":
        td.notice = takedown.draft_notice(await _org(db, principal.tenant_id), td)
    await db.commit()
    return takedown.serialize(td, full=True)


@router.patch("/takedowns/{td_id}", tags=["takedowns"])
async def update_takedown(td_id: str, body: TakedownUpdate, request: Request,
                          principal: Principal = Depends(require_scope("write")), db: AsyncSession = Depends(get_db)):
    td = await _td(db, principal, td_id)
    who = principal.email or principal.actor
    now = utcnow()
    if body.notice is not None:
        td.notice = body.notice
    if body.contacts is not None:
        clean = []
        for c in body.contacts:
            email = str(c.get("email", "")).strip()
            if not _EMAIL_RE.match(email):
                raise HTTPException(422, f"not a valid contact email: {email}")
            clean.append({"role": str(c.get("role") or "contact")[:64], "name": (str(c.get("name"))[:120] if c.get("name") else None),
                          "email": email[:255], "source": c.get("source") if c.get("source") in ("rdap", "manual") else "manual"})
        td.contacts = clean
    if body.status and body.status != td.status:
        td.status = body.status
        if body.status == "submitted" and not td.submitted_at:
            td.submitted_at = now
        if body.status in ("taken_down", "rejected", "withdrawn"):
            td.resolved_at = now
        elif td.resolved_at:
            td.resolved_at = None  # reopened
        await takedown.write_back(db, td)
    if body.status or body.note:
        td.history = [*(td.history or []), {"at": now.isoformat(), "actor": who, "status": td.status, "note": body.note}]
    await log_action(db, action="UPDATE_TAKEDOWN", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="takedown", resource_id=td.id, details={"status": td.status},
                     ip_address=client_ip(request))
    return takedown.serialize(td, full=True)

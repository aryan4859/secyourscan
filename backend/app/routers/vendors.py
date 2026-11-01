"""Supply-chain risk: the tenant's vendors and their outside-in ratings.
Scans run as the ``vendors`` module of POST /intel/scan/{module}."""

import csv
import io
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..database import get_db
from ..deps import Principal, client_ip, require_scope
from ..models import Vendor
from ..services import vendors as svc
from .serializers import iso

router = APIRouter(prefix="/vendors", tags=["supply chain"])

Criticality = Literal["critical", "high", "medium", "low"]
_CRIT = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def _clean_domain(v: str) -> str:
    d = svc.registrable(v)
    if not _DOMAIN_RE.fullmatch(d):
        raise ValueError("not a valid domain")
    return d


def _vendor(v: Vendor, *, full: bool = False) -> dict:
    findings = v.findings or []
    out = {"id": v.id, "name": v.name, "domain": v.domain, "criticality": v.criticality, "category": v.category,
           "score": v.score, "grade": v.grade, "breaches": len(v.breaches or []),
           "top_findings": [f["title"] for f in findings[:3]],
           "critical_findings": sum(1 for f in findings if f["severity"] == "critical"),
           "trend": (v.history[-1]["score"] - v.history[-2]["score"]) if len(v.history or []) >= 2 else None,
           "last_scanned_at": iso(v.last_scanned_at), "created_at": iso(v.created_at)}
    if full:
        out |= {"contact": v.contact, "notes": v.notes, "findings": findings, "breach_posts": v.breaches or [],
                "history": v.history or [], "facts": v.facts or {}}
    return out


async def _get(db: AsyncSession, principal: Principal, vendor_id: str) -> Vendor:
    v = await db.get(Vendor, vendor_id)
    if v is None or v.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Vendor not found")
    return v


@router.get("")
async def list_vendors(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(Vendor).where(Vendor.tenant_id == principal.tenant_id))).scalars().all()
    rows.sort(key=lambda v: (v.score if v.score is not None else 101, _CRIT.get(v.criticality, 9), v.name.lower()))
    return [_vendor(v) for v in rows]


@router.get("/summary")
async def vendor_summary(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(Vendor).where(Vendor.tenant_id == principal.tenant_id))).scalars().all()
    rated = [v for v in rows if v.score is not None]
    return {
        "vendors": len(rows), "rated": len(rated),
        "average": round(sum(v.score for v in rated) / len(rated)) if rated else None,
        "by_grade": {g: sum(1 for v in rated if v.grade == g) for g in "ABCDF"},
        "breached": sum(1 for v in rows if v.breaches),
        "critical_at_risk": sum(1 for v in rated if v.criticality in ("critical", "high") and v.grade in ("D", "F")),
    }


class VendorIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    domain: str = Field(min_length=4, max_length=255)
    criticality: Criticality = "medium"
    category: str | None = Field(None, max_length=64)
    contact: str | None = Field(None, max_length=255)
    notes: str = Field("", max_length=4000)

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        return _clean_domain(v)


@router.post("", status_code=201)
async def add_vendor(body: VendorIn, request: Request, principal: Principal = Depends(require_scope("write")),
                     db: AsyncSession = Depends(get_db)):
    if await db.scalar(select(Vendor.id).where(Vendor.tenant_id == principal.tenant_id, Vendor.domain == body.domain)):
        raise HTTPException(409, f"{body.domain} is already a vendor")
    v = Vendor(tenant_id=principal.tenant_id, **body.model_dump())
    db.add(v)
    await db.commit()
    await log_action(db, action="ADD_VENDOR", tenant_id=principal.tenant_id, user_id=principal.actor, resource_type="vendor",
                     resource_id=v.id, details={"name": v.name, "domain": v.domain}, ip_address=client_ip(request))
    return _vendor(v, full=True)


class VendorImport(BaseModel):
    csv: str = Field(min_length=1, max_length=500_000, description="name,domain[,criticality[,category]] per line")


@router.post("/import")
async def import_vendors(body: VendorImport, request: Request, principal: Principal = Depends(require_scope("write")),
                         db: AsyncSession = Depends(get_db)):
    have = set((await db.execute(select(Vendor.domain).where(Vendor.tenant_id == principal.tenant_id))).scalars())
    added, skipped = [], []
    for row in csv.reader(io.StringIO(body.csv)):
        cells = [c.strip() for c in row]
        if not cells or not any(cells) or cells[0].lower() == "name":
            continue
        try:
            name, domain = cells[0], _clean_domain(cells[1])
        except (IndexError, ValueError):
            skipped.append(",".join(cells)[:120])
            continue
        crit = cells[2].lower() if len(cells) > 2 and cells[2].lower() in _CRIT else "medium"
        if domain in have or len(name) < 2 or len(have) >= svc.MAX_VENDORS:
            skipped.append(f"{name},{domain}")
            continue
        have.add(domain)
        db.add(Vendor(tenant_id=principal.tenant_id, name=name[:120], domain=domain, criticality=crit,
                      category=(cells[3][:64] if len(cells) > 3 and cells[3] else None)))
        added.append(domain)
    await db.commit()
    if added:
        await log_action(db, action="IMPORT_VENDORS", tenant_id=principal.tenant_id, user_id=principal.actor,
                         details={"added": len(added)}, ip_address=client_ip(request))
    return {"added": len(added), "skipped": skipped[:100]}


@router.get("/{vendor_id}")
async def get_vendor(vendor_id: str, principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    return _vendor(await _get(db, principal, vendor_id), full=True)


class VendorUpdate(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=120)
    criticality: Criticality | None = None
    category: str | None = Field(None, max_length=64)
    contact: str | None = Field(None, max_length=255)
    notes: str | None = Field(None, max_length=4000)


@router.patch("/{vendor_id}")
async def update_vendor(vendor_id: str, body: VendorUpdate, request: Request,
                        principal: Principal = Depends(require_scope("write")), db: AsyncSession = Depends(get_db)):
    v = await _get(db, principal, vendor_id)
    changes = {k: val for k, val in body.model_dump(exclude_unset=True).items()
               if val is not None or k in ("category", "contact")}  # only optional fields may be cleared
    for k, val in changes.items():
        setattr(v, k, val)
    await db.commit()
    await log_action(db, action="UPDATE_VENDOR", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="vendor", resource_id=v.id, details=changes, ip_address=client_ip(request))
    return _vendor(v, full=True)


@router.delete("/{vendor_id}", status_code=204)
async def delete_vendor(vendor_id: str, request: Request, principal: Principal = Depends(require_scope("write")),
                        db: AsyncSession = Depends(get_db)):
    v = await _get(db, principal, vendor_id)
    await db.delete(v)
    await db.commit()
    await log_action(db, action="DELETE_VENDOR", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="vendor", resource_id=vendor_id, details={"domain": v.domain}, ip_address=client_ip(request))
    return Response(status_code=204)

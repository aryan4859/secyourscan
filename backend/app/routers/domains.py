"""Domain ownership verification."""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..config import settings
from ..database import get_db
from ..deps import Principal, client_ip, require_scope
from ..models import VerifiedDomain
from ..services import domains, license
from .serializers import iso

router = APIRouter(prefix="/domains", tags=["domains"])


def _out(d: VerifiedDomain) -> dict:
    return {
        "id": d.id, "domain": d.domain, "verified": d.verified_at is not None, "verified_at": iso(d.verified_at),
        "created_at": iso(d.created_at), "last_checked_at": iso(d.last_checked_at), "last_error": d.last_error,
        "record_name": domains.record_name(d.domain), "record_value": f"{domains.VALUE_PREFIX}{d.token}",
    }


class DomainCreate(BaseModel):
    domain: str = Field(min_length=3, max_length=255)

    @field_validator("domain")
    @classmethod
    def _root(cls, v: str) -> str:
        root = domains.root_of(v)
        if "." not in root or not all(p and len(p) <= 63 for p in root.split(".")):
            raise ValueError("not a valid domain")
        return root


@router.get("")
async def list_domains(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(VerifiedDomain).where(VerifiedDomain.tenant_id == principal.tenant_id)
                             .order_by(VerifiedDomain.domain))).scalars()
    return {"required": settings.REQUIRE_DOMAIN_VERIFICATION, "items": [_out(d) for d in rows]}


@router.post("", status_code=201)
async def add_domain(body: DomainCreate, request: Request, principal: Principal = Depends(require_scope("write")),
                     db: AsyncSession = Depends(get_db)):
    """Start verification of a root domain; returns the TXT record to publish."""
    limit = license.max_domains()
    if limit is not None:
        used = await db.scalar(select(func.count()).select_from(VerifiedDomain))
        if used >= limit:
            raise HTTPException(402, f"Licence allows {limit} domain(s) on this install")
    row = VerifiedDomain(tenant_id=principal.tenant_id, domain=body.domain, token=domains.new_token())
    db.add(row)
    try:
        await db.flush()
    except IntegrityError:
        raise HTTPException(409, "Domain already added")
    await log_action(db, action="ADD_DOMAIN", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="domain", resource_id=row.id, details={"domain": row.domain},
                     ip_address=client_ip(request))
    return _out(row)


async def _get(db, principal, domain_id) -> VerifiedDomain:
    row = await db.get(VerifiedDomain, domain_id)
    if row is None or row.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Domain not found")
    return row


@router.post("/{domain_id}/verify")
async def verify_domain(domain_id: str, request: Request, principal: Principal = Depends(require_scope("write")),
                        db: AsyncSession = Depends(get_db)):
    row = await _get(db, principal, domain_id)
    was = row.verified_at is not None
    ok = await domains.check(row)
    if ok and not was:
        await log_action(db, action="VERIFY_DOMAIN", tenant_id=principal.tenant_id, user_id=principal.actor,
                         resource_type="domain", resource_id=row.id, details={"domain": row.domain},
                         ip_address=client_ip(request))
    await db.commit()
    return _out(row)


@router.delete("/{domain_id}", status_code=204)
async def delete_domain(domain_id: str, request: Request, principal: Principal = Depends(require_scope("write")),
                        db: AsyncSession = Depends(get_db)):
    row = await _get(db, principal, domain_id)
    await db.delete(row)
    await log_action(db, action="DELETE_DOMAIN", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="domain", resource_id=domain_id, details={"domain": row.domain},
                     ip_address=client_ip(request))

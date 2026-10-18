"""Domain Exposure report (JSON and PDF)."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..config import settings
from ..database import get_db
from ..deps import Principal, client_ip, require_scope
from ..models import Tenant, WatchItem
from ..services import domains, report

router = APIRouter(prefix="/report", tags=["report"])


@router.get("/domains")
async def report_domains(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    """Root domains a report can be built for, from the watchlist."""
    watched = (await db.execute(select(WatchItem.value).where(WatchItem.tenant_id == principal.tenant_id,
                                                              WatchItem.type == "domain"))).scalars().all()
    verified = await domains.verified_roots(db, principal.tenant_id)
    roots = sorted({domains.root_of(d) for d in watched} | verified)
    return [{"domain": r, "verified": r in verified,
             "allowed": r in verified or not settings.REQUIRE_DOMAIN_VERIFICATION} for r in roots]


async def _allowed(db, principal, domain) -> str:
    root = domains.root_of(domain)
    if settings.REQUIRE_DOMAIN_VERIFICATION and root not in await domains.verified_roots(db, principal.tenant_id):
        raise HTTPException(403, f"{root} is not verified for this tenant; verify it on the Domains page")
    return root


@router.get("/domain/{domain}")
async def domain_report(domain: str, principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    return await report.build(db, principal.tenant_id, await _allowed(db, principal, domain))


@router.get("/domain/{domain}/pdf")
async def domain_report_pdf(domain: str, request: Request, principal: Principal = Depends(require_scope("read")),
                            db: AsyncSession = Depends(get_db)):
    root = await _allowed(db, principal, domain)
    data = await report.build(db, principal.tenant_id, root)
    tenant = await db.get(Tenant, principal.tenant_id)
    body = report.pdf(data, tenant.name if tenant else "")
    await log_action(db, action="EXPORT_DOMAIN_REPORT", tenant_id=principal.tenant_id, user_id=principal.actor,
                     details={"domain": root, "score": data["score"]}, ip_address=client_ip(request))
    return Response(body, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="exposure-{root}.pdf"'})

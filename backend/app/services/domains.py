"""Domain ownership verification.

A tenant proves it controls a root domain by publishing a TXT record at
``_secyourscan-verify.<domain>`` containing ``secyourscan-verification=<token>``.
Subdomains are covered by their verified root.
"""

import secrets

import dns.asyncresolver
import dns.exception
import dns.resolver
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import VerifiedDomain, utcnow
from .brand import split_domain

RECORD_PREFIX = "_secyourscan-verify"
VALUE_PREFIX = "secyourscan-verification="


def root_of(domain: str) -> str:
    return ".".join(split_domain(domain.lower().strip(".")))


def new_token() -> str:
    return secrets.token_urlsafe(24)


def record_name(domain: str) -> str:
    return f"{RECORD_PREFIX}.{domain}"


async def txt_values(name: str) -> list[str]:
    r = dns.asyncresolver.Resolver()
    r.lifetime = 8
    try:
        return ["".join(s.decode(errors="replace") for s in a.strings) for a in await r.resolve(name, "TXT")]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []


async def check(row: VerifiedDomain) -> bool:
    """Look the record up now; records the outcome on ``row``."""
    row.last_checked_at = utcnow()
    try:
        values = await txt_values(record_name(row.domain))
    except (dns.exception.DNSException, OSError) as exc:
        row.last_error = f"DNS lookup failed: {type(exc).__name__}"
        return False
    if f"{VALUE_PREFIX}{row.token}" in values:
        row.verified_at = row.verified_at or utcnow()
        row.last_error = None
        return True
    row.last_error = "TXT record not found" if not values else "TXT record present but the token does not match"
    return False


async def verified_roots(db: AsyncSession, tenant_id: str) -> set[str]:
    rows = (await db.execute(select(VerifiedDomain.domain).where(
        VerifiedDomain.tenant_id == tenant_id, VerifiedDomain.verified_at.is_not(None)))).scalars().all()
    return set(rows)


async def in_scope(db: AsyncSession, tenant_id: str, domains) -> list[str]:
    """The watched domains a scan may cover: all of them when verification is
    not required, otherwise only those under a verified root."""
    domains = list(domains)
    if not settings.REQUIRE_DOMAIN_VERIFICATION:
        return domains
    roots = await verified_roots(db, tenant_id)
    return [d for d in domains if root_of(d) in roots]

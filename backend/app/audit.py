"""Hash-chained audit log.

Each row's hash covers its own canonical content and the previous row's hash
within the same tenant. ``verify_chain`` recomputes every hash in order and
reports the first row where either the content or the link no longer matches.
"""

import hashlib
import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditLog, utcnow

GENESIS = "0" * 64


def _canonical(row: AuditLog) -> bytes:
    body = {
        "tenant_id": row.tenant_id,
        "user_id": row.user_id,
        "action": row.action,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "details": row.details or {},
        "ip_address": row.ip_address,
        "timestamp": row.timestamp.isoformat(),
        "prev_hash": row.prev_hash,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()


def compute_hash(row: AuditLog) -> str:
    return hashlib.sha256(_canonical(row)).hexdigest()


async def _last_hash(db: AsyncSession, tenant_id: str | None) -> str:
    stmt = select(AuditLog.row_hash).order_by(AuditLog.id.desc()).limit(1)
    stmt = stmt.where(AuditLog.tenant_id == tenant_id) if tenant_id else stmt.where(AuditLog.tenant_id.is_(None))
    return (await db.scalar(stmt)) or GENESIS


async def log_action(
    db: AsyncSession,
    *,
    action: str,
    tenant_id: str | None,
    user_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
    commit: bool = True,
) -> AuditLog:
    if db.bind.dialect.name == "postgresql":
        # Two concurrent writers must not both link to the same previous row.
        from sqlalchemy import text

        await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"audit:{tenant_id}"})
    row = AuditLog(
        tenant_id=tenant_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        ip_address=ip_address,
        timestamp=utcnow(),
        prev_hash=await _last_hash(db, tenant_id),
    )
    row.row_hash = compute_hash(row)
    db.add(row)
    if commit:
        await db.commit()
    else:
        await db.flush()
    return row


async def verify_chain(db: AsyncSession, tenant_id: str | None) -> dict:
    stmt = select(AuditLog).order_by(AuditLog.id)
    stmt = stmt.where(AuditLog.tenant_id == tenant_id) if tenant_id else stmt.where(AuditLog.tenant_id.is_(None))
    rows = (await db.execute(stmt)).scalars().all()
    expected_prev = GENESIS
    for position, row in enumerate(rows):
        if row.prev_hash != expected_prev:
            return {"valid": False, "checked": position, "broken_at": row.id, "reason": "link"}
        if compute_hash(row) != row.row_hash:
            return {"valid": False, "checked": position, "broken_at": row.id, "reason": "content"}
        expected_prev = row.row_hash
    return {"valid": True, "checked": len(rows), "broken_at": None, "reason": None}

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..database import get_db
from ..deps import Principal, client_ip, get_principal, require_admin, require_platform_admin
from ..models import ApiKey, Tenant, User, utcnow
from ..security import generate_api_key, hash_password, verify_password
from . import serializers as ser

router = APIRouter(tags=["users"])


class ProfileUpdate(BaseModel):
    full_name: str | None = Field(None, max_length=120)
    current_password: str | None = None
    new_password: str | None = Field(None, min_length=12, max_length=256)


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    full_name: str | None = Field(None, max_length=120)
    role: Literal["admin", "analyst"] = "analyst"


class UserUpdate(BaseModel):
    role: Literal["admin", "analyst"] | None = None
    is_active: bool | None = None


class TenantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    admin_email: EmailStr
    admin_password: str = Field(min_length=12, max_length=256)


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scopes: list[Literal["ingest", "read", "write", "recon"]] = ["ingest"]


async def _me(db: AsyncSession, principal: Principal) -> User:
    if principal.via == "api_key":
        raise HTTPException(403, "API keys have no user profile")
    return await db.get(User, principal.user_id)


@router.get("/users/me")
async def get_me(principal: Principal = Depends(get_principal), db: AsyncSession = Depends(get_db)):
    user = await _me(db, principal)
    tenant = await db.get(Tenant, user.tenant_id)
    return {**ser.user(user), "tenant_name": tenant.name if tenant else None}


@router.put("/users/me")
async def update_me(body: ProfileUpdate, request: Request, principal: Principal = Depends(get_principal),
                    db: AsyncSession = Depends(get_db)):
    user = await _me(db, principal)
    if body.full_name is not None:
        user.full_name = body.full_name
    if body.new_password:
        if not body.current_password or not verify_password(body.current_password, user.password_hash):
            raise HTTPException(400, "Current password is incorrect")
        user.password_hash = hash_password(body.new_password)
    await log_action(db, action="UPDATE_PROFILE", tenant_id=user.tenant_id, user_id=user.id,
                     details={"password_changed": bool(body.new_password)}, ip_address=client_ip(request))
    return ser.user(user)


# ── Tenant user management (admin) ───────────────────────────────────────────


@router.get("/users")
async def list_users(principal: Principal = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    rows = await db.execute(select(User).where(User.tenant_id == principal.tenant_id).order_by(User.created_at))
    return [ser.user(u) for u in rows.scalars()]


@router.post("/users", status_code=201)
async def create_user(body: UserCreate, request: Request, principal: Principal = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)):
    if await db.scalar(select(User).where(func.lower(User.email) == body.email.lower())):
        raise HTTPException(409, "Email already registered")
    user = User(email=body.email.lower(), full_name=body.full_name, role=body.role, tenant_id=principal.tenant_id,
                password_hash=hash_password(body.password))
    db.add(user)
    await db.flush()
    await log_action(db, action="CREATE_USER", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="user", resource_id=user.id, details={"email": user.email, "role": user.role},
                     ip_address=client_ip(request))
    return ser.user(user)


@router.patch("/users/{user_id}")
async def update_user(user_id: str, body: UserUpdate, request: Request, principal: Principal = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if user is None or user.tenant_id != principal.tenant_id:
        raise HTTPException(404, "User not found")
    if user.id == principal.user_id and (body.role == "analyst" or body.is_active is False):
        raise HTTPException(400, "You cannot demote or disable yourself")
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(user, k, v)
    await log_action(db, action="UPDATE_USER", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="user", resource_id=user.id, details=changes, ip_address=client_ip(request))
    return ser.user(user)


# ── Tenants (admin) ──────────────────────────────────────────────────────────


@router.get("/tenants")
async def list_tenants(principal: Principal = Depends(require_platform_admin), db: AsyncSession = Depends(get_db)):
    rows = await db.execute(select(Tenant).order_by(Tenant.created_at))
    return [{"id": t.id, "name": t.name, "created_at": ser.iso(t.created_at), "is_current": t.id == principal.tenant_id}
            for t in rows.scalars()]


@router.post("/tenants", status_code=201)
async def create_tenant(body: TenantCreate, request: Request, principal: Principal = Depends(require_platform_admin),
                        db: AsyncSession = Depends(get_db)):
    if await db.scalar(select(Tenant).where(Tenant.name == body.name)):
        raise HTTPException(409, "Tenant name taken")
    if await db.scalar(select(User).where(func.lower(User.email) == body.admin_email.lower())):
        raise HTTPException(409, "Email already registered")
    tenant = Tenant(name=body.name)
    db.add(tenant)
    await db.flush()
    db.add(User(email=body.admin_email.lower(), role="admin", tenant_id=tenant.id,
                password_hash=hash_password(body.admin_password)))
    await log_action(db, action="CREATE_TENANT", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="tenant", resource_id=tenant.id, details={"name": tenant.name},
                     ip_address=client_ip(request))
    return {"id": tenant.id, "name": tenant.name}


@router.delete("/tenants/{tenant_id}", status_code=202)
async def delete_tenant(tenant_id: str, request: Request, principal: Principal = Depends(require_platform_admin),
                        db: AsyncSession = Depends(get_db)):
    if tenant_id == principal.tenant_id:
        raise HTTPException(400, "You cannot delete your own tenant")
    if await db.get(Tenant, tenant_id) is None:
        raise HTTPException(404, "Tenant not found")
    await log_action(db, action="DELETE_TENANT_TRIGGERED", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="tenant", resource_id=tenant_id, ip_address=client_ip(request))
    from ..config import settings
    from ..services import broker

    if settings.inline_pipeline:
        import asyncio

        from ..worker.tasks import delete_tenant_saga

        # The saga drives its own event loop, so it runs in a thread here.
        await asyncio.to_thread(delete_tenant_saga, tenant_id, principal.actor)
        return {"status": "deleted", "mode": "inline"}
    task_id = await broker.publish(broker.TASK_DELETE_TENANT, [tenant_id, principal.actor])
    return {"status": "accepted", "task_id": task_id}


# ── API keys (admin) ─────────────────────────────────────────────────────────


@router.get("/api-keys")
async def list_keys(principal: Principal = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    rows = await db.execute(select(ApiKey).where(ApiKey.tenant_id == principal.tenant_id).order_by(ApiKey.created_at.desc()))
    return [ser.api_key(k) for k in rows.scalars()]


@router.post("/api-keys", status_code=201)
async def create_key(body: ApiKeyCreate, request: Request, principal: Principal = Depends(require_admin),
                     db: AsyncSession = Depends(get_db)):
    plaintext, prefix, digest = generate_api_key()
    key = ApiKey(tenant_id=principal.tenant_id, name=body.name, prefix=prefix, key_hash=digest,
                 scopes=sorted(set(body.scopes)), created_by=principal.user_id)
    db.add(key)
    await db.flush()
    await log_action(db, action="CREATE_API_KEY", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="api_key", resource_id=key.id, details={"name": key.name, "scopes": key.scopes},
                     ip_address=client_ip(request))
    return {**ser.api_key(key), "key": plaintext}


@router.delete("/api-keys/{key_id}")
async def revoke_key(key_id: str, request: Request, principal: Principal = Depends(require_admin),
                     db: AsyncSession = Depends(get_db)):
    key = await db.get(ApiKey, key_id)
    if key is None or key.tenant_id != principal.tenant_id:
        raise HTTPException(404, "API key not found")
    key.revoked_at = key.revoked_at or utcnow()
    await log_action(db, action="REVOKE_API_KEY", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="api_key", resource_id=key.id, ip_address=client_ip(request))
    return ser.api_key(key)

"""Who is calling, and what they may touch.

Three credentials are accepted:

* ``Authorization: Bearer <jwt>`` — API clients.
* ``Authorization: Bearer sys_…`` or ``X-API-Key: sys_…`` — a tenant-bound API
  key (scrapers, the MCP server). Limited to the key's scopes.
* The ``sys_access_token`` httpOnly cookie — the browser. A state-changing
  request must echo the ``sys_csrf`` cookie in ``X-SYS-CSRF`` (double submit).
"""

import hmac
from dataclasses import dataclass, field

import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .database import get_db
from .models import ApiKey, RevokedToken, User, utcnow
from .security import API_KEY_PREFIX, decode_access_token, hash_api_key

ACCESS_COOKIE = "sys_access_token"
CSRF_COOKIE = "sys_csrf"
CSRF_HEADER = "X-SYS-CSRF"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Scopes a JWT session holds implicitly; API keys hold a subset.
ALL_SCOPES = {"ingest", "read", "write", "recon"}


@dataclass
class Principal:
    user_id: str
    tenant_id: str
    role: str
    via: str  # bearer | cookie | api_key
    scopes: set[str] = field(default_factory=lambda: set(ALL_SCOPES))
    email: str | None = None
    is_platform_admin: bool = False

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def actor(self) -> str:
        return self.user_id if self.via != "api_key" else f"apikey:{self.user_id}"


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail, headers={"WWW-Authenticate": "Bearer"})


async def _principal_from_api_key(db: AsyncSession, key: str) -> Principal:
    row = await db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_api_key(key)))
    if row is None or row.revoked_at is not None:
        raise _unauthorized("Invalid API key")
    row.last_used_at = utcnow()
    await db.commit()
    return Principal(user_id=row.id, tenant_id=row.tenant_id, role="analyst", via="api_key", scopes=set(row.scopes or []))


async def _principal_from_jwt(db: AsyncSession, token: str, via: str) -> Principal:
    try:
        claims = decode_access_token(token)
    except jwt.PyJWTError:
        raise _unauthorized("Invalid or expired token")
    if await db.get(RevokedToken, claims["jti"]):
        raise _unauthorized("Token revoked")
    user = await db.get(User, claims["sub"])
    if user is None or not user.is_active:
        raise _unauthorized("User disabled")
    # Role and tenant come from the database, not the token, so a demotion
    # takes effect before the token expires.
    return Principal(user_id=user.id, tenant_id=user.tenant_id, role=user.role, via=via, email=user.email,
                     is_platform_admin=user.is_platform_admin)


async def get_principal(request: Request, db: AsyncSession = Depends(get_db)) -> Principal:
    auth = request.headers.get("authorization", "")
    api_key = request.headers.get("x-api-key")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token.startswith(API_KEY_PREFIX):
            return await _principal_from_api_key(db, token)
        return await _principal_from_jwt(db, token, "bearer")
    if api_key:
        return await _principal_from_api_key(db, api_key)

    cookie = request.cookies.get(ACCESS_COOKIE)
    if not cookie:
        raise _unauthorized()
    if request.method not in SAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        expected = request.cookies.get(CSRF_COOKIE, "")
        if not expected or not hmac.compare_digest(sent, expected):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid")
    return await _principal_from_jwt(db, cookie, "cookie")


def require_scope(scope: str):
    async def dep(principal: Principal = Depends(get_principal)) -> Principal:
        if scope not in principal.scopes:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing scope: {scope}")
        return principal

    return dep


async def require_admin(principal: Principal = Depends(get_principal)) -> Principal:
    if not principal.is_admin or principal.via == "api_key":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin only")
    return principal


async def require_platform_admin(principal: Principal = Depends(require_admin)) -> Principal:
    if not principal.is_platform_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Platform admin only")
    return principal


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None

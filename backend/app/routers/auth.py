import secrets

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..config import settings
from ..database import get_db
from ..deps import ACCESS_COOKIE, CSRF_COOKIE, client_ip
from ..limiter import limiter
from ..models import RevokedToken, User
from ..security import create_access_token, decode_access_token, dummy_verify, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_cookies(response: Response, token: str, max_age: int) -> None:
    common = {"secure": settings.COOKIE_SECURE, "samesite": "strict", "max_age": max_age, "path": "/"}
    response.set_cookie(ACCESS_COOKIE, token, httponly=True, **common)
    # Readable by JS on purpose: the SPA echoes it in X-SYS-CSRF.
    response.set_cookie(CSRF_COOKIE, secrets.token_urlsafe(32), httponly=False, **common)


@router.post("/login")
@limiter.limit("10/minute")
async def login(request: Request, response: Response, form: OAuth2PasswordRequestForm = Depends(),
                db: AsyncSession = Depends(get_db)):
    email = form.username.strip().lower()
    user = await db.scalar(select(User).where(func.lower(User.email) == email))
    if user is None:
        dummy_verify()
    if user is None or not user.is_active or not verify_password(form.password, user.password_hash):
        # Sign-in attempts are audited (naso's docs list this as a gap).
        await log_action(db, action="LOGIN_FAILED", tenant_id=user.tenant_id if user else None,
                         user_id=user.id if user else None, details={"email": email[:255]}, ip_address=client_ip(request))
        raise HTTPException(401, "Incorrect email or password")
    token, _, _ = create_access_token(user.id, user.tenant_id, user.role)
    _set_cookies(response, token, settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    await log_action(db, action="LOGIN", tenant_id=user.tenant_id, user_id=user.id, ip_address=client_ip(request))
    return {"access_token": token, "token_type": "bearer", "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60}


@router.post("/logout")
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    """Revokes the presented token (bearer or cookie) and clears the cookies.
    Anonymous callers get 200 and nothing else."""
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else request.cookies.get(ACCESS_COOKIE)
    if token and not token.startswith("sys_"):
        try:
            claims = decode_access_token(token)
        except jwt.PyJWTError:
            claims = None
        if claims and not await db.get(RevokedToken, claims["jti"]):
            from datetime import UTC, datetime

            db.add(RevokedToken(jti=claims["jti"], expires_at=datetime.fromtimestamp(claims["exp"], UTC).replace(tzinfo=None)))
            await log_action(db, action="LOGOUT", tenant_id=claims.get("tid"), user_id=claims["sub"], ip_address=client_ip(request))
    response.delete_cookie(ACCESS_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return {"status": "logged_out"}

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import func, select

from .config import settings
from .database import SessionLocal, engine
from .limiter import limiter
from .models import Base, Source, Tenant, User
from .routers import ai, auth, domains, incidents, intel, leaks, monitoring, report, system, threatintel, users, vendors
from .security import hash_password, signing_keys
from .services import broker

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("secyourscan")


async def bootstrap() -> None:
    """Create tables and, on an empty database, the first tenant and admin
    from ADMIN_EMAIL / ADMIN_PASSWORD. There is no default password."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with SessionLocal() as db:
        if await db.scalar(select(func.count()).select_from(User)):
            return
        if not (settings.ADMIN_EMAIL and settings.ADMIN_PASSWORD):
            logger.warning("No users and no ADMIN_EMAIL/ADMIN_PASSWORD set: nobody can sign in yet")
            return
        if len(settings.ADMIN_PASSWORD) < 12:
            raise RuntimeError("ADMIN_PASSWORD must be at least 12 characters")
        tenant = Tenant(name="Default")
        db.add(tenant)
        await db.flush()
        db.add(User(email=settings.ADMIN_EMAIL.lower(), role="admin", tenant_id=tenant.id,
                    password_hash=hash_password(settings.ADMIN_PASSWORD), full_name="Administrator",
                    is_platform_admin=True))
        # A sweep source per kind that needs no target; they do nothing until
        # the watchlist has entries (and, for GitHub/HIBP, an API key).
        db.add(Source(tenant_id=tenant.id, kind="ahmia", interval_minutes=720))
        await db.commit()
        logger.info("Bootstrapped tenant 'Default' with admin %s", settings.ADMIN_EMAIL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    signing_keys()  # fail fast on a bad key
    await bootstrap()
    yield
    await broker.close()


app = FastAPI(
    title="SecYourScan API",
    version="0.2.0",
    description="Self-hosted exposure monitoring for your organisation's domains, emails and keywords.",
    lifespan=lifespan,
    docs_url=None if settings.is_production else "/api/docs",
    redoc_url=None if settings.is_production else "/api/redoc",
    openapi_url=None if settings.is_production else "/api/openapi.json",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=[h.strip() for h in settings.ALLOWED_HOSTS.split(",")])
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-SYS-CSRF", "X-API-Key"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if not request.url.path.startswith(("/api/docs", "/api/redoc")):
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    return response


for r in (auth.router, users.router, leaks.router, monitoring.router, intel.router, domains.router, report.router, ai.router,
          system.router, incidents.router, threatintel.router, vendors.router):
    app.include_router(r)

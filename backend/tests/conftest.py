import os
import tempfile

_db = os.path.join(tempfile.mkdtemp(prefix="sys-test-"), "test.db")
os.environ.update({
    "DATABASE_URL": f"sqlite+aiosqlite:///{_db}",
    "ADMIN_EMAIL": "admin@acme.example.com",
    "ADMIN_PASSWORD": "correct-horse-battery",
    "PIPELINE_INLINE": "true",
    "ENV": "development",
    "REQUIRE_DOMAIN_VERIFICATION": "false",  # tests/test_domains.py turns it on where it matters
})
for var in ("RABBITMQ_URL", "ES_URL", "ES_PASSWORD", "MINIO_ENDPOINT", "AI_ENDPOINT", "TOR_PROXY", "SOAR_WEBHOOK_URL"):
    os.environ.pop(var, None)

import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.database import engine  # noqa: E402
from app.limiter import limiter  # noqa: E402
from app.main import app, bootstrap  # noqa: E402
from app.models import Base  # noqa: E402

limiter.enabled = False
ADMIN = ("admin@acme.example.com", "correct-horse-battery")


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await bootstrap()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def login(client, email=ADMIN[0], password=ADMIN[1]) -> dict:
    r = await client.post("/auth/login", data={"username": email, "password": password})
    assert r.status_code == 200, r.text
    client.cookies.clear()  # use bearer auth unless a test opts into cookies
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest_asyncio.fixture
async def admin(client):
    return await login(client)


@pytest_asyncio.fixture
async def other_tenant(client, admin):
    r = await client.post("/tenants", headers=admin, json={
        "name": "Globex", "admin_email": "admin@globex.example.com", "admin_password": "another-long-password"})
    assert r.status_code == 201, r.text
    return await login(client, "admin@globex.example.com", "another-long-password")

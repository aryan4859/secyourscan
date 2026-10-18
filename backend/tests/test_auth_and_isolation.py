import re

from app.main import app

from .conftest import ADMIN, login

OPEN_ROUTES = {("POST", "/auth/login"), ("POST", "/auth/logout"), ("GET", "/system/status"), ("GET", "/system/health")}


def _concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "00000000-0000-0000-0000-000000000000", path)


async def test_every_route_requires_auth_except_the_open_ones(client):
    """Walk the OpenAPI schema and call every operation anonymously."""
    for path, ops in app.openapi()["paths"].items():
        for method in ops:
            if (method.upper(), path) in OPEN_ROUTES:
                continue
            r = await client.request(method.upper(), _concrete(path))
            assert r.status_code in (401, 403), f"{method.upper()} {path} answered {r.status_code} anonymously"


async def test_login_success_and_failure_are_audited(client):
    bad = await client.post("/auth/login", data={"username": ADMIN[0], "password": "wrong-password"})
    assert bad.status_code == 401
    headers = await login(client)
    actions = [a["action"] for a in (await client.get("/system/audit", headers=headers)).json()]
    assert "LOGIN" in actions and "LOGIN_FAILED" in actions


async def test_cookie_session_needs_csrf_for_writes(client):
    r = await client.post("/auth/login", data={"username": ADMIN[0], "password": ADMIN[1]})
    csrf = r.cookies.get("sys_csrf")
    assert client.cookies.get("sys_access_token")
    assert (await client.get("/watchlist")).status_code == 200  # safe method, no header needed
    body = {"type": "domain", "value": "acme.example.com"}
    assert (await client.post("/watchlist", json=body)).status_code == 403
    ok = await client.post("/watchlist", json=body, headers={"X-SYS-CSRF": csrf})
    assert ok.status_code == 201, ok.text


async def test_logout_revokes_the_token(client, admin):
    assert (await client.get("/users/me", headers=admin)).status_code == 200
    await client.post("/auth/logout", headers=admin)
    assert (await client.get("/users/me", headers=admin)).status_code == 401


async def test_tenants_cannot_see_each_others_data(client, admin, other_tenant):
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "acme.example.com"})
    r = await client.post("/leaks/ingest/webhook", headers=admin, json={"source": "test", "content": "ceo@acme.example.com:hunter2pass"})
    leak_id = r.json()["result"]["id"]

    assert (await client.get(f"/leaks/{leak_id}", headers=other_tenant)).status_code == 404
    assert (await client.get("/leaks/", headers=other_tenant)).json()["total"] == 0
    assert (await client.get("/watchlist", headers=other_tenant)).json() == []
    assert (await client.get("/leaks/search", headers=other_tenant, params={"q": "acme"})).json()["total"] == 0
    assert (await client.patch(f"/leaks/{leak_id}/status", headers=other_tenant, json={"status": "resolved"})).status_code == 404


async def test_api_key_is_limited_to_its_scopes(client, admin):
    key = (await client.post("/api-keys", headers=admin, json={"name": "scraper", "scopes": ["ingest"]})).json()["key"]
    h = {"X-API-Key": key}
    r = await client.post("/leaks/ingest/webhook", headers=h, json={"source": "scraper", "content": "fresh dump of something"})
    assert r.status_code == 202
    assert (await client.get("/leaks/", headers=h)).status_code == 403
    assert (await client.get("/users", headers=h)).status_code == 403
    key_id = (await client.get("/api-keys", headers=admin)).json()[0]["id"]
    await client.delete(f"/api-keys/{key_id}", headers=admin)
    assert (await client.post("/leaks/ingest/webhook", headers=h, json={"content": "x y z"})).status_code == 401


async def test_analyst_cannot_administer(client, admin):
    await client.post("/users", headers=admin, json={"email": "ana@acme.example.com", "password": "analyst-password-1", "role": "analyst"})
    analyst = await login(client, "ana@acme.example.com", "analyst-password-1")
    assert (await client.get("/users", headers=analyst)).status_code == 403
    assert (await client.post("/api-keys", headers=analyst, json={"name": "x"})).status_code == 403
    assert (await client.get("/leaks/", headers=analyst)).status_code == 200


async def test_only_the_platform_admin_manages_tenants(client, admin, other_tenant):
    tenants = (await client.get("/tenants", headers=admin)).json()
    acme = next(t for t in tenants if t["is_current"])
    # Globex's admin is a tenant admin, not a platform admin.
    assert (await client.get("/tenants", headers=other_tenant)).status_code == 403
    assert (await client.delete(f"/tenants/{acme['id']}", headers=other_tenant)).status_code == 403
    r = await client.post("/tenants", headers=other_tenant, json={
        "name": "Initech", "admin_email": "a@initech.example.com", "admin_password": "yet-another-password"})
    assert r.status_code == 403

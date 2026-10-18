"""SecYourScan MCP server (stdio).

Lets an MCP client — Claude Desktop, an IDE — query exposure data and queue
probes. Unlike a direct database connection, it talks to the HTTP API with a
tenant-bound API key, so the API's tenant scoping and the key's scopes apply:
the model cannot name another tenant, and a key without ``write`` cannot
change anything.

Environment:
    SYS_API_URL   e.g. http://localhost:8000
    SYS_API_KEY   an API key with scopes read (+ recon, write as wanted)
"""

import os

import httpx
from mcp.server.fastmcp import FastMCP

API_URL = os.environ.get("SYS_API_URL", "http://localhost:8000").rstrip("/")
API_KEY = os.environ.get("SYS_API_KEY")
if not API_KEY:
    raise SystemExit("SYS_API_KEY is required")

mcp = FastMCP("secyourscan")


async def _call(method: str, path: str, **kwargs):
    async with httpx.AsyncClient(base_url=API_URL, headers={"X-API-Key": API_KEY}, timeout=30) as client:
        resp = await client.request(method, path, **kwargs)
    if resp.status_code >= 400:
        return {"error": resp.status_code, "detail": resp.json().get("detail") if resp.headers.get("content-type", "").startswith("application/json") else resp.text[:200]}
    return resp.json()


@mcp.tool()
async def sys_search_leaks(query: str = "", min_severity: int = 0, limit: int = 10) -> dict:
    """Full-text search over this tenant's leaks (secrets are masked)."""
    return await _call("GET", "/leaks/search", params={"q": query or None, "min_severity": min_severity, "limit": min(limit, 50)})


@mcp.tool()
async def sys_get_leak(leak_id: str) -> dict:
    """Full detail of one leak: entities, YARA matches, AI verdict, CTI."""
    return await _call("GET", f"/leaks/{leak_id}")


@mcp.tool()
async def sys_get_stats() -> dict:
    """Totals, open criticals, breakdown by source/status/category, 30-day timeline."""
    return await _call("GET", "/leaks/stats")


@mcp.tool()
async def sys_get_watchlist() -> list | dict:
    """The organisation's monitored domains, emails, keywords, IPs and wallets."""
    return await _call("GET", "/watchlist")


@mcp.tool()
async def sys_darkweb_probe(query: str) -> dict:
    """Queue an Ahmia dark-web search (via Tor) for a watched term. Needs the recon scope."""
    return await _call("GET", "/recon/darkweb", params={"q": query})


@mcp.tool()
async def sys_shodan_exposure(ip: str) -> dict:
    """Open ports / CVEs for one of your public IPs (Shodan InternetDB). Needs the recon scope."""
    return await _call("GET", "/recon/shodan", params={"ip": ip})


@mcp.tool()
async def sys_flag_leak(leak_id: str, status: str) -> dict:
    """Set triage status: reviewing | escalated | resolved | false_positive. Needs the write scope."""
    return await _call("PATCH", f"/leaks/{leak_id}/status", json={"status": status})


if __name__ == "__main__":
    mcp.run()

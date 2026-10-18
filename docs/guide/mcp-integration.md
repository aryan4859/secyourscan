# MCP Server

`backend/mcp_server.py` is a [Model Context Protocol](https://modelcontextprotocol.io)
server over stdio. It lets an MCP client — Claude Desktop, an IDE, an agent
framework — search exposure data and queue probes.

## How it reaches the data

Through the HTTP API, with a tenant-bound API key. It does not open a database
connection.

That is the point of the design. naso's MCP server connects to the database
directly with the tenant fixed in its environment; this one is just another API
client. Consequently:

- **Tenant scoping holds.** The key belongs to one tenant, and every endpoint
  filters on the key's tenant. No tool takes a tenant argument, and nothing the
  model sends can change which tenant is queried.
- **Scopes hold.** A key without `write` cannot change a status; a key without
  `recon` cannot probe. The API answers `403` and the tool returns the error.
- **API keys are never admins.** `require_admin` rejects API keys outright, and
  raw evidence download refuses them, so the MCP server can reach neither user
  management nor unmasked content, whatever its scopes.
- **Actions are audited like any API call.** An audited action from the MCP
  server is recorded with `user_id` `apikey:<key id>`.

## Configuration

| Variable | Meaning |
|---|---|
| `SYS_API_URL` | base URL of the API; default `http://localhost:8000` |
| `SYS_API_KEY` | an API key (`sys_…`); the server exits at start if it is missing |

With the bundled Compose stack the API is not published on the host; reach it
through the web container, which proxies every API path:
`SYS_API_URL=http://localhost:8080`.

Create a key as an admin, with only the scopes the client needs:

```bash
curl -X POST http://localhost:8080/api-keys \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "claude-desktop", "scopes": ["read"]}'
```

The plaintext key is in the `key` field of the response and is shown once.

Claude Desktop, `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "secyourscan": {
      "command": "python",
      "args": ["/path/to/secyourscan/backend/mcp_server.py"],
      "env": {
        "SYS_API_URL": "http://localhost:8080",
        "SYS_API_KEY": "sys_…"
      }
    }
  }
}
```

The server needs `httpx` and `mcp` (both in `backend/requirements.txt`). It is
also copied into the backend image as `/srv/mcp_server.py`.

## Tools

| Tool | Calls | Scope needed |
|---|---|---|
| `sys_search_leaks(query, min_severity, limit)` | `GET /leaks/search`, `limit` capped at 50 | `read` |
| `sys_get_leak(leak_id)` | `GET /leaks/{id}` | `read` |
| `sys_get_stats()` | `GET /leaks/stats` | `read` |
| `sys_get_watchlist()` | `GET /watchlist` | `read` |
| `sys_darkweb_probe(query)` | `GET /recon/darkweb` | `recon` |
| `sys_shodan_exposure(ip)` | `GET /recon/shodan` | `recon` |
| `sys_flag_leak(leak_id, status)` | `PATCH /leaks/{id}/status` | `write` |

An HTTP error comes back to the client as `{"error": <status>, "detail": …}`
rather than an exception, so the model sees why it was refused.

## Caveats

- **Leak content reaches the MCP client's model.** Whatever model the client
  runs — local or hosted — receives the masked snippets, emails and hostnames
  the tools return. The data-residency warning on
  [AI Co-Analyst](/guide/ai-coanalyst#where-the-data-goes) applies here too,
  and here the model is chosen by the client, not by the server operator.
- **The same prompt-injection risk applies.** Tool results are leak text. With
  a `write` key, an injected instruction can change a triage status; with
  `recon`, it can queue probes. Grant `read` only unless you need more.
- **Rate limits are per client IP** and only the webhook and login have them,
  so the MCP server is effectively unthrottled.
- **The key is a bearer secret** in the client's config file. Revoke it with
  `DELETE /api-keys/{id}` if the machine is lost; revocation takes effect on
  the next request.

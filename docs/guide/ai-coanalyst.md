# AI Co-Analyst

A chat that can look at this tenant's data through a fixed set of tools, plus
investigation plans to keep track of what to do next. It runs against any
OpenAI-compatible model server — Ollama, LM Studio, vLLM — that you point
`AI_ENDPOINT` at. With `AI_ENDPOINT` unset the feature is off and the pipeline
uses rule-based severity only.

Separate from the chat, the same model server performs one-shot
[triage](/guide/pipeline#_7-ai-triage-optional) of each new leak.

## Where the data goes

Prompts, tool results and leak snippets go to `AI_ENDPOINT`. The default in
`.env.example` comments is a server on the host
(`http://host.docker.internal:1234/v1`) or the optional Compose Ollama service
(`http://ollama:11434/v1`); either way the data stays on your machines.

Point `AI_ENDPOINT` at a hosted API and it no longer does. Nothing in the code
prevents that — it is a URL, and `AI_API_KEY` exists precisely so a hosted API
can be used. The masked snippets the model sees exclude recognised passwords,
card numbers and private keys, but still contain email addresses, hostnames and
whatever else the leak held. If data residency is why you self-host, this is
the variable to watch.

## The tool allow-list

`services/agent.py`. Seven tools, every one executed by a single `dispatch`
function that takes the tenant from the authenticated caller — the model never
names a tenant, and no tool takes a tenant argument.

| Tool | Kind | Does | Audited as |
|---|---|---|---|
| `search_leaks` | read | SQL `ILIKE` over snippet and title, optional `min_severity` and `status`, up to 20 results, highest severity first | — |
| `get_leak` | read | one leak: snippet (2,000 chars), AI verdict, up to 50 emails and domains, credential count, CTI, source URL | — |
| `get_watchlist` | read | every watch item: type, value, VIP, active | — |
| `get_recent_runs` | read | up to 20 recent source runs with status and error | — |
| `flag_leak` | write | set status to `reviewing`, `escalated`, `resolved` or `false_positive`; updates the Elasticsearch document like the API does | `AI_FLAG_LEAK` |
| `dark_web_probe` | write | queue an Ahmia query on the `osint` queue | `AI_DARK_WEB_PROBE` |
| `create_task` | write | add a task to the most recent active plan, creating `Investigation YYYY-MM-DD` if there is none | — |

Every chat request is also audited as `AI_CHAT` with the first 500 characters of
the latest prompt.

What is deliberately absent: deleting anything, changing the watchlist,
reading raw evidence, exporting, managing users or keys, and any general code
or HTTP tool. The write tools are reversible — a status can be set back, a task
closed, a queued probe only adds data.

Two caveats about the list:

- **Not every tool call is audited.** The four read tools and `create_task`
  leave no audit entry; the tool calls and results are visible only in the SSE
  stream the user saw.
- **`dark_web_probe` does nothing without a broker.** In inline mode it is
  audited and then returns `{"mode": "skipped"}`.

## The loop

`POST /ai/chat`, scope `write`. Body: `{"messages": [{"role": "user" |
"assistant", "content": "…"}]}`, 1–40 messages of up to 8,000 characters. The
server keeps the last 20, prepends its system prompt, and loops:

1. Send the conversation and the tool definitions to the model
   (non-streaming, `tool_choice: auto`, temperature 0.1).
2. If the answer contains `tool_calls`, run each one through `dispatch`, append
   the result as a `tool` message, and go round again.
3. If it does not, emit the text and stop.

The loop stops after **`AI_MAX_ITERATIONS`** model turns (default 5) with the
text `Stopped after the maximum number of tool iterations. Narrow the question
and ask again.` A tool that raises is reported to the model as
`{"error": "<ExceptionName>"}` and the loop continues.

The model must support OpenAI-style tool calling. One that does not will simply
answer in text without ever looking at the data.

## SSE events

The response is `text/event-stream`, one JSON object per `data:` line, with
`Cache-Control: no-store` and `X-Accel-Buffering: no` (the bundled nginx also
disables buffering for it).

| `type` | Fields | When |
|---|---|---|
| `thinking` | `content` | the model's `<think>…</think>` block, if it produced one |
| `tool_call` | `id`, `name`, `args` | before each tool runs |
| `tool_result` | `id`, `name`, `data` | after it runs — exactly what the model receives |
| `text` | `content` | the final answer, or the iteration-limit message |
| `error` | `message` | the model server is unreachable or its breaker is open |
| `done` | — | end of the turn; always the last event, including after an `error` |

Events arrive per step, not per token: each model turn is a single
non-streaming completion. A slow model means a long pause, then a burst.

```
data: {"type": "tool_call", "id": "call_1", "name": "search_leaks", "args": {"min_severity": 80}}

data: {"type": "tool_result", "id": "call_1", "name": "search_leaks", "data": {"leaks": [ … ]}}

data: {"type": "text", "content": "Two critical leaks mention acme.example.com …"}

data: {"type": "done"}
```

Render `tool_result` beside the conversation. What the model saw is then
visible without taking its summary on trust.

## Investigation plans

Plans are lists of tasks, per tenant, shared by everyone in it.

| Endpoint | Scope |
|---|---|
| `GET /ai/plans` | `read` |
| `POST /ai/plans` — `{title, description}` | `write` |
| `PATCH /ai/plans/{id}` — `{title?, description?, status?: active \| closed}` | `write` |
| `DELETE /ai/plans/{id}` | `write` |
| `POST /ai/plans/{id}/tasks` — `{title}` | `write` |
| `PATCH /ai/plans/{id}/tasks/{task_id}` — `{status: todo \| doing \| done}` | `write` |

Each task records `created_by: human` or `ai`. Plan and task changes are not
audited, and `DELETE /ai/plans/{id}` removes the plan and its tasks outright.

## Health

`GET /ai/health` (any authenticated caller) asks the model server for
`/models` with a five-second timeout and returns `status` (`online`,
`offline`, `disabled`), the endpoint, the configured model and the models the
server lists.

::: warning A model reading breach text is reading untrusted input
Leak content comes from dump sites and paste sites and can contain instructions
aimed at the model. The mitigations are real and partial:

- the system prompt tells the model that tool results are hostile data;
- tool results are wrapped in `<tool_data>…</tool_data>` and truncated to
  12,000 characters;
- the toolkit is a fixed allow-list with no destructive operation;
- every tool runs inside the caller's tenant, so an injected instruction cannot
  reach data the user could not reach.

An injection can still make the model misreport, mark a leak `false_positive`,
or queue probes. The status change is audited and reversible; the misreport is
not detectable by the system. Treat what the Co-Analyst says as a lead to
verify, not as a finding.
:::

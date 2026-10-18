"""Collectors. Each returns candidate documents; the caller feeds them to the
pipeline and records a SourceRun for provenance.

* Ahmia      — onion search engine, queried through the Tor pool when
               ``TOR_PROXY`` is set (``via_tor`` is recorded either way).
* Onion      — same-host breadth-first crawl of an operator-supplied .onion
               seed, through Tor only; page and byte caps apply.
* Telegram   — the public web preview at t.me/s/<channel>; clearnet, no
               credentials, public channels only.
* GitHub     — code search for watchlist terms (needs GITHUB_TOKEN).
* HIBP       — breaches for a watched email (needs HIBP_API_KEY).
* Feed       — any JSON list or RSS/Atom URL.
"""

import asyncio
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from urllib.parse import quote, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ..config import settings

logger = logging.getLogger("secyourscan.recon")

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
_QUERY_RE = re.compile(r"[^\w@.\-+ \"']", re.UNICODE)


class ReconError(Exception):
    pass


@dataclass
class Candidate:
    source: str
    content: str
    url: str | None = None
    title: str | None = None
    metadata: dict = field(default_factory=dict)


def ensure_public_url(url: str) -> str:
    """Refuse URLs that resolve to loopback, private, link-local or reserved
    addresses, so a feed or bulk URL cannot make a worker fetch internal
    services (Elasticsearch, MinIO, cloud metadata). .onion hosts are allowed;
    they only resolve through Tor."""
    import ipaddress
    import socket

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ReconError("URL must be http(s) with a host")
    host = parsed.hostname
    if host.endswith(".onion"):
        return url
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ReconError("host does not resolve")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            raise ReconError("URL resolves to a non-public address")
    return url


def sanitize_query(raw: str, min_len: int = 2, max_len: int = 128) -> str:
    q = _QUERY_RE.sub(" ", (raw or "")).strip()
    q = re.sub(r"\s+", " ", q)
    if not (min_len <= len(q) <= max_len):
        raise ReconError(f"query must be {min_len}-{max_len} characters after sanitising")
    return q


def _client(*, tor: bool, timeout: float = 30.0) -> httpx.AsyncClient:
    kwargs = {
        "timeout": httpx.Timeout(timeout, connect=20.0),
        "headers": {"User-Agent": USER_AGENT},
        "follow_redirects": True,
    }
    if tor:
        if not settings.TOR_PROXY:
            raise ReconError("TOR_PROXY is not configured")
        kwargs["proxy"] = settings.TOR_PROXY
    return httpx.AsyncClient(**kwargs)


def _text_of(html: str) -> tuple[str, str | None]:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    title = soup.title.get_text(strip=True) if soup.title else None
    return soup.get_text("\n", strip=True), title


# ── Ahmia ────────────────────────────────────────────────────────────────────


@dataclass
class AhmiaResult:
    title: str
    url: str
    description: str
    page: int
    via_tor: bool
    fetched_at: str


async def ahmia_search(query: str, *, max_results: int = 100) -> dict:
    q = sanitize_query(query)
    via_tor = bool(settings.TOR_PROXY)
    results: list[AhmiaResult] = []
    seen: set[str] = set()
    async with _client(tor=via_tor) as client:
        # Ahmia's search form carries a rotating hidden field; without it the
        # search endpoint answers with an empty page.
        landing = await client.get(settings.AHMIA_URL.replace("/search/", "/"))
        hidden = {}
        form = BeautifulSoup(landing.text, "html.parser").select_one("form#searchForm, form[action*='search']")
        if form:
            for inp in form.select("input[type=hidden]"):
                if inp.get("name"):
                    hidden[inp["name"]] = inp.get("value", "")
        # Ahmia returns every hit on one page; a `page` parameter makes it
        # answer 500 (observed October 2026), so there is no pagination.
        resp = await client.get(settings.AHMIA_URL, params={"q": q, **hidden})
        if resp.status_code != 200:
            raise ReconError(f"Ahmia answered {resp.status_code}")
        items = BeautifulSoup(resp.text, "html.parser").select("li.result")
        for item in items:
            url_el = item.select_one("cite, p.onion-site")
            url = url_el.get_text(strip=True) if url_el else ""
            if not url or url in seen:
                continue
            seen.add(url)
            title_el = item.select_one("h4")
            desc_el = item.select_one("p")
            results.append(
                AhmiaResult(
                    title=title_el.get_text(strip=True) if title_el else "(no title)",
                    url=url if url.startswith("http") else f"http://{url}",
                    description=desc_el.get_text(" ", strip=True) if desc_el else "",
                    page=0,
                    via_tor=via_tor,
                    fetched_at=datetime.now(UTC).isoformat(),
                )
            )
            if len(results) >= max_results:
                break
    return {"query": q, "via_tor": via_tor, "count": len(results), "total_hits": len(items),
            "results": [asdict(r) for r in results]}


def ahmia_candidates(report: dict) -> list[Candidate]:
    return [
        Candidate(
            source="ahmia",
            content=f"{r['title']}\n{r['url']}\n{r['description']}",
            url=r["url"],
            title=r["title"],
            metadata={"query": report["query"], "via_tor": r["via_tor"], "page": r["page"], "fetched_at": r["fetched_at"]},
        )
        for r in report["results"]
    ]


# ── Onion crawler ────────────────────────────────────────────────────────────


async def crawl_onion(seed: str, *, max_pages: int | None = None) -> list[Candidate]:
    parsed = urlparse(seed if "://" in seed else f"http://{seed}")
    if not parsed.hostname or not parsed.hostname.endswith(".onion"):
        raise ReconError("the crawler only fetches .onion hosts")
    root = parsed.geturl()
    host = parsed.hostname
    limit = min(max_pages or settings.CRAWL_MAX_PAGES, 50)
    to_visit, visited, out = [root], set(), []
    async with _client(tor=True, timeout=60.0) as client:
        while to_visit and len(visited) < limit:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                async with client.stream("GET", url) as resp:
                    if resp.status_code != 200 or "html" not in resp.headers.get("content-type", "html"):
                        continue
                    body = b""
                    async for chunk in resp.aiter_bytes():
                        body += chunk
                        if len(body) >= settings.CRAWL_MAX_BYTES:
                            break
            except httpx.HTTPError as exc:
                logger.info("crawl %s failed: %s", url, exc)
                continue
            html = body.decode("utf-8", "replace")
            text, title = _text_of(html)
            if text:
                out.append(Candidate(source="onion", content=text, url=url, title=title,
                                     metadata={"seed": root, "via_tor": True, "bytes": len(body)}))
            for a in BeautifulSoup(html, "html.parser").find_all("a", href=True):
                nxt = urljoin(url, a["href"]).split("#", 1)[0]
                if urlparse(nxt).hostname == host and nxt not in visited and nxt not in to_visit:
                    to_visit.append(nxt)
            await asyncio.sleep(2.0)
    return out


# ── Telegram public preview ──────────────────────────────────────────────────

_CHANNEL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,31}$")


async def telegram_channel(channel: str, *, limit: int = 30) -> list[Candidate]:
    name = channel.strip().lstrip("@").removeprefix("https://t.me/").removeprefix("s/").strip("/")
    if not _CHANNEL_RE.match(name):
        raise ReconError("invalid Telegram channel username")
    async with _client(tor=False) as client:
        resp = await client.get(f"https://t.me/s/{name}")
    if resp.status_code != 200:
        raise ReconError(f"t.me answered {resp.status_code}")
    soup = BeautifulSoup(resp.text, "html.parser")
    out = []
    for msg in soup.select("div.tgme_widget_message")[-limit:]:
        text_el = msg.select_one("div.tgme_widget_message_text")
        if not text_el:
            continue
        post = msg.get("data-post", "")
        time_el = msg.select_one("time")
        views_el = msg.select_one("span.tgme_widget_message_views")
        out.append(
            Candidate(
                source="telegram",
                content=text_el.get_text("\n", strip=True),
                url=f"https://t.me/{post}" if post else f"https://t.me/s/{name}",
                title=f"@{name}",
                metadata={"channel": name, "posted_at": time_el.get("datetime") if time_el else None,
                          "views": views_el.get_text(strip=True) if views_el else None},
            )
        )
    return out


# ── GitHub code search ───────────────────────────────────────────────────────


async def github_code_search(term: str, *, per_page: int = 20) -> list[Candidate]:
    if not settings.GITHUB_TOKEN:
        raise ReconError("GITHUB_TOKEN is not configured")
    q = sanitize_query(term)
    headers = {
        "Authorization": f"Bearer {settings.GITHUB_TOKEN}",
        "Accept": "application/vnd.github.text-match+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with _client(tor=False) as client:
        resp = await client.get("https://api.github.com/search/code", params={"q": f'"{q}"', "per_page": per_page}, headers=headers)
    if resp.status_code != 200:
        raise ReconError(f"GitHub answered {resp.status_code}: {resp.text[:200]}")
    out = []
    for item in resp.json().get("items", []):
        fragments = "\n...\n".join(m.get("fragment", "") for m in item.get("text_matches", []))
        repo = item.get("repository", {}).get("full_name", "")
        out.append(Candidate(source="github", content=f"{repo}/{item.get('path')}\n{fragments}", url=item.get("html_url"),
                             title=f"{repo}: {item.get('path')}", metadata={"query": q, "repo": repo}))
    return out


# ── Have I Been Pwned ────────────────────────────────────────────────────────


async def hibp_breaches(email: str) -> list[Candidate]:
    if not settings.HIBP_API_KEY:
        raise ReconError("HIBP_API_KEY is not configured")
    headers = {"hibp-api-key": settings.HIBP_API_KEY, "user-agent": "SecYourScan"}
    async with _client(tor=False) as client:
        resp = await client.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
                                params={"truncateResponse": "false"}, headers=headers)
    if resp.status_code == 404:
        return []
    if resp.status_code != 200:
        raise ReconError(f"HIBP answered {resp.status_code}")
    out = []
    for b in resp.json():
        desc = BeautifulSoup(b.get("Description", ""), "html.parser").get_text(" ", strip=True)
        out.append(Candidate(
            source="hibp",
            content=f"{email} found in breach {b['Name']} ({b.get('BreachDate')})\n"
                    f"Data classes: {', '.join(b.get('DataClasses', []))}\n{desc}",
            url=f"https://haveibeenpwned.com/PwnedWebsites#{b['Name']}",
            title=f"HIBP: {b.get('Title', b['Name'])}",
            metadata={"breach": b["Name"], "breach_date": b.get("BreachDate"), "pwn_count": b.get("PwnCount"),
                      "data_classes": b.get("DataClasses", []), "email": email},
        ))
    return out


# ── Generic feed ─────────────────────────────────────────────────────────────


async def feed_items(url: str, *, limit: int = 50) -> list[Candidate]:
    ensure_public_url(url)
    tor = urlparse(url).hostname.endswith(".onion")
    async with _client(tor=tor) as client:
        # No redirects: a public URL must not bounce the worker to an internal one.
        resp = await client.get(url, follow_redirects=False)
    resp.raise_for_status()
    ctype = resp.headers.get("content-type", "")
    out = []
    if "json" in ctype:
        data = resp.json()
        items = data if isinstance(data, list) else data.get("items") or data.get("data") or []
        for it in items[:limit]:
            if isinstance(it, dict):
                content = it.get("content") or it.get("text") or it.get("body") or str(it)
                out.append(Candidate(source="feed", content=str(content), url=it.get("url") or url,
                                     title=it.get("title"), metadata={"feed": url}))
    else:
        soup = BeautifulSoup(resp.text, "xml" if "xml" in ctype else "html.parser")
        for it in soup.find_all(["item", "entry"])[:limit]:
            title = it.find("title").get_text(strip=True) if it.find("title") else None
            link = it.find("link")
            href = (link.get("href") or link.get_text(strip=True)) if link else url
            body = it.find(["description", "summary", "content"])
            text = BeautifulSoup(body.get_text(), "html.parser").get_text(" ", strip=True) if body else ""
            out.append(Candidate(source="feed", content=f"{title or ''}\n{text}", url=href, title=title, metadata={"feed": url}))
    return out

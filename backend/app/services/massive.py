"""Streaming bulk ingestion for multi-gigabyte dumps.

The file is read line by line — from object storage or an http(s) URL —
never loaded whole. A pre-filter keeps only lines that mention a watched
domain / email / keyword, or that look like a credential pair or a private
key; matching lines are batched into chunks and each chunk goes through the
normal pipeline. Runs on the ``massive`` queue with concurrency 1 so one big
job cannot starve the per-leak queue.
"""

import re
from collections.abc import Iterable, Iterator

from .babel import CRED_RE, EMAIL_RE

CHUNK_LINES = 500
MAX_CHUNKS = 2000


def build_filter(watch_values: list[str]):
    terms = [re.escape(v.lower()) for v in watch_values if v and len(v) >= 3]
    watch_re = re.compile("|".join(terms)) if terms else None

    def keep(line: str) -> bool:
        if "PRIVATE KEY-----" in line:
            return True
        low = line.lower()
        if watch_re is not None:
            return bool(watch_re.search(low))
        # No watchlist: keep anything that looks like exposed credentials.
        return bool(EMAIL_RE.search(line) and CRED_RE.match(line))

    return keep


def chunk_matching(lines: Iterable[str], keep) -> Iterator[tuple[str, dict]]:
    batch: list[str] = []
    scanned = matched = chunks = 0
    for line in lines:
        scanned += 1
        if keep(line):
            matched += 1
            batch.append(line)
            if len(batch) >= CHUNK_LINES:
                chunks += 1
                truncated = chunks >= MAX_CHUNKS
                yield "\n".join(batch), {"scanned": scanned, "matched": matched, "chunk": chunks, "truncated": truncated}
                batch = []
                if truncated:
                    return
    if batch:
        chunks += 1
        yield "\n".join(batch), {"scanned": scanned, "matched": matched, "chunk": chunks, "truncated": False}


def iter_url_lines(url: str) -> Iterator[str]:
    import httpx

    from .recon import ensure_public_url

    ensure_public_url(url)
    with httpx.stream("GET", url, timeout=httpx.Timeout(60.0), follow_redirects=False) as resp:
        resp.raise_for_status()
        for line in resp.iter_lines():
            yield line

"""Minimal async circuit breaker.

After ``fail_max`` consecutive failures the breaker opens and calls fail fast
for ``reset_timeout`` seconds, so a dead Elasticsearch does not add its
connect timeout to every leak in the queue.
"""

import time


class CircuitOpen(Exception):
    pass


class CircuitBreaker:
    def __init__(self, name: str, fail_max: int = 5, reset_timeout: float = 60.0):
        self.name = name
        self.fail_max = fail_max
        self.reset_timeout = reset_timeout
        self.failures = 0
        self.opened_at: float | None = None

    @property
    def state(self) -> str:
        if self.opened_at is None:
            return "closed"
        if time.monotonic() - self.opened_at >= self.reset_timeout:
            return "half-open"
        return "open"

    async def call(self, fn, *args, **kwargs):
        if self.state == "open":
            raise CircuitOpen(f"{self.name} circuit open")
        try:
            result = await fn(*args, **kwargs)
        except Exception:
            self.failures += 1
            if self.failures >= self.fail_max or self.state == "half-open":
                self.opened_at = time.monotonic()
            raise
        self.failures = 0
        self.opened_at = None
        return result


es_breaker = CircuitBreaker("elasticsearch")
minio_breaker = CircuitBreaker("minio")
ai_breaker = CircuitBreaker("ai", fail_max=3, reset_timeout=120.0)

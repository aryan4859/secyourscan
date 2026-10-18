"""Per-process rate limiting (in-memory). With several API replicas the
effective limit multiplies; put a shared limit at the reverse proxy for that."""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=[])

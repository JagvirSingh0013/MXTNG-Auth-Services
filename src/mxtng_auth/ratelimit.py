"""Per-IP fixed-window rate limiting for the unauthenticated surface (SECURITY_AUDIT M-1).

The per-credential lockout in `services.authenticate` answers "is one account
being brute-forced". It cannot answer "is one source trying one password against
every account", and it says nothing at all about the endpoints that have no
account attached yet — signup, password-reset requests, session introspection.
Those are the ones a stranger can reach, so those are the ones limited here.

Deliberately in-process and dependency-free. That means the ceiling is per
replica rather than per cluster, which is a weaker guarantee than a shared
counter but a far stronger one than none, and it cannot itself fail closed and
take sign-in down. A Redis-backed limiter can replace `_Window` later without
touching the call sites.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from fastapi import HTTPException, Request, status

from mxtng_auth.settings import settings


def client_ip(request: Request) -> str | None:
    """The caller's address, trusting `X-Forwarded-For` only when told to.

    Behind a load balancer `request.client.host` is the balancer, so every caller
    collapses onto one bucket and the audit trail records one address for the
    whole world. Reading the header unconditionally is worse — it is
    client-supplied, so a limiter keyed on it limits nobody. Hence the switch
    (SECURITY_AUDIT L-6): set `TRUST_PROXY_HEADERS` only where a proxy you
    control overwrites the header.
    """
    if settings.TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # Left-most entry is the original client; the proxy appends its own.
            first = forwarded.split(",")[0].strip()
            if first:
                return first
    return request.client.host if request.client else None


@dataclass
class _Window:
    started_at: float
    count: int = 0


@dataclass
class _Limiter:
    _windows: dict[tuple[str, str], _Window] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _last_sweep: float = 0.0

    def hit(self, bucket: str, key: str, *, limit: int, window_seconds: int) -> bool:
        """Count one request. Returns False when it is over the ceiling."""
        now = time.monotonic()
        with self._lock:
            self._sweep(now, window_seconds)
            slot = (bucket, key)
            window = self._windows.get(slot)
            if window is None or (now - window.started_at) >= window_seconds:
                self._windows[slot] = _Window(started_at=now, count=1)
                return True
            window.count += 1
            return window.count <= limit

    def _sweep(self, now: float, window_seconds: int) -> None:
        """Drop finished windows so an IP-keyed dict cannot grow unbounded."""
        if now - self._last_sweep < window_seconds:
            return
        self._last_sweep = now
        self._windows = {
            slot: window
            for slot, window in self._windows.items()
            if (now - window.started_at) < window_seconds
        }

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()
            self._last_sweep = 0.0


limiter = _Limiter()


def rate_limit(bucket: str, per_minute_setting: str):
    """A FastAPI dependency enforcing one named ceiling.

    `per_minute_setting` is read at request time rather than captured at import,
    so tests (and a future hot reload) can change the ceiling without rebuilding
    the routing table.
    """

    async def dependency(request: Request) -> None:
        if not settings.RATE_LIMIT_ENABLED:
            return
        limit = getattr(settings, per_minute_setting)
        key = client_ip(request) or "unknown"
        if not limiter.hit(
            bucket, key, limit=limit, window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Try again shortly.",
                headers={"Retry-After": str(settings.RATE_LIMIT_WINDOW_SECONDS)},
            )

    return dependency

"""A small in-memory sliding-window rate limiter.

It is per process. With several workers or replicas the effective limit is multiplied,
so a shared store such as Redis would be needed for strict limits. That trade-off is
documented in docs/ARCHITECTURE.md.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable


class SlidingWindowLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if limit < 1 or window_seconds <= 0:
            raise ValueError("limit must be >= 1 and window_seconds must be > 0")
        self._limit = limit
        self._window = window_seconds
        self._clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, float]:
        """Record a hit for key. Returns (allowed, seconds_until_next_slot)."""
        now = self._clock()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] >= self._window:
                hits.popleft()
            if len(hits) >= self._limit:
                return False, max(self._window - (now - hits[0]), 0.0)
            hits.append(now)
            if len(self._hits) > 10_000:
                self._evict(now)
            return True, 0.0

    def _evict(self, now: float) -> None:
        stale = [k for k, h in self._hits.items() if not h or now - h[-1] >= self._window]
        for key in stale:
            del self._hits[key]

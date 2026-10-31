"""Conservative in-process rate limiting for simple local mode."""

from collections import defaultdict, deque
from time import monotonic

from app.core.exceptions import RateLimitError


class InProcessRateLimiter:
    """Sliding-window limiter used when Redis is intentionally unavailable."""

    def __init__(self, requests_per_minute: int = 60, scans_per_hour: int = 20) -> None:
        self.requests_per_minute = requests_per_minute
        self.scans_per_hour = scans_per_hour
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._scans: dict[str, deque[float]] = defaultdict(deque)

    def check_request(self, key: str) -> None:
        """Raise when a client exceeds the request-per-minute limit."""
        now = monotonic()
        window = self._requests[key]
        while window and now - window[0] >= 60:
            window.popleft()
        if len(window) >= self.requests_per_minute:
            raise RateLimitError()
        window.append(now)

    def check_scan(self, key: str) -> None:
        """Raise when a session exceeds the scan-per-hour limit."""
        now = monotonic()
        window = self._scans[key]
        while window and now - window[0] >= 3600:
            window.popleft()
        if len(window) >= self.scans_per_hour:
            raise RateLimitError(3600)
        window.append(now)


limiter = InProcessRateLimiter()

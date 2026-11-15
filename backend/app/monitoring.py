"""Small dependency-free application metrics for local and container deployments."""

from collections import Counter
from threading import Lock
from time import monotonic


class RequestMetrics:
    def __init__(self) -> None:
        self.started_at = monotonic()
        self._lock = Lock()
        self.requests = 0
        self.errors = 0
        self.in_flight = 0
        self.status_codes: Counter[str] = Counter()
        self.routes: Counter[str] = Counter()

    def begin(self) -> None:
        with self._lock:
            self.requests += 1
            self.in_flight += 1

    def finish(self, path: str, status_code: int) -> None:
        with self._lock:
            self.in_flight = max(0, self.in_flight - 1)
            self.status_codes[str(status_code)] += 1
            self.routes[path] += 1
            if status_code >= 500:
                self.errors += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "uptime_seconds": round(monotonic() - self.started_at, 3),
                "requests_total": self.requests,
                "errors_total": self.errors,
                "in_flight": self.in_flight,
                "status_codes": dict(self.status_codes),
                "top_routes": self.routes.most_common(10),
            }


metrics = RequestMetrics()

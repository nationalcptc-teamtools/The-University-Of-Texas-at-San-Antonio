"""Injectable UTC and monotonic clock for repeatable audit tests."""

from __future__ import annotations


class FakeClock:
    def __init__(self, timestamp: str = "2026-01-01T00:00:00.000000Z", monotonic_ns: int = 0):
        self.timestamp = timestamp
        self.monotonic_ns = monotonic_ns

    def utc(self) -> str:
        return self.timestamp

    def monotonic(self) -> int:
        return self.monotonic_ns

    def advance(self, seconds: float) -> None:
        self.monotonic_ns += int(seconds * 1_000_000_000)

"""Small deterministic fault hook used by recovery tests."""

from __future__ import annotations


CHECKPOINTS = (
    "intent", "reservation", "attempt", "dispatch", "connect", "first_byte",
    "capture", "parse", "result", "audit_append", "audit_checkpoint", "signing", "completion",
)


class InjectedCrash(RuntimeError):
    pass


class FaultInjector:
    def __init__(self, checkpoint: str | None = None):
        if checkpoint is not None and checkpoint not in CHECKPOINTS:
            raise ValueError("unknown checkpoint")
        self.checkpoint = checkpoint
        self.hit = False

    def check(self, checkpoint: str) -> None:
        if checkpoint == self.checkpoint:
            self.hit = True
            raise InjectedCrash(checkpoint)

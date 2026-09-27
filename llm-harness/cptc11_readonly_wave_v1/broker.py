"""Reservation-bound broker for the four sealed read-only actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol
import hashlib
import time

from .audit import AuditError, ReadonlyAuditWriter
from .catalog import resolve_action
from .contracts import ActionResult, FrozenWaveApproval, WireCounters
from .ledger import LedgerError, ReadonlyWaveLedger
from .parsers import parse_keycloak, parse_meilisearch, parse_redis, parse_traefik
from .wire import WireError, execute_http, execute_redis


class BrokerError(RuntimeError):
    """The broker rejected or could not complete a bounded action."""


class ChannelProvider(Protocol):
    def open(self, action: object) -> object: ...


class SyntheticChannelProvider:
    """Test provider. Channels are supplied by the test process only."""

    def __init__(self, channels: dict[str, object]):
        self._channels = dict(channels)
        self.opens: list[str] = []

    def open(self, action: object) -> object:
        action_id = getattr(action, "action_id", None)
        if action_id not in self._channels or action_id in self.opens:
            raise BrokerError("synthetic channel is unavailable or already used")
        self.opens.append(action_id)
        channel = self._channels[action_id]
        return channel() if callable(channel) else channel


class FixedRelayChannelProvider:
    """A deployment-injected descriptor provider with no request endpoint fields."""

    def __init__(self, opener: Callable[[object], object]):
        if not callable(opener): raise TypeError("relay opener must be callable")
        self._opener = opener
        self._used: set[str] = set()

    def open(self, action: object) -> object:
        action_id = getattr(action, "action_id", None)
        if not isinstance(action_id, str) or action_id in self._used:
            raise BrokerError("relay channel is unavailable or already used")
        self._used.add(action_id)
        try: return self._opener(action)
        except Exception as exc: raise BrokerError("relay did not provide a channel") from exc


@dataclass(frozen=True, slots=True)
class DispatchContext:
    wave_id: str
    plan_id: str
    action_id: str
    profile_id: str
    started_monotonic_ns: int


def _zero_hash() -> str:
    return hashlib.sha256(b"").hexdigest()


def _provenance(action: object, wave_id: str, ledger: ReadonlyWaveLedger) -> dict[str, str]:
    return {"wave_id": wave_id, "plan_id": action.plan_id, "action_id": action.action_id,
            "profile_id": action.profile_id, "target_id": action.target_id,
            "catalog_sha256": action.catalog_sha256, "profile_sha256": action.profile_sha256,
            "operation_sha256": action.operation.request_sha256, "parser_id": action.parser_id,
            "policy_sha256": ledger.policy_sha256, "release_sha256": ledger.release_sha256,
            "worker_sha256": ledger.worker_sha256, "runtime_sha256": ledger.runtime_sha256}


class ReadonlyWaveBroker:
    def __init__(self, ledger: ReadonlyWaveLedger, audit: ReadonlyAuditWriter, provider: ChannelProvider):
        self.ledger, self.audit, self.provider = ledger, audit, provider
        self._active = False

    def execute(self, wave_id: str, plan_id: str, action_id: str, profile_id: str) -> ActionResult:
        if any(type(value) is not str or not value for value in (wave_id, plan_id, action_id, profile_id)):
            raise BrokerError("execution identity is invalid")
        if self._active: raise BrokerError("one action is already in flight")
        try: action = resolve_action(plan_id, action_id, profile_id)
        except Exception as exc: raise BrokerError("action is not catalog-bound") from exc
        if self.ledger.stopped(): raise BrokerError("wave is stopped")
        self._active = True
        reservation = None; dispatched = False; counters = WireCounters(0, 0, 0, 0, 0)
        try:
            self.audit.verify_or_raise()
            self.audit.reserve_output(action.action_id, action.budget.max_capture_bytes)
            # This is the first point at which a provider can be called.
            reservation = self.ledger.reserve_action(wave_id, plan_id, action_id, profile_id)
            self.ledger.record_transport_event(action_id, "intent", {"target_id": action.target_id, "profile_id": profile_id})
            self.ledger.claim_action(action_id)
            self.ledger.activate_action(action_id)
            self.ledger.record_transport_event(action_id, "dispatch", {"profile_id": profile_id})
            if self.ledger.stopped(): raise BrokerError("wave stopped before contact")
            # A provider may contact a target before it returns a channel.  Set
            # this latch before the call and conservatively stop on any error.
            with self.ledger.contact_gate():
                dispatched = True
                channel = self.provider.open(action)
            self.ledger.record_transport_event(action_id, "connect", {"count": 1})
            if action.operation.__class__.__name__ == "HttpGetOperation":
                status, body, counters = execute_http(channel, action, stopped=self.ledger.stopped, deadline_ns=time.monotonic_ns() + action.budget.timeout_ms * 1_000_000)
                self.ledger.record_transport_event(action_id, "receive", {"status_code": status, "bytes": counters.rx_bytes})
                evidence = self.audit.capture_bytes(action_id, "response", body)
                parser = {"traefik": parse_traefik, "keycloak": parse_keycloak, "meilisearch": parse_meilisearch}[action.parser_id]
                facts = parser(status, body)
            else:
                frame, counters = execute_redis(channel, action, stopped=self.ledger.stopped, deadline_ns=time.monotonic_ns() + action.budget.timeout_ms * 1_000_000)
                self.ledger.record_transport_event(action_id, "receive", {"bytes": counters.rx_bytes})
                evidence = self.audit.capture_bytes(action_id, "response", frame)
                facts = parse_redis(frame)
            result = ActionResult.for_action(action, "complete", "none", counters, evidence, facts)
            receipt = {**_provenance(action, wave_id, self.ledger), "outcome": "complete", "evidence_sha256": evidence,
                       "cleanup_status": "closed", "facts_type": type(facts).__name__}
            self.ledger.finish_action(action_id, "complete", receipt)
            self.audit.emit("result", {**receipt, "counters": {"connects": counters.connects, "requests": counters.requests, "tx_bytes": counters.tx_bytes, "rx_bytes": counters.rx_bytes, "captured_bytes": counters.captured_bytes}})
            self.audit.release_output(action_id)
            return result
        except WireError as exc:
            counters = exc.counters
            outcome = exc.outcome
            if outcome == "cancelled":
                limitation = "cancelled-before-contact"
            elif outcome == "uncertain":
                limitation = "transport-uncertain"
            else:
                limitation = "protocol-rejected"
            if dispatched:
                outcome = "uncertain"
            try:
                self.ledger.finish_action(action_id, outcome, {**_provenance(action, wave_id, self.ledger), "outcome": outcome,
                                                               "reason": str(exc), "evidence_sha256": _zero_hash(),
                                                               "cleanup_status": "uncertain", "incomplete": outcome == "uncertain"})
            except Exception as inner:
                try: self.ledger.mark_incomplete(action_id, "wire failure could not be persisted")
                except Exception as marker: raise BrokerError("wire failure could not be persisted") from marker
                raise BrokerError("wire failure could not be persisted") from inner
            self.audit.emit("result", {**_provenance(action, wave_id, self.ledger), "outcome": outcome,
                                        "evidence_sha256": _zero_hash(), "cleanup_status": "uncertain",
                                        "counters": {"connects": counters.connects,
                                        "requests": counters.requests, "tx_bytes": counters.tx_bytes,
                                        "rx_bytes": counters.rx_bytes, "captured_bytes": counters.captured_bytes}})
            if outcome == "uncertain": self.ledger.stop("target outcome is uncertain")
            self.audit.release_output(action_id)
            raise BrokerError(str(exc)) from exc
        except Exception as exc:
            if dispatched:
                self.ledger.stop("post-contact outcome is uncertain")
                try:
                    self.ledger.finish_action(action_id, "uncertain", {**_provenance(action, wave_id, self.ledger), "outcome": "uncertain",
                                                                         "reason": "post-contact failure", "evidence_sha256": _zero_hash(),
                                                                         "cleanup_status": "incomplete", "incomplete": True})
                except Exception as finish_error:
                    try: self.ledger.mark_incomplete(action_id, "post-contact outcome could not be persisted")
                    except Exception as marker_error: raise BrokerError("post-contact outcome is incomplete") from marker_error
                    raise BrokerError("post-contact outcome is incomplete") from finish_error
                self.audit.emit("result", {**_provenance(action, wave_id, self.ledger), "outcome": "uncertain",
                                            "evidence_sha256": _zero_hash(), "cleanup_status": "incomplete", "incomplete": True})
                self.audit.release_output(action_id)
            elif reservation is not None and self.ledger.action_state(action_id) in {"claimed", "active"}:
                # A stop or broker failure after reservation but before the
                # provider call has not contacted a target.  Record a normal
                # cancellation so recovery does not misclassify it.
                self.ledger.finish_action(action_id, "cancelled", {**_provenance(action, wave_id, self.ledger), "outcome": "cancelled",
                                                                    "reason": "cancelled before contact", "evidence_sha256": _zero_hash(),
                                                                    "cleanup_status": "not_started"})
                self.audit.emit("result", {**_provenance(action, wave_id, self.ledger), "outcome": "cancelled",
                                            "evidence_sha256": _zero_hash(), "cleanup_status": "not_started"})
                self.audit.release_output(action_id)
            raise exc if isinstance(exc, BrokerError) else BrokerError(str(exc)) from exc
        finally:
            self._active = False

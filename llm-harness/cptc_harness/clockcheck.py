"""Read the host clock state without changing clocks or contacting NTP.

The production PortCast service cannot use the host D-Bus from its private
root.  The root-only deployment helper therefore records a short lived host
attestation in a fixed file.  This module validates that file without
following links or accepting caller supplied paths in production.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid
from .contracts import ClockState


CLOCK_ATTESTATION_PATH = Path(
    "/run/cptc-harness-clock/portcast-live-v1.json"
)
CLOCK_ATTESTATION_VERSION = 1
CLOCK_ATTESTATION_TTL_NS = 30_000_000_000
_MAX_ATTESTATION_BYTES = 4096
_UTC_MICROSECONDS = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)
_OFFSET_UNITS = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1}


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate clock attestation field")
        value[key] = item
    return value


def _boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text(
        encoding="ascii"
    ).strip()
    parsed = uuid.UUID(value)
    if str(parsed) != value.lower():
        raise ValueError("boot identity is not canonical")
    return value.lower()


def _utc(value: object) -> str:
    if not isinstance(value, str) or _UTC_MICROSECONDS.fullmatch(value) is None:
        raise ValueError("invalid attestation UTC timestamp")
    datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    return value


def _attestation_fields(value: object) -> dict:
    """Validate and return an attestation with no caller-controlled extras."""

    if not isinstance(value, dict):
        raise ValueError("clock attestation is not an object")
    expected = {
        "version",
        "boot_id",
        "observed_utc",
        "expires_utc",
        "observed_monotonic_ns",
        "expires_monotonic_ns",
        "synchronized",
        "offset_s",
        "source",
    }
    if set(value) != expected:
        raise ValueError("clock attestation fields differ")
    if type(value["version"]) is not int or value["version"] != CLOCK_ATTESTATION_VERSION:
        raise ValueError("clock attestation version differs")
    try:
        boot = str(uuid.UUID(value["boot_id"]))
    except (ValueError, AttributeError, TypeError):
        raise ValueError("clock attestation boot identity differs") from None
    if not isinstance(value["boot_id"], str) or boot != value["boot_id"].lower():
        raise ValueError("clock attestation boot identity is not canonical")
    observed_utc = _utc(value["observed_utc"])
    expires_utc = _utc(value["expires_utc"])
    observed_dt = datetime.strptime(observed_utc, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    expires_dt = datetime.strptime(expires_utc, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    if not observed_dt < expires_dt <= observed_dt + timedelta(seconds=30):
        raise ValueError("clock attestation UTC expiry differs")
    for name in ("observed_monotonic_ns", "expires_monotonic_ns"):
        if type(value[name]) is not int or value[name] < 0:
            raise ValueError("clock attestation monotonic value differs")
    observed = value["observed_monotonic_ns"]
    expires = value["expires_monotonic_ns"]
    if not observed < expires <= observed + CLOCK_ATTESTATION_TTL_NS:
        raise ValueError("clock attestation expiry differs")
    if type(value["synchronized"]) is not bool:
        raise ValueError("clock attestation synchronization differs")
    offset = value["offset_s"]
    if offset is not None and (type(offset) is not float or not -2.0 <= offset <= 2.0):
        raise ValueError("clock attestation offset differs")
    if value["source"] != "timedatectl":
        raise ValueError("clock attestation source differs")
    return {
        "version": value["version"],
        "boot_id": boot,
        "observed_utc": observed_utc,
        "expires_utc": expires_utc,
        "observed_monotonic_ns": observed,
        "expires_monotonic_ns": expires,
        "synchronized": value["synchronized"],
        "offset_s": offset,
        "source": value["source"],
    }


def parse_clock_attestation(
    raw: bytes | str,
    *,
    boot_id: str | None = None,
    monotonic_ns: int | None = None,
    utc_now: datetime | None = None,
    minimum_remaining_s: float = 0.0,
) -> ClockState:
    """Parse a strict attestation and return a usable ``ClockState``.

    ``boot_id`` and ``monotonic_ns`` are injectable for offline tests.  The
    production call uses the current kernel boot identity and monotonic clock.
    """

    if isinstance(raw, bytes):
        if len(raw) > _MAX_ATTESTATION_BYTES:
            raise ValueError("clock attestation exceeds its collection allowance")
        raw = raw.decode("utf-8", "strict")
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > _MAX_ATTESTATION_BYTES:
        raise ValueError("clock attestation exceeds its collection allowance")
    if (
        isinstance(minimum_remaining_s, bool)
        or not isinstance(minimum_remaining_s, (int, float))
        or not math.isfinite(minimum_remaining_s)
        or not 0 <= minimum_remaining_s <= 30
    ):
        raise ValueError("invalid clock attestation remaining lifetime")
    value = json.loads(raw, object_pairs_hook=_pairs)
    fields = _attestation_fields(value)
    expected_boot = _boot_id() if boot_id is None else boot_id
    if fields["boot_id"] != expected_boot:
        raise ValueError("clock attestation boot identity differs")
    now = time.monotonic_ns() if monotonic_ns is None else monotonic_ns
    if type(now) is not int or now < fields["observed_monotonic_ns"]:
        raise ValueError("clock attestation is from a future monotonic time")
    minimum_ns = int(minimum_remaining_s * 1_000_000_000)
    if now + minimum_ns >= fields["expires_monotonic_ns"]:
        raise ValueError(
            "clock attestation has expired"
            if minimum_remaining_s == 0
            else "clock attestation cannot cover the bounded action"
        )
    current_utc = utc_now or datetime.now(timezone.utc)
    if current_utc.tzinfo is None:
        raise ValueError("clock attestation UTC clock is invalid")
    current_utc = current_utc.astimezone(timezone.utc)
    expires_utc = datetime.strptime(fields["expires_utc"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    observed_utc = datetime.strptime(fields["observed_utc"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    if current_utc < observed_utc:
        raise ValueError("clock attestation is from a future UTC time")
    if current_utc + timedelta(seconds=minimum_remaining_s) >= expires_utc:
        raise ValueError(
            "clock attestation has expired"
            if minimum_remaining_s == 0
            else "clock attestation cannot cover the bounded action"
        )
    return ClockState(fields["synchronized"], fields["offset_s"], "timedatectl-attestation")


def read_clock_attestation(
    path: Path = CLOCK_ATTESTATION_PATH,
    *,
    boot_id: str | None = None,
    monotonic_ns: int | None = None,
    utc_now: datetime | None = None,
    minimum_remaining_s: float = 0.0,
) -> ClockState:
    """Read one root-owned 0440 regular file and validate its short lifetime."""

    if path != CLOCK_ATTESTATION_PATH:
        raise ValueError("clock attestation path is fixed")
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != os.getegid()
            or info.st_nlink != 1
            or (info.st_mode & 0o777) != 0o440
            or not 1 <= info.st_size <= _MAX_ATTESTATION_BYTES
        ):
            raise ValueError("clock attestation file metadata differs")
        raw = bytearray()
        while len(raw) < info.st_size:
            chunk = os.read(descriptor, info.st_size - len(raw))
            if not chunk:
                raise ValueError("clock attestation file changed during read")
            raw.extend(chunk)
        if os.read(descriptor, 1):
            raise ValueError("clock attestation file changed during read")
        return parse_clock_attestation(
            bytes(raw),
            boot_id=boot_id,
            monotonic_ns=monotonic_ns,
            utc_now=utc_now,
            minimum_remaining_s=minimum_remaining_s,
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ValueError("clock attestation is unavailable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def current_clock() -> ClockState:
    try:
        status = subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], capture_output=True, text=True, timeout=3, env={"LC_ALL": "C"})
        details = subprocess.run(["timedatectl", "timesync-status", "--no-pager"], capture_output=True, text=True, timeout=3, env={"LC_ALL": "C"})
        if status.returncode or details.returncode or status.stdout.strip() != "yes":
            return ClockState(False, None, "timedatectl")
        found = re.search(r"Offset:\s*([+-]?[0-9.]+)\s*(ns|us|µs|ms|s)\b", details.stdout)
        if not found:
            return ClockState(True, None, "timedatectl-offset-unavailable")
        return ClockState(True, float(found[1]) * _OFFSET_UNITS[found[2]], "timedatectl")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return ClockState(False, None, "unavailable")


class ClockService:
    """One workspace clock monitor; wall-clock jumps latch unknown synchronization."""
    def __init__(self, source=current_clock, *, wall=time.time, monotonic=time.monotonic):
        self.source, self.wall, self.monotonic = source, wall, monotonic
        self.baseline = (wall(), monotonic())
        self.sample_time = -1.0
        self.state = ClockState(False, None, "not-sampled")
        self.jumped = False
        self.unsafe_latched = False

    def __call__(self):
        wall, monotonic = self.wall(), self.monotonic()
        displacement = (wall - self.baseline[0]) - (monotonic - self.baseline[1])
        if self.unsafe_latched:
            return self.state
        if self.jumped or abs(displacement) > 2:
            self.jumped = True
            return ClockState(False, displacement, "local-clock-jump")
        if self.sample_time < 0 or monotonic - self.sample_time >= 5:
            self.state, self.sample_time = self.source(), monotonic
            if self.source is attested_clock and not self.state.synchronized:
                self.unsafe_latched = True
        return self.state

    def valid_for(self, seconds: float) -> bool:
        """Require one clock state to cover a complete bounded operation."""

        state = self()
        if not state.synchronized or state.offset_s is None or abs(state.offset_s) > 2:
            return False
        if self.source is not attested_clock:
            return True
        try:
            read_clock_attestation(minimum_remaining_s=seconds)
        except (OSError, ValueError, json.JSONDecodeError):
            self.unsafe_latched = True
            self.state = ClockState(
                False, None, "timedatectl-attestation-insufficient-lifetime"
            )
            return False
        return True


def attested_clock() -> ClockState:
    """Read the fixed production attestation, returning an unsafe state on error."""

    try:
        return read_clock_attestation()
    except (OSError, ValueError, json.JSONDecodeError):
        return ClockState(False, None, "timedatectl-attestation-unavailable")

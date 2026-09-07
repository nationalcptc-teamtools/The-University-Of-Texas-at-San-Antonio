"""Read existing OS synchronization status; never change clocks or contact NTP."""
import re
import subprocess
import time
from .contracts import ClockState


def current_clock() -> ClockState:
    try:
        status = subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], capture_output=True, text=True, timeout=3, env={"LC_ALL": "C"})
        details = subprocess.run(["timedatectl", "timesync-status", "--no-pager"], capture_output=True, text=True, timeout=3, env={"LC_ALL": "C"})
        if status.returncode or details.returncode or status.stdout.strip() != "yes":
            return ClockState(False, None, "timedatectl")
        found = re.search(r"Offset:\s*([+-]?[0-9.]+)\s*(ns|us|µs|ms|s)\b", details.stdout)
        if not found:
            return ClockState(True, None, "timedatectl-offset-unavailable")
        scale = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1}
        return ClockState(True, float(found[1]) * scale[found[2]], "timedatectl")
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

    def __call__(self):
        wall, monotonic = self.wall(), self.monotonic()
        displacement = (wall - self.baseline[0]) - (monotonic - self.baseline[1])
        if self.jumped or abs(displacement) > 2:
            self.jumped = True
            return ClockState(False, displacement, "local-clock-jump")
        if self.sample_time < 0 or monotonic - self.sample_time >= 5:
            self.state, self.sample_time = self.source(), monotonic
        return self.state

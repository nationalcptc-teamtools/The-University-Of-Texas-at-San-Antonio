"""Structured pytest reports over a parent-owned pipe; no engagement inputs."""
import json
import os
import stat

_EVENT_WRITE = os.write
_EVENT_FD = None


def pytest_configure(config):
    del config
    global _EVENT_FD
    if _EVENT_FD is not None:
        return
    raw = os.environ.pop("CPTC_TEST_EVENT_FD", "")
    if not raw.isascii() or not raw.isdecimal():
        raise RuntimeError("test event descriptor is unavailable")
    descriptor = int(raw)
    if descriptor <= 2 or not stat.S_ISFIFO(os.fstat(descriptor).st_mode):
        raise RuntimeError("test event descriptor is invalid")
    _EVENT_FD = descriptor


def _send(kind, **values):
    descriptor = _EVENT_FD
    if descriptor is None:
        raise RuntimeError("test event descriptor was not initialized")
    raw = (json.dumps({"kind": kind, **values}, ensure_ascii=True, allow_nan=False) + "\n").encode()
    view = memoryview(raw)
    while view:
        count = _EVENT_WRITE(descriptor, view)
        if count <= 0: raise OSError("test event pipe unavailable")
        view = view[count:]


def pytest_collection_finish(session):
    _send("collection", nodeids=[item.nodeid for item in session.items])


def pytest_collectreport(report):
    if report.failed or report.skipped:
        _send("collection_problem", nodeid=report.nodeid, outcome=report.outcome,
              reason=str(report.longrepr))


def pytest_runtest_logreport(report):
    _send("case", nodeid=report.nodeid, phase=report.when, outcome=report.outcome,
          duration=report.duration, xfail=bool(getattr(report, "wasxfail", False)),
          subtest=hasattr(report, "context"), reason=str(report.longrepr) if report.longrepr else "",
          rendered_sections=[list(section) for section in report.sections])


def pytest_sessionfinish(session, exitstatus):
    _send("session_finished", exit_code=int(exitstatus))

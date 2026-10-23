"""One fresh Python namespace per code-mode call; stdio carries private broker RPC.

This is a process boundary for deadlines/output, not a Python security sandbox.
"""

import io
import json
import sys
import traceback
from contextlib import redirect_stderr, redirect_stdout

from fieldkit.core.agent import MAX_RESPONSE
from fieldkit.core.code_api import API


class OutputLimit(BaseException):
    pass


class APIError(Exception):
    pass


class Capture(io.StringIO):
    def __init__(self, budget):
        super().__init__()
        self.budget = budget

    def write(self, value):
        size = len(value.encode("utf-8"))
        if size > self.budget[0]:
            raise OutputLimit
        self.budget[0] -= size
        return super().write(value)


class Fieldkit:
    def __init__(self, request):
        self._request = request

    def __getattr__(self, name):
        if name not in API:
            raise AttributeError("Unknown fieldkit method; use fieldkit_search_reference")

        def call(*args, **kwargs):
            return self._request(name, args, kwargs)

        return call


def main():
    incoming, outgoing = sys.stdin, sys.stdout

    def send(value, maximum=262144):
        encoded = json.dumps(value, ensure_ascii=True, allow_nan=False)
        if len(encoded.encode()) > maximum:
            raise OutputLimit
        outgoing.write(encoded + "\n")
        outgoing.flush()

    def request(method, args, kwargs):
        send({"type": "call", "method": method, "args": args, "kwargs": kwargs})
        reply = json.loads(incoming.readline())
        if "error" in reply:
            raise APIError(reply["error"])
        return reply["value"]

    configuration = json.loads(incoming.readline())
    budget = [MAX_RESPONSE // 4]
    stdout, stderr = Capture(budget), Capture(budget)
    namespace = {"fieldkit": Fieldkit(request), "__name__": "__fieldkit__"}
    response = {}
    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exec(compile(configuration["code"], "<fieldkit>", "exec"), namespace)
        response["result"] = namespace.get("result")
    except BaseException as exc:
        # Traceback source lines and arbitrary exception messages may contain secrets.
        frames = traceback.extract_tb(exc.__traceback__)
        lines = [frame.lineno for frame in frames if frame.filename == "<fieldkit>"]
        response = {
            "error": "Python execution failed.",
            "exception": type(exc).__name__,
            "line": lines[-1] if lines else getattr(exc, "lineno", None),
        }
        if isinstance(exc, APIError):
            response["detail"] = str(exc)
        if isinstance(exc, OutputLimit):
            response["error"] = "Python output or API request exceeds its byte limit."
    response.update(type="result", stdout=stdout.getvalue(), stderr=stderr.getvalue())
    try:
        send(response, MAX_RESPONSE)
    except (TypeError, ValueError, RecursionError, OutputLimit):
        send({"type": "result", "error": "Set result to a JSON-serializable value under 64 KiB."})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

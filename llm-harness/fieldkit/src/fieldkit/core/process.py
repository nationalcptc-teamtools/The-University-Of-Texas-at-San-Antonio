"""Bounded argv-only child processes with POSIX group cleanup and partial output."""

import asyncio
import math
import os
import signal
import time
from dataclasses import dataclass, field


@dataclass
class ProcessResult:
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    returncode: int | None = None
    reason: str = "running"
    elapsed: float = 0
    bytes_seen: int = 0

    def metadata(self):
        return {k: getattr(self, k) for k in ("returncode", "reason", "elapsed", "bytes_seen")}


async def run_process(
    argv,
    *,
    timeout=10.0,
    max_output=1048576,
    on_stdout=None,
    result=None,
    env=None,
    cwd=None,
    cancel=None,
    terminate_grace=0.05,
):
    """Never use a shell. Callbacks see bounded bytes; result survives cancellation.

    Both output streams share one ceiling. A new process group includes grandchildren;
    cleanup also kills descendants whose parent exited while they kept pipes open.
    Credentials belong in private input/config files, never in argv.
    """
    if (
        not argv
        or not all(isinstance(a, str) and "\0" not in a for a in argv)
        or not math.isfinite(timeout)
        or timeout <= 0
        or max_output <= 0
        or not math.isfinite(terminate_grace)
        or not 0 <= terminate_grace <= 5
    ):
        raise ValueError("Process requires string argv and positive finite limits")
    result = result or ProcessResult()
    start = time.monotonic()
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            env=env,
            cwd=cwd,
        )
    except (OSError, ValueError):
        result.reason = "unavailable"
        result.elapsed = time.monotonic() - start
        return result
    limit = asyncio.Event()

    async def read(stream, buffer, callback=None):
        while chunk := await stream.read(65536):
            remaining = max_output - len(result.stdout) - len(result.stderr)
            result.bytes_seen += len(chunk)
            kept = chunk[: max(0, remaining)]
            buffer.extend(kept)
            if callback and kept:
                try:
                    callback(kept)
                except Exception:
                    result.reason = "output_handler_error"
                    raise
            if len(chunk) > remaining:
                limit.set()
                return

    readers = [
        asyncio.create_task(read(process.stdout, result.stdout, on_stdout)),
        asyncio.create_task(read(process.stderr, result.stderr)),
    ]
    completion = asyncio.gather(process.wait(), *readers)
    limits = asyncio.create_task(limit.wait())
    cancelled = asyncio.create_task(cancel.wait()) if cancel else None
    try:
        waiting = {completion, limits}
        if cancelled:
            waiting.add(cancelled)
        done, _ = await asyncio.wait(waiting, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        if limits in done:
            result.reason = "output_limit"
        elif cancelled and cancelled in done:
            result.reason = "cancelled"
        elif completion in done:
            await completion
            result.reason = "finished" if process.returncode == 0 else "exit_error"
        else:
            result.reason = "timeout"
    except asyncio.CancelledError:
        result.reason = "cancelled"
        raise
    finally:
        # Signal the group even if the immediate child has already exited.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
            if sig == signal.SIGTERM:
                await asyncio.sleep(terminate_grace)
        await process.wait()
        for task in [limits, cancelled, *readers]:
            if task and not task.done():
                task.cancel()
        await asyncio.gather(
            limits, *readers, *([cancelled] if cancelled else []), return_exceptions=True
        )
        if not completion.done():
            completion.cancel()
        await asyncio.gather(completion, return_exceptions=True)
        result.returncode = process.returncode
        result.elapsed = time.monotonic() - start
    return result

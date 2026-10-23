"""Small MCP surface with bounded Python workers and a shared assessment broker."""

import asyncio
import json
import math
import os
import signal
import sys

from fieldkit.core.agent import MAX_RESPONSE, FieldkitAgentError, object_schema, public_data
from fieldkit.core.code_api import invoke, search_reference

MAX_CODE = 32768
MAX_MESSAGE = 262144
MAX_CALLS = 1000


class CodeMode:
    """Each script gets a fresh process; every facade call uses the same job manager."""

    def __init__(self, agent):
        self.agent = agent
        self.tasks = set()
        self.cleanups = set()
        self.closed = False

    def tools(self):
        return [
            {
                "name": "fieldkit_execute_python",
                "description": (
                    "Execute Python in a fresh workspace process with a synchronous fieldkit API. "
                    "Methods: list_modules, module_info, run, list_jobs, job_status, cancel_job, "
                    "read_report, read_evidence, vault_records. Compose calls, loops and filters; "
                    "set result to a JSON value and/or print a concise answer. Jobs persist across "
                    "calls; Python variables do not. Use search_reference for signatures/examples. "
                    "Runs require explicit scope and module controls. Python has the server user's "
                    "filesystem/network permissions; this is not a sandbox. On errors inspect "
                    "jobs_started before retrying side effects."
                ),
                "input_schema": object_schema(
                    {
                        "code": {"type": "string", "minLength": 1, "maxLength": MAX_CODE},
                        "timeout_seconds": {
                            "type": "number",
                            "minimum": 1,
                            "maximum": 120,
                            "default": 30,
                        },
                    },
                    ["code"],
                ),
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": False,
                    "openWorldHint": True,
                },
            },
            {
                "name": "fieldkit_search_reference",
                "description": (
                    "Search local fieldkit Python API signatures/examples and registered modules. "
                    "Use a method name or keywords (e.g. run, read_report, jwt). An exact module "
                    "name (e.g. web/header-review) returns its typed options/defaults. No jobs run."
                ),
                "input_schema": object_schema(
                    {
                        "query": {"type": "string", "minLength": 1, "maxLength": 256},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
                    },
                    ["query"],
                ),
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": False,
                },
            },
        ]

    async def call(self, name, arguments):
        if self.closed:
            raise FieldkitAgentError("Server is closing")
        if name == "fieldkit_search_reference":
            return public_data(search_reference(self.agent, **arguments))
        if name == "fieldkit_execute_python":
            return await self.execute(**arguments)
        raise FieldkitAgentError("Unknown code-mode tool")

    async def execute(self, code, timeout_seconds=30):
        if not isinstance(code, str) or not code.strip() or len(code.encode()) > MAX_CODE:
            raise FieldkitAgentError("Python code must contain 1-32768 UTF-8 bytes")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 1 <= timeout_seconds <= 120
        ):
            raise FieldkitAgentError("Python timeout must be finite and 1-120 seconds")
        if self.closed:
            raise FieldkitAgentError("Server is closing")
        if len(self.tasks) >= self.agent.max_jobs:
            raise FieldkitAgentError("Active Python execution limit reached; wait for a script")
        task = asyncio.current_task()
        self.tasks.add(task)
        process = None
        pending = None
        jobs_started, calls = [], 0

        async def exchange():
            nonlocal pending, calls
            while line := await process.stdout.readline():
                message = json.loads(line)
                if message.get("type") == "result":
                    message.pop("type")
                    if len(line) > MAX_RESPONSE:
                        raise ValueError("Oversized result")
                    return message
                if message.get("type") != "call" or calls >= MAX_CALLS:
                    raise ValueError("Invalid or excessive API calls")
                calls += 1
                try:
                    # Record job IDs before waiting, including on script timeout/cancellation.
                    pending = asyncio.create_task(
                        invoke(
                            self.agent,
                            message.get("method"),
                            message.get("args"),
                            message.get("kwargs"),
                            jobs_started.append,
                        )
                    )
                    value = await asyncio.shield(pending)
                    reply = {"value": public_data(value)}
                except FieldkitAgentError as exc:
                    reply = {"error": str(exc)}
                except Exception:
                    reply = {"error": "API request failed; check the reference and job status."}
                finally:
                    if pending and pending.done():
                        pending = None
                encoded = json.dumps(reply, ensure_ascii=True, allow_nan=False).encode() + b"\n"
                if len(encoded) > MAX_MESSAGE:
                    encoded = b'{"error":"API response exceeds its byte limit."}\n'
                process.stdin.write(encoded)
                await process.stdin.drain()
            raise ValueError("Python worker exited without a result")

        try:
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "fieldkit.code_worker",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                cwd=str(self.agent.workspace),
                start_new_session=True,
                limit=MAX_MESSAGE,
            )
            process.stdin.write(json.dumps({"code": code}, ensure_ascii=True).encode() + b"\n")
            async with asyncio.timeout(timeout_seconds):
                await process.stdin.drain()
                response = await exchange()
        except TimeoutError:
            response = {"error": "Python execution timed out.", "timed_out": True}
        except asyncio.CancelledError:
            raise
        except Exception:
            response = {"error": "Python worker failed; check code and API reference."}
        finally:

            async def cleanup():
                try:
                    if pending:
                        # Stop the broker wait; assessment jobs persist independently.
                        pending.cancel()
                        await asyncio.gather(pending, return_exceptions=True)
                    if process:
                        for sig in (signal.SIGTERM, signal.SIGKILL):
                            try:
                                os.killpg(process.pid, sig)
                            except ProcessLookupError:
                                pass
                            if sig == signal.SIGTERM:
                                await asyncio.sleep(0.05)
                        process.stdin.close()
                        # Drain corrupt frames so paused pipe readers can reach EOF.
                        await process.communicate()
                finally:
                    self.tasks.discard(task)

            # SDK cancellation scopes can cancel every await in this handler. A
            # separate shielded task finishes cleanup even after the handler exits.
            cleanup_task = asyncio.create_task(cleanup())
            self.cleanups.add(cleanup_task)
            cleanup_task.add_done_callback(self.cleanups.discard)
            await asyncio.shield(cleanup_task)
        response.update(api_calls=calls, jobs_started=jobs_started)
        response = public_data(response)
        if len(json.dumps(response, ensure_ascii=True).encode()) > MAX_RESPONSE:
            return {
                "error": "Python response exceeds 64 KiB; return a smaller selection.",
                "api_calls": calls,
                "jobs_started": jobs_started,
            }
        return response

    async def close(self):
        self.closed = True
        tasks = list(self.tasks - {asyncio.current_task()})
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.gather(*self.cleanups, return_exceptions=True)

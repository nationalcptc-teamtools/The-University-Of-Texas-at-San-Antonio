"""Private argv-only MCP worker. Configuration contents never enter command arguments."""

import json
import signal
import sys
from pathlib import Path

from rich.console import Console

from fieldkit.core.agent import read_json
from fieldkit.core.assessment import write_private
from fieldkit.registry import modules


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        return 2
    configuration = read_json(Path(args[0]), 262144)
    module = modules().get(configuration.get("module"))
    if module is None:
        return 2
    result = {"module": module.name}

    def terminate(_sig, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, terminate)
    try:
        code = module.run(configuration["settings"], Console(file=sys.stderr, markup=False))
    except (ValueError, OSError) as exc:
        code = 2
        print(f"Input error: {exc}", file=sys.stderr)
        result.update(error="input_error", detail="Check required inputs and module option limits")
    except KeyboardInterrupt:
        code = 130
        result.update(error="interrupted")
    except Exception:
        code = 1
        result.update(error="module_error", detail="Module failed; inspect saved report/coverage")
    result["exit_code"] = code
    write_private(Path(configuration["result_file"]), json.dumps(result))
    return code


if __name__ == "__main__":
    raise SystemExit(main())

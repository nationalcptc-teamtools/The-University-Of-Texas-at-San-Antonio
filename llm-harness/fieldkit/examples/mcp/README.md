# MCP client examples

First install Fieldkit's optional server dependency:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[mcp]'
.venv/bin/fieldkit mcp --help
```

The extra installs Python MCP SDK version `>=2.3,<3`, matching Fieldkit's server API.

These examples are configuration templates. They are not active agent configuration.

## Copilot and portable clients

Copy [portable.mcp.json](portable.mcp.json) to `.mcp.json` at your workspace root,
or merge its `fieldkit` entry into an existing configuration. Replace both
`/absolute/path/to/cptc-private-toolkit/llm-harness/fieldkit` values with your actual
Fieldkit directory path. The
`mcpServers` format also works with compatible local stdio clients; consult your
client's configuration reference before choosing its configuration location.

VS Code currently recommends this portable workspace format for new servers.
Copilot also documents a user configuration at `~/.copilot/mcp-config.json` when
`COPILOT_HOME` is unset. These locations and formats are described in the
[official VS Code MCP setup documentation](https://code.visualstudio.com/docs/agent-customization/mcp-servers).

## VS Code workspace format

The alternative [vscode.mcp.json](vscode.mcp.json) uses VS Code's `servers` object
and `${workspaceFolder}` substitution. Copy it to `.vscode/mcp.json`, or merge the
entry into that file. It assumes Fieldkit is installed in the workspace's `.venv`.
Open `llm-harness/fieldkit` as the VS Code workspace so `${workspaceFolder}` resolves
to this project's directory. For a different workspace or environment, change both
`command` and the `--workspace` argument to their absolute Fieldkit paths.

Start Fieldkit from the client's MCP server list, then enable its tools in your
agent's tool picker. Follow the client's workspace/server trust prompts. VS Code's
MCP logs are available through **MCP: List Servers → Fieldkit → Show Output**.

An initial agent instruction can be:

> Use Fieldkit to list the available modules and inspect evidence/ingest's options.
> Import examples/workbench/traffic.har into artifacts/demo.sqlite, inspect the
> saved job report, then list the public request records. Do not contact the example
> hosts; this is a local evidence review.

The server advertises `fieldkit_execute_python` and `fieldkit_search_reference`.
Inside Python, call `fieldkit.run(module, options)` with uppercase option names and
Python lists/booleans, except server-controlled `OUTPUT`. Search exact module names
for their typed options, or call `fieldkit.module_info(module)`. Set the MCP output location in the
server's startup arguments. The same explicit target origins, profile files, limits, and confirmation
flags apply to network requests. Keep populated profiles and credentials in private
files rather than adding them to shared MCP configuration. See [the MCP guide](../../docs/mcp.md)
for tools, job polling, result pagination, and private evidence handling.

For example, pass this `code` to `fieldkit_execute_python`:

```python
job = fieldkit.run("evidence/ingest", {
    "INPUT": ["examples/workbench/traffic.har"],
    "FORMAT": "har",
    "DATABASE": "artifacts/demo.sqlite",
}, wait_seconds=5)
result = {"job_id": job["job_id"], "report": fieldkit.read_report(job["job_id"])}
```

Existing launch configurations work with code mode. Refresh the client's tool list
after updating; old `fieldkit_run_*` and utility calls must move into Python. Each
script has fresh variables; jobs persist. Python runs with the server user's file
and network permissions, so process separation is not a sandbox.

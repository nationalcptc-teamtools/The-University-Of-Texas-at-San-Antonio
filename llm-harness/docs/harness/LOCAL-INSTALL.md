# Local AI-harness installation

From the repository root, run `cd llm-harness` before the commands below.

Use Python 3.11 or newer on the reviewed Linux operator host. Install into a
private virtual environment. Do not run preparation downloads from an
engagement workflow or provide client data to package services.

```sh
python3 -m venv .tools/operator-venv
.tools/operator-venv/bin/python -m pip install --no-index \
  --find-links /approved/local/wheelhouse -e '.[test,mcp,browser,benchmark]'
python3 scripts/bootstrap-harness.py --install-age
.tools/operator-venv/bin/python -m cptc_harness doctor
.tools/operator-venv/bin/python -m cptc_harness modules
```

`bootstrap-harness.py` downloads only the pinned official age archive into the
ignored `.tools/` directory and verifies its SHA256. It does not change PATH or
global packages. `bootstrap-native-tools.py` is a separate preparation-only ZAP
installer for the reviewed offline passive profile.

The installed `cptc` program is the operator control plane for the AI harness.
It is not a general assessment shell and must not be offered to the model. Use
it to create the restricted workspace, freeze workflow state, apply approvals,
stop work, inspect coverage, verify logs, and create a reviewed encrypted local
export.

Run the complete fail-closed suite with:

```sh
.tools/operator-venv/bin/python scripts/test-harness.py
```

The runner uses synthetic inputs, writes complete UTC audit and stream files,
rejects skips and xfails, and returns failure for incomplete or interrupted
runs. Build artifacts with a fixed epoch only after the suite passes:

```sh
.tools/operator-venv/bin/python scripts/package-harness.py \
  --epoch 1788839662 --output .tools/package-review
```

Packaging produces an allowlisted wheel and normalized source archive. It does
not produce or include a human toolkit.

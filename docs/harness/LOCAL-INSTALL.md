# Local operator installation

The private wheel provides `cptc-tools` for human operation and `cptc` for the
complete local harness CLI. The human kit also includes collectors and cards
usable without installing Python dependencies; start at `human/README.md`.

On the tested host, install the wheel in a dedicated environment. The command
below uses the already reviewed local dependency installation and performs no
package download. On another host, prepare the exact dependencies from the lock
file before assessment and repeat the applicable tests and pin review.

```sh
python3 -m venv --system-site-packages .tools/operator-venv
.tools/operator-venv/bin/python -m pip install --no-index --no-deps \
  dist/cptc_guarded_harness-0.1.0a3-py3-none-any.whl
.tools/operator-venv/bin/cptc-tools --help
.tools/operator-venv/bin/cptc-tools modules
.tools/operator-venv/bin/cptc-tools preflight --age "$PWD/.tools/age"
```

Use the environment's absolute entry-point paths from another directory. An
operator may add links in `~/.local/bin` when those names are unused. Do not
replace unrelated launchers. Pass an explicit reviewed `--age` path to `init`;
the package does not bundle age, Nmap, Nuclei, Java or ZAP binaries.

Native paths and hashes in the release catalog describe this tested host.
Moving the source checkout, upgrading a tool or rebuilding the Nmap shim can
invalidate those pins. A package installation does not admit new binaries.
`scripts/review-release-pins.py` checks the source deployment offline. The CLI's
catalog distinguishes file availability from verified profile dependencies.

Use the synthetic examples for the first encrypted import/report/audit check.
Create all engagement workspaces outside Git on approved protected storage.
Do not reuse synthetic policies or test keys for client work. No AI provider is
needed for human imports, native observations, coverage or reports.

The archives and `dist/BUILD-RECEIPT.json` record evaluation evidence. Review
`ACCEPTANCE.md` and `RELEASE-STATUS.json` for unsupported profiles and outstanding
live gates. No artifact is uploaded by installation or export.

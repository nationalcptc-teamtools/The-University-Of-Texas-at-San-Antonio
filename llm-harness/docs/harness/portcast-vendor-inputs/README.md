# PortCast vendor inputs

This folder defines how to reproduce the sealed PortCast runtime. The builder
does not read installed Python packages, `/usr/lib`, `pacman`, or `ldconfig`.
It does not download files. It reads exact archives from an operator-controlled
directory and checks all output bytes against the two reviewed runtime locks.

## Prepare the input directory

Read `manifest-v1.json`. Place each `archives[].path` and detached signature at
the same relative path under one directory outside the repository. Use the
exact archive bytes. The manifest records the file size, SHA-256, package name,
package version, architecture, origin, signature SHA-256, and reviewed signer
fingerprint.

The `age` archive is the upstream `age-v1.3.2-linux-amd64.tar.gz` release
asset. Its SHA-256 and Sigsum proof are pinned. The folder retains the exact
publisher keys and verification instructions. The package archives retain
their detached signatures. The release review verified the package signatures
and the Sigsum proof without network access before it admitted the manifest.

For the reviewed Linux amd64 asset, use the retained proof and key with the
pinned `sigsum-verify` build:

```bash
sigsum-verify \
  -k docs/harness/portcast-vendor-inputs/files/age/sigsum-key.pub \
  -P sigsum-generic-2025-1 \
  /absolute/path/to/portcast-vendor-inputs/age-v1.3.2-linux-amd64.tar.gz.proof \
  < /absolute/path/to/portcast-vendor-inputs/age-v1.3.2-linux-amd64.tar.gz
```

The manifest pins the verifier module, version, and binary hash. Check those
values before you treat an exit status of zero as the reviewed result.

Do not place credentials or client data in this directory.

## Check the current runtime

Use Python 3.14 or later. The standard library must support Zstandard tar
archives. Install exactly `patchelf 0.19.1` for the recorded SQLite RUNPATH
removal.

```bash
python3 scripts/portcast_vendor_inputs.py \
  --inputs /absolute/path/to/portcast-vendor-inputs
```

The command checks the following items:

- every archive, signature, attestation, package identity, version, and
  architecture;
- all 1,028 runtime files and their inventory owners;
- every package-to-runtime member mapping;
- the one reviewed SQLite transformation;
- the generated corresponding-source notice;
- ELF membership, dependencies, RPATH state, and native Python closure;
- current bytes and normalized file modes.

Success returns JSON with `"reproduced": true`. It also states that signature
review evidence is bound and that signatures were not reverified in this run.
The default command does not write to the repository. The command always uses
the checked-in manifest. It has no option to admit a replacement manifest.

## Materialize a review tree

Write a new tree outside the repository when you must compare two builds:

```bash
python3 scripts/portcast_vendor_inputs.py \
  --inputs /absolute/path/to/portcast-vendor-inputs \
  --skip-current \
  --output /var/tmp/portcast-runtime-review
```

The output directory must not exist. The builder removes a partial new output
if writing fails. It will not replace the checked-in runtime. A release owner
must review a different runtime, update the inventory and locks, regenerate the
bootstrap and release seals, and run the full package gate.

## Source and notice files

The `files/` directory contains small reviewed notice inputs. Each file has an
exact origin, revision, method, and SHA-256 in `manifest-v1.json`. Reviewed
notice summaries are distinct from verbatim license files.

`CORRESPONDING-SOURCE.json` is generated. It binds the current source bundles,
metadata sidecars, package versions, and selected permissive-license records.
It is not accepted as a staged input.

## Limits

Each archive record binds exact package members. A unique matching byte string
at another member path is rejected. Selected permissive-license records bind
the package version, inventory license, immutable source revision, and retained
license evidence. Each archive member is limited to 64 MiB and is read in
chunks of at most 1 MiB. The complete expanded archive limit remains 1 GiB.

This manifest reproduces one reviewed runtime only. It does not approve a new
package version or different bytes. The builder binds earlier signature and
attestation review receipts. It does not perform cryptographic signature
verification itself. A new release review must verify those proofs before it
updates the manifest.

## Seal the reviewed release

Run the sealer without options after the source, runtime, inventory, and tests
are frozen:

```bash
python3 scripts/seal-portcast-release.py
```

A stale seal returns exit status 1 and prints the exact plan SHA-256. Review
that plan. Then admit only that digest:

```bash
python3 scripts/seal-portcast-release.py \
  --write \
  --expected-plan-sha256 PLAN_SHA256
```

The sealer refuses changed legacy workers, the profile worker, or the static
launcher. Their exact approvals are pinned in reviewed code and cannot be
replaced through command-line data. The V2 plan digest binds the complete
current manifest, generated bootstrap, and proposed manifest. Review a changed
approval pin separately from an ordinary runtime refresh. The sealer locks and
opens the resources directory by descriptor, writes the bootstrap first, and
writes the release manifest second. An interruption therefore leaves a
fail-closed stale release. Run the read-only command again to verify the final
seal. Run the write operation as the trusted checkout owner; the sealer rejects
a different effective user instead of changing file ownership.

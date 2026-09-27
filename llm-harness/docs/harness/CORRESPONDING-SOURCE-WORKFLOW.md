# Corresponding-source retention workflow

The private release uses third-party inventory schema version 2. Every
distributed copyleft component has a prepared corresponding-source descriptor,
and the source-fulfillment and full-compliance gates must both pass before a
release artifact is produced.

For each distributed copyleft component, retain one canonical outer `tar.gz`
archive under `vendor/corresponding-source/` and one hashed JSON sidecar under
`docs/harness/corresponding-source/`. The outer archive has normalized gzip and
tar timestamps, owners, groups, permissions, ordering, and padding. It contains
only unique relative regular files. Links, device nodes, directories, Git LFS
pointers, duplicate paths, oversized members, and excessive expansion are
rejected.

The inventory descriptor has exactly these fields:

```json
{
  "method": "exact_archive",
  "archive": "vendor/corresponding-source/component-exact-source.tar.gz",
  "sha256": "...",
  "bytes": 0,
  "archive_format": "tar.gz",
  "metadata_path": "docs/harness/corresponding-source/component.json",
  "metadata_sha256": "..."
}
```

The outer `tar.gz` is a container for retained evidence. Its packaging and
upstream source members are separately normalized `tar.xz` archives. Each
source reference records `archive_format: "tar.xz"`, the exact member hash,
member count, unpacked-byte total, and an immutable commit URL. The component's
`approved_source_origins` has separate canonical HTTPS base URL lists for
`packaging` and `upstream`. A reference must be one approved base followed by
`/commit/<full-commit>` or `/-/commit/<full-commit>`; queries, fragments,
credentials, tags, and branch names are rejected.

Each upstream reference also records how the packaging recipe selected that
commit. A commit selector must equal the resolved revision. A tag selector must
name the recipe tag and retain the raw annotated Git tag object under
`evidence/revision-bindings/`. The gate checks the tag name, target commit,
object identity, and evidence SHA-256. It also requires the exact `source =`
record in the retained `.SRCINFO`. It does not execute `PKGBUILD`. These checks
bind the retained recipe selector to the retained source revision. The gate
does not validate a tag signature.

The hashed sidecar uses schema version 1 and records the inventory component,
distribution package, packaging source, upstream sources, patches, build
evidence, reviewer, review time, and every outer member's path, byte count, and
SHA-256. `distribution_package.component_version` must exactly equal the
inventory component's `version`. The distribution package's own `version` may
include a package release suffix; for example, Paramiko component version
`5.0.0` is bound to Arch package version `5.0.0-1`.

All four retained bundles use `reproducibility_status: "metadata-only"`. This
means no reproduction was performed. `source_date_epoch`, `build_log_member`,
and `build_log_sha256` are therefore `null`. The package archive and
`.BUILDINFO` are hashed evidence for the selected distribution package. The
packaging recipe, upstream source, and any patch record source correspondence.
The sidecar separately records hashes for copied runtime files. The gate does
not inspect package members and does not prove that a copied runtime file came
from the retained package. Detached package signatures and `gpgv` verification
status are not retained in the bundle. The Bubblewrap tag object contains a
signature, but the release gate does not verify it. The Paramiko tag object is
unsigned.

The PortCast vendor-input builder performs a separate derivation check. It
opens the exact package archives listed in
[`portcast-vendor-inputs/manifest-v1.json`](portcast-vendor-inputs/manifest-v1.json),
checks the hashes of their retained detached signatures and reviewed signer
records, maps exact package members to the runtime locks, and verifies the final
ELF closure. It also binds the upstream Sigsum proof for the age release. The
release review performs the cryptographic signature and proof checks. The
builder does not depend on the host keyring or Sigsum verifier. Its result says
that reviewed proof evidence is bound; it does not say that the current builder
run repeated cryptographic verification. This check does not claim that the
distribution packages were rebuilt from source.

The retained archive and sidecar are source-distribution inputs only. Both must
appear in the source allowlist and must be absent from the runtime allowlist and
runtime wheel. The runtime contains its owned license and provenance notices,
while every copied runtime file remains owned by exactly one inventory
component.

The source-fulfillment check runs before a runtime tree is built. It validates
the v2 inventory, retained outer archives, nested `tar.xz` sources, hashes,
metadata, package evidence, immutable origins, patches, and source-only
allowlist placement. Final compliance recomputes that fulfillment, rejects a
forged supplied result, then requires both sealed runtime roots, their exact
locks, every installed-file hash, and complete physical vendor ownership.

After any prepared source change, run the focused license and packaging tests,
then run `scripts/package-harness.py` with the intended fixed epoch. The command
writes `BUILD-RECEIPT-<version>.json` only after full compliance passes. Its
`third_party_compliance` section binds the canonical inventory hash to every
retained archive and metadata sidecar. Keep the receipt with the private release
review record.

The exact package hashes, packaging revisions, upstream revisions, and retained
patch are recorded in
[`CORRESPONDING-SOURCE-PROVENANCE.md`](CORRESPONDING-SOURCE-PROVENANCE.md).

# Third-party source and license policy

This private project may invoke or install external tools, but external source
must not enter the repository merely because it is publicly readable.

Before copying code, templates, rules, documentation, generated assets, or
other material from an online repository, the contributor must record:

- The upstream project, exact URL, immutable revision or release, and copied
  files.
- The applicable license and the upstream file that establishes it.
- Copyright, attribution, NOTICE, source-offer, modification-marking, patent,
  trademark, and redistribution requirements that apply to the intended use.
- Whether the material is invoked, downloaded for local use, included in a
  release artifact, modified, or redistributed.
- The reviewer and validation date.

Unknown or missing licensing blocks an import. A repository description,
package index classifier, search result, or lack of a copyright notice is not
permission to copy. License compatibility is assessed for the actual release
artifact, not only for local development.

Permissively licensed material retains its required copyright and license
notices. Copyleft, source-available, noncommercial, custom, dual-license, and
proprietary terms require an explicit distribution review before admission.
Nmap is treated as a system dependency because its NPSL places material limits
on redistribution and embedding. External binaries and their dependency trees
remain outside the wheel and source archive unless the inventory records every
required notice and the package allowlist is reviewed.

The canonical PortCast service is one configured exception. Its private source
release contains a sealed Python 3.14 SSH runtime and a private RootDirectory
runtime. The runtimes include exact copies of Paramiko, cryptography, cffi,
pycparser, bcrypt, PyNaCl, Invoke, fluidity-sm, Lexicon, PyYAML, CPython 3.14.7,
bubblewrap 0.12.0, age 1.3.2, the static Go launcher runtime, and the exact
native closure recorded by the two mandatory runtime locks. The inventory owns
every copied file, including each retained license and provenance notice.
Missing, additional, changed, or unowned runtime files block release.

The machine-readable inventory is schema version 2. It records a prepared
corresponding-source descriptor for each distributed copyleft component:
glibc, libgcc, bubblewrap, and Paramiko. Each descriptor binds a canonical outer
`tar.gz`, its JSON sidecar, normalized packaging and upstream `tar.xz` members,
the distribution package and `.BUILDINFO`, exact installed-file hashes,
and any retained patch. The exact package hashes and immutable revisions are
listed in
[`CORRESPONDING-SOURCE-PROVENANCE.md`](CORRESPONDING-SOURCE-PROVENANCE.md).

These records use `metadata-only` build evidence. They establish the recorded
source and package provenance used by the compliance gate. They do not assert
that a build was reproduced. The gate hashes the retained package and copied
runtime files independently. It does not inspect package members or prove a
package-to-runtime derivation. Detached package signatures and `gpgv`
verification status are not retained in the bundles. A future reproduced result
must also retain a fixed source epoch and a hashed build log.

The separate
[`portcast-vendor-inputs/manifest-v1.json`](portcast-vendor-inputs/manifest-v1.json)
binds the complete PortCast runtime to 28 signed distribution packages and the
upstream age release archive. Its offline builder inspects package members and
reproduces all 1,028 locked files. It records the SQLite RUNPATH transformation
and the reviewed notice inputs. This proves the package-to-runtime derivation
for the current sealed runtime. It does not change the `metadata-only` status
of the four corresponding-source builds.

The package command enforces two stages. Source fulfillment validates the v2
inventory, source-only allowlist placement, canonical archives, nested source
archives, sidecars, immutable origins, and evidence hashes before a runtime
tree is required. Full compliance recomputes that result and additionally
validates both runtime locks, physical vendor ownership, component ownership of
all license-like notices, and copied-file hashes before an artifact is created.

Metasploit is an operator-installed system dependency. Its top-level framework
license does not establish one license for every bundled component. Do not copy
or redistribute the framework tree. Pin and review the selected module,
runtime closure, notices, and component licenses before a profile can move
beyond design-only tests.

The machine-readable record is
[`THIRD-PARTY-INVENTORY.json`](THIRD-PARTY-INVENTORY.json). Any future copied
source entry must name each repository path in `copied_files`; an empty list
means no upstream source is incorporated. CI or local release review must fail
when an admitted copied file lacks a reviewed inventory entry.

This inventory records third-party use and obligations. It does not assign a
license to the private CPTC project itself.

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
remain outside the wheel and source archive unless the inventory is
updated with every required notice and the package allowlist is reviewed.

Metasploit is also an operator-installed system dependency. Its top-level
framework license does not establish one license for every bundled component.
Do not copy or redistribute the framework tree. Pin and review the selected
module, runtime closure, notices, and component licenses before a profile can
move beyond design-only tests.

The machine-readable record is
[`THIRD-PARTY-INVENTORY.json`](THIRD-PARTY-INVENTORY.json). Any future copied
source entry must name each repository path in `copied_files`; an empty list
means no upstream source is incorporated. CI or local release review must fail
when an admitted copied file lacks a reviewed inventory entry.

This inventory records third-party use and obligations. It does not assign a
license to the private CPTC project itself.

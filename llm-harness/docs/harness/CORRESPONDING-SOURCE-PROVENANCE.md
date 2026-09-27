# Corresponding-source provenance

This record identifies the public provenance retained for the four distributed
copyleft components. Package SHA-256 values refer to the retained distribution
package inside the corresponding-source bundle. Detached signatures and
signature-verification receipts are not part of the bundle evidence.

| Component | Package SHA-256 | Packaging revision | Recipe selector | Resolved upstream revision | Retained binding or patch |
| --- | --- | --- | --- | --- | --- |
| glibc | `5db2283f5b46b6114d06b4bc71fcf8ede5f1a04fcccb4d307048fcdc4e501d93` | `7a444d10dd6b85918b891bf386f03c68c548de3b` | commit `16be1518495f1fa05481b0182c4e4c24927c62df` | `16be1518495f1fa05481b0182c4e4c24927c62df` | None |
| libgcc | `7367dad49fc3229bde804816d412ab77306d433b1f92e4126b8b3ba3502c67d6` | `13b07516f792b0b11ef818300f9d7a9341f31b5b` | commit `d564253eb6c859e266d3cae18e82fb4db9a88316` | `d564253eb6c859e266d3cae18e82fb4db9a88316` | None |
| bubblewrap | `b68821c30191db0bb3ce573db2498a84a49de27b5ec61030199ea3556fd8f62d` | `de3ede1da96bc18e87fe7f6f54ff08b38f814bcf` | tag `v0.12.0` | `2a76602a8c71f36c1527cf9fc3417d9149822e0c` | tag object `014a04330642e5c870418beb621532cb896e0002`; patch SHA-256 `5b784413c959d5d6ad3a7e1616612693dc3849e2e7879f2b0e3b78a654021381` |
| Paramiko | `3008c1a71bc9999b78a9e57826f9ad58e760956f8ff5373e5ccbe5dd8b35f8d9` | `df13e046df634d0b97d4721cd5da7fa1faa9a57a` | tag `5.0.0` | `710cc5c02e2ded370d8d24e261e2baa8317a20fa` | tag object `db7f22ee140be84e2eed6f2fb69305149a22f0a6` |

The retained sidecars bind these revisions to canonical commit URLs and to the
normalized `tar.xz` members. The outer canonical `tar.gz` archives and sidecar
hashes remain authoritative for the exact retained bytes. The package archive,
`.BUILDINFO`, and copied runtime hashes are checked separately. The current gate
does not inspect package members and does not claim build reproduction.

The retained glibc and GCC trees were compared with the official Sourceware
Forge archives for their resolved commits. The full path, type, size, content,
and symlink-target comparisons had zero differences. The Bubblewrap tag object
contains a signature, but the release gate checks only its Git object identity,
tag name, and target commit. The Paramiko tag object is unsigned.

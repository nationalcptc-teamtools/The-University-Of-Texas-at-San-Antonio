# Corresponding-source builder

This folder contains an offline builder for public corresponding-source bundles.
It creates source-only output. It does not fetch a repository. It does not read
credentials. It does not include client data or runtime files.

## Use

Run the builder from the repository root:

```text
python3 scripts/corresponding_source/builder.py \
  --spec /path/to/example-spec.json \
  --input-dir /path/to/source-input \
  --repo-root /path/to/repository \
  --archive /path/to/out/example.tar.gz \
  --metadata /path/to/out/example.json \
  --receipt /path/to/out/example.receipt.json
```

The command is offline. The builder refuses an existing output path. It writes
all three files with new-file atomic publication. A failure removes only its
own temporary files.

## Input layout

The input directory contains only files named by the spec. Use these prefixes:

| Prefix | Use |
| --- | --- |
| `evidence/` | Package and build information files |
| `evidence/revision-bindings/` | Raw annotated Git tag objects for tag selectors |
| `sources/` | Packaging and upstream `tar` or `tar.xz` files |
| `patches/` | Reviewed patch files |

The repository root is used only for the `component.copied_files` hash check.
Copied files are not added to the source archive.

Each input must be a regular, non-symlink file. Paths are relative POSIX paths.
They cannot contain `.` or `..`, backslashes, or NUL characters. The builder
checks every declared hash before it writes output.

## Spec data model

The spec is strict JSON. Duplicate keys, missing keys, and unknown keys fail.
The top-level keys are:

```json
{
  "schema_version": 1,
  "component": { "...": "..." },
  "distribution_package": { "...": "..." },
  "packaging_source": { "...": "..." },
  "upstream_sources": [{ "...": "..." }],
  "patches": [{ "...": "..." }],
  "build": { "...": "..." },
  "verified_at": "2026-09-10T00:00:00Z",
  "verified_by": "reviewer"
}
```

`component` uses the current inventory identity fields:

```text
name, version, use, source, license, license_source,
copied_files, distributed, obligations, distribution_basis,
approved_source_origins
```

`distributed` must be true and `distribution_basis` must be
`copyleft-source-required`. `copied_files` is a sorted list of repository
paths. The two origin lists are sorted canonical HTTPS bases.

`distribution_package` contains:

```text
name, version, component_version, architecture, package_filename,
package_sha256, installed_file_hashes, archive_member,
build_info_member, build_info_sha256,
input: { package, build_info }
```

`component_version` must equal the component version. `version` is the exact
distribution package release and can include a package release suffix. The
package name is independent from the component display name. `architecture`
must be a lowercase reviewed identifier such as `any`, `x86_64`, or
`x86_64_v3`.
`installed_file_hashes` must contain one SHA-256 value for every copied file.

Each source reference contains:

```text
origin, revision, archive_member, input_path, sha256,
archive_format, member_count, unpacked_bytes, revision_binding
```

`archive_format` is exactly `tar` or `tar.xz`. A revision is a 40 or 64
character lowercase hexadecimal value. The origin must be the exact
`/commit/<revision>` or `/-/commit/<revision>` URL under its approved base.

Every upstream source requires `revision_binding`. A commit binding contains:

```text
recipe_selector_type: "commit", recipe_selector, resolved_revision,
recipe_manifest_path: ".SRCINFO", recipe_source,
binding_evidence_member: null, binding_evidence_input: null,
binding_evidence_sha256: null, tag_object_revision: null
```

The selector and resolved revision must equal the source reference revision. A
tag binding contains the same keys with `recipe_selector_type: "tag"`. It also
names a raw annotated Git tag-object input and outer member, its SHA-256, and
its 40- or 64-character Git object identity. `recipe_source` is the exact
`source =` value from the retained `.SRCINFO`. The builder checks that record,
the approved normalized source origin, tag header, tag name, target commit,
object identity, and evidence hash. It removes the local input path from the
sidecar. It does not execute `PKGBUILD` or validate a tag signature.

Patches contain `archive_member`, `input_path`, and `sha256`. The build object
uses the current fields:

```text
recipe_member, source_info_member, toolchain, flags,
source_date_epoch, build_log_member, build_log_sha256,
reproducibility_status
```

For `metadata-only`, the three build-log fields are `null`. For `reproduced`,
the build log is read from `input_dir/build_log_member`, and the epoch and hash
are required.

## Validation and output

Nested archives use streaming `tar` or `tar.xz` readers. The builder checks:

- sorted, unique, safe member names;
- zero mtime, uid, gid, and root owner names;
- canonical directory, file, and safe symlink modes;
- no hardlinks, devices, FIFOs, unsupported members, or LFS pointers;
- expected member count and regular-file byte count;
- two zero end blocks, zero padding, and a 10,240-byte tar boundary;
- compressed input hashes and xz end-of-stream state.

The outer archive is sorted regular members in deterministic `tar.gz` form.
Its gzip header uses mtime zero, XFL two, and OS 255. The compressed bundle must
be smaller than 95 MiB. Sidecar JSON and the descriptor receipt use sorted
compact JSON with a final newline.

The sidecar follows the current corresponding-source metadata shape. It holds
source references, package evidence, patches, build data, member hashes, and
review metadata. It does not contain input-only paths. The receipt contains
the archive and sidecar hashes, sizes, member counts, component, and
`verified: true`.

Keep the generated files in approved public source staging. Review the archive
contents and license obligations before any publication. This tool does not
publish or upload files.

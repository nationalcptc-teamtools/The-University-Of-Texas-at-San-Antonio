# CPTC11 image audit: Phase A

Phase A is a deterministic, test-only validation layer. It freezes the nine
public CPTC11 Team 01 image identities, validates synthetic HTTP range
responses, writes bounded chunks through restricted capabilities, validates an
explicit interrupted-run resume, parses supplied `qemu-img` JSON, and builds
read-only command specifications. It performs no network request and executes
no subprocess.

The package is under `testing/cptc11_benchmark/`. It is outside
`cptc_harness`, is not a runtime dependency, and is not included in the runtime
wheel. The source allowlist includes the Phase A modules, tests, and this
document only. Packaging tests reject them from the runtime allowlist. Images,
expected benchmark catalogs, credentials, client data, and raw command output
are not part of the package or its fixtures.

## Frozen source allowlist

The only allowed source origin is `http://cptc.rit.edu:80`. Each URL uses the
exact path `/cptc11/vms/<filename>`. Query strings, fragments, redirects,
alternate schemes, ports, hosts, paths, filenames, and advertised lengths are
rejected.

| Asset | Role | Filename | Advertised bytes |
|---|---|---|---:|
| APT-CREWCOMMS | production | `cptc11-export-team-01-APT-CREWCOMMS.qcow2` | 11071979520 |
| APT-DC-01 | production | `cptc11-export-team-01-APT-DC-01.qcow2` | 8404598784 |
| APT-ENVCTRL | production | `cptc11-export-team-01-APT-ENVCTRL.qcow2` | 10225451008 |
| APT-GPS | production | `cptc11-export-team-01-APT-GPS.qcow2` | 10668670976 |
| Penny | production | `cptc11-export-team-01-Penny.qcow2` | 22096838656 |
| PortCast | production | `cptc11-export-team-01-PortCast.qcow2` | 12454264832 |
| ShorePass | production | `cptc11-export-team-01-ShorePass.qcow2` | 9387704320 |
| kali01 | support | `cptc11-export-team-01-kali01.qcow2` | 15381561344 |
| win01 | support | `cptc11-export-team-01-win01.qcow2` | 12307070976 |

`kali01` and `win01` are support images. They appear only when the operator uses
the explicit support flag. They never enter the production benchmark scope by
default.

The source uses unsigned public HTTP. An ETag and Last-Modified value bind
range requests to the initially observed source identity, but neither value is
proof of authenticity. Phase A records this limit in every acquisition
receipt. A signed organizer checksum is still unavailable.

## Implemented CLI

List production sources as canonical JSON:

```text
python -m testing.cptc11_benchmark list-sources
```

Include the two support images explicitly:

```text
python -m testing.cptc11_benchmark list-sources --include-support
```

Validate an existing state root:

```text
python -m testing.cptc11_benchmark doctor --state-root /absolute/restricted/path
```

The state root must be an existing directory owned by the current user, have
mode `0700`, contain no symlink path component, and be outside every Git
repository. Phase A `doctor` checks only these state-root properties. Encrypted
filesystem, free-space, tool, NBD, mount, holder, and stale-lock checks belong
to a later live-capable phase.

These planned commands are intentionally unavailable in Phase A and exit with
status 2:

```text
python -m testing.cptc11_benchmark acquire
python -m testing.cptc11_benchmark inventory
python -m testing.cptc11_benchmark extract
python -m testing.cptc11_benchmark verify
python -m testing.cptc11_benchmark export-derivative
python -m testing.cptc11_benchmark cleanup
```

No Phase A option performs a request to the CPTC host or public source.

## Validation contracts

Range requests are pure data objects. They set `Range`,
`Accept-Encoding: identity`, and `If-Match` when the source has an ETag. They
disable redirects and specify an exact streaming receive cap of at most 4 MiB.
The future transport must stop reading when this cap is reached. Headers use an
ordered sequence of name-value pairs so duplicate fields remain visible and are
rejected. A convenience mapping is not an accepted response-header input.
Response validation requires status 206, the exact final URL, exact
`Content-Range`, exact Content-Length and body size, proof that the streaming
cap was enforced, unchanged ETag and Last-Modified values, identity content
encoding, and at most 64 KiB of response headers.

Opening the state root creates a capability. The root must be owner-only mode
`0700`, outside Git, and free of symlink path components. A run capability is
created relative to that open root. All child operations use directory file
descriptors, fixed names, no-follow opens, and matching `lstat` and `fstat`
identities. The initial image creation uses `O_EXCL`. New directory entries are
followed by a directory `fsync`.

The sparse writer accepts only a run capability and writes the fixed
`image.qcow2.partial` file. It creates an owner-only `0600` regular file. It
does not write all-zero chunks, so those ranges remain holes. It rejects
preplaced files, path replacement, symlinks, permission drift, out-of-range
writes, empty chunks, and chunks larger than 4 MiB. A state-root flock allows
one active image operation. Before future acquisition, the caller must reserve:

```text
advertised content length
+ QCOW metadata reserve
+ encrypted output reserve
+ 2 GiB safety reserve
```

Resume is explicit. The old receipt must be `interrupted`; source URL, listing
hash, advertised length, ETag, and Last-Modified must match; the staging file
must remain owner-only; every recorded chunk hash must verify; and no NBD
attachment may exist. A completed, running, failed, changed, or uncertain run
does not resume.

QCOW validation is staged. The info parser first rejects malformed JSON,
non-QCOW2 format, backing files, encryption, snapshots, virtual sizes above
512 GiB, allocation values inconsistent with the logical size, and invalid
cluster sizes. Only that parser can issue the sealed typed token required to
build a map command. Both the command builder and map parser recheck the token's
format, size, cluster, backing, encryption, snapshot, and hash invariants. The
map parser then requires depth-zero extents with real boolean
fields and complete contiguous coverage from byte zero through the virtual
size. It rejects gaps, overlaps, out-of-bounds extents, and extents larger than
4 GiB. This ordering prevents a map command specification for an image whose
info is unsafe.

Every command requires a trusted typed tool pin for exactly
`/usr/bin/qemu-img`. The pin contains the package name, package version, package
origin, owner, mode, and SHA-256 hash. The accepted SHA-256 value is also fixed
in the source and tested against the checked-in dependency inventory; a caller
cannot select a new trusted digest. The builder rechecks the regular file,
owner, mode, hash, and open-file identity. Commands explicitly set `-f qcow2`,
`LC_ALL=C`, a fixed timeout and output bound, closed inherited descriptors,
and `shell=False`. Each specification requires network-disabled execution.
Phase A has no process runner and never passes a specification to `subprocess`.

## Receipts and limits

`ImageSource`, `AcquisitionReceipt`, and `QcowReceipt` produce sorted,
compact, newline-terminated canonical JSON. Receipt timestamps are supplied by
the caller; canonicalization does not add a clock value or a local path.
Acquisition receipts include each range hash and observed source identity,
downloaded and sparse byte counts, the tool version, and audit-chain references.
A running receipt has no finish time, failure reason, or final hash. Interrupted
and failed receipts require a finish time and reason and forbid a final hash. A
complete receipt requires a finish time, complete contiguous coverage, and a
final hash, and it forbids a failure reason. Finish time cannot precede start
time.

Audit-chain references must be a tuple. Each reference is a nonempty bounded
identifier. Malformed field containers and scalar types fail with a typed
staging rejection; they do not escape as Python type or attribute errors.

The local dependency inventory records QEMU image tools 11.1.1-1, libnbd
1.24.3-1.1, pytsk3 20250801-2, and Sleuth Kit 4.15.0-1.1 with the locally
reported origin and license plus verified executable or extension hashes. They
are image-audit test or prototype tools. They are not runtime dependencies and
are not distributed in the wheel.

Phase A cannot acquire or authenticate an image, inspect an image file, attach
NBD, inventory partitions or filesystems, extract configuration, detect
secrets, generate findings, or update the external expected catalog. It cannot
establish dynamic runtime, web, AD, service, or exploit conditions. All tests
use synthetic bytes and metadata.

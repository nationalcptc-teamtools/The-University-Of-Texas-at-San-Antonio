# Package 2 implementation

Package 2 adds the durable execution boundary for the CPTC11 read-only wave.

The ledger reserves a catalog action before a channel can open. It records
the action state and spends allowances across restarts. An interruption marks
an action as uncertain. Recovery stops the wave. The broker has no retry path.

The audit writer stores metadata in an append-only hash chain. Response bytes
are accepted only through a bounded descriptor or test capture method. The
encryptor runs before response bytes are written. Readable files contain
timestamps, identifiers, sizes, and hashes.

The service accepts identifier-only JSON requests over local Unix sequence
packets. It checks the peer identity and rejects unknown fields. A stop writes
an independent sentinel before it attempts central reconciliation.

Every action belongs to a frozen `FrozenWaveApproval`. The SHA-256 `wave_id`
binds the plan, catalog, policy, release, action order, operation hashes, and
budgets. The ledger stores this identity and rejects legacy actions until a
human migration review is recorded.

Policy, release, worker, and runtime pins are mandatory explicit lowercase
SHA-256 values. Empty or invalid pins fail before the ledger opens. The worker
and runtime pins are never substituted from another pin. Legacy ledgers receive additive
columns and remain stopped when old actions have no frozen wave. Existing
history remains intact.

Terminal receipts use a closed provenance shape. They include the wave,
catalog, operation, profile, parser, policy, release, worker, and runtime
digests; action identity; evidence digest; outcome; and cleanup status.
Missing or conflicting values are rejected.

The audit lock uses an exclusive Unix `flock`. Each mutation reloads state
under the lock. A capture must use a typed age record in production. Tests
use a separate synthetic record and must set `test_only=True`. Descriptor
capture accepts only a read-only memfd with all write, grow, shrink, and seal
seals. Ordinary files are rejected.

Each encrypted artifact has one immutable entry in `evidence-manifest.json`.
The entry binds the action, stream, record format, recipient fingerprint,
plaintext digest and length, and ciphertext digest and length. Verification
rejects a deleted, modified, extra, or unsafe artifact. The seal includes the
inventory digest.

The broker marks provider opening as contact attempted before it calls the
provider. An open error therefore stops the wave and records an uncertain
outcome. If the database cannot record that outcome, it writes a durable
incomplete marker.

The production channel owner and age recipient remain deployment decisions.
This package is source-only. It has no live transport and no target opener.

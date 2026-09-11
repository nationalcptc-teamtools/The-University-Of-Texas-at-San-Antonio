# Package 2 security model

The package uses four boundaries.

1. The catalog owns endpoints, request bytes, parsers, and limits.
2. The ledger owns durable reservations, terminal states, and the stop latch.
3. The broker owns the only provider call and sends only catalog actions.
4. The audit writer owns readable metadata and encrypted response capture.

The service accepts local peers with an enrolled Unix user ID or primary group
ID. It requires an explicit socket owner, group, and mode. It does not accept
credentials or arbitrary file paths. Request and response bytes use one
canonical JSON encoding over `SOCK_SEQPACKET`. A stop sentinel works when the
SQLite writer is locked or unavailable. Recovery treats a possibly contacted
target as uncertain and blocks later work.

Audit mutations use an exclusive file lock. The writer reloads its durable
state under the lock before each operation. The central chain stores metadata
only. Capture uses a typed age record in production. It accepts a sealed
read-only memfd and rejects ordinary files.

The source package has no benchmark data, no target opener, no subprocess
runner, and no import from the main harness. The synthetic provider and test
encryptor are for tests only. They do not provide isolation for a deployment.

Readable logs are not a safe disclosure channel for client content. Keep the
encrypted evidence directory protected. Select an approved age recipient and
review the provider boundary before deployment.

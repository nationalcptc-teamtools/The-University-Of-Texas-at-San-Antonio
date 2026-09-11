# Service operations

Package 2 does not install a service. It provides the source-only service
authority for a later reviewed deployment.

The service accepts these methods:

* `info` reports readiness.
* `plan` reports the fixed action count.
* `inspect` reports the stop state.
* `execute` accepts `wave_id`, `plan_id`, `action_id`, and `profile_id` only.
* `stop` writes the local stop sentinel.

Responses use a closed schema for each method. `info` returns `status` and
`service`; `plan` returns `status` and `actions`; `inspect` returns `status`
and `stopped`; `stop` returns `status`; and `execute` returns `status`,
`wave_id`, `action_id`, `profile_id`, `target_id`, and `evidence_sha256`.
Rejected requests return only `status` and `reason`.

The deployment must provide a verified release, a separate state root, a
separate trust anchor, and a fixed channel provider. Requests do not supply a
host, port, method, path, headers, body, proxy, command, or runtime option.

The service uses `SOCK_SEQPACKET`. The client and server use the same
canonical JSON bytes. The client checks the complete send and receives one
bounded packet. The server checks the peer UID or primary GID, socket owner,
group, and mode. A deployment must set explicit owner and group values.

On a stop or uncertain result, stop the service and inspect the ledger and
audit chain. Do not retry an action after an uncertain result. Resolve the
transport ownership and the host identity before any live admission.

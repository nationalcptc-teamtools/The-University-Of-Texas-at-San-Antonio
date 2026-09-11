# CPTC11 image audit: Phase A

This test-only package freezes the public CPTC11 Team 01 source identities and
implements pure validation for bounded HTTP ranges, capability-based local
staging, explicit resume, and supplied QCOW metadata. It performs no network
requests, does not execute QEMU, and is excluded from the `cptc_harness`
runtime wheel.

The future runner must enforce the response byte cap while it streams data. It
must also start every image process with network access disabled. Phase A only
records these requirements in typed request and command objects. It contains no
runner that can use them.

See `docs/harness/CPTC11-IMAGE-AUDIT.md` for the operator interface and current
limits.

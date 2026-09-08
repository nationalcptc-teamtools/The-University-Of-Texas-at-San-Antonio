# Native and human tooling work package

Approved continuation: bring up the available lab tooling and prepare an
independent human toolkit. This extends `APPROVED-PLAN.md`; it does not relax
disclosure, scope, auditing, availability or manual-only requirements.

1. Main freezes the trusted process-local `ExecutionContext.network` capability,
   native catalog API and passive-capture envelope. Public action JSON cannot
   supply this capability. Existing engagement schemas remain version 1.
2. Luna implements the operator CLI, standalone local collectors, profiles,
   runbooks, manual cards and synthetic examples in `human/`, `human.py` and its
   focused tests. No model/provider setup is required to use these tools.
3. Terra implements the native Nmap one-connect profile in `nmap_bridge.py`,
   `native/` and focused tests. A networkless scanner requests an exact parent
   TCP probe through AF_UNIX. The parent closes the target socket and returns
   only its result; the scanner never receives a target-connected descriptor.
4. Main implements offline Nuclei and ZAP response analysis, pins, static
   registry integration, encrypted audit integration and release packaging.
   Existing active scanner IDs stay visibly unsupported.
5. Luna independently reviews the changes. Fixes require focused regression
   tests before full suite, package inspection and local installation.
6. Run live profile acceptance only after target access, assignment, identity,
   recovery and policy gates are established. Management-plane access alone
   does not satisfy guest-profile acceptance. Preserve existing services and
   lifecycle records; do not introduce disruptive acceptance tests.

Build agents receive only source and synthetic fixtures. They do not receive
raw lab evidence, credentials or target inventories. At most two delegated
write agents own disjoint files. Requested models and available identity
evidence are recorded in `BUILD-AGENTS.json`. No remote push is authorized.

Required validation: existing regressions; native open/refused TCP results;
pin-before-probe denial; repeated/mismatched probe denial; stop/deadline/output
failures; passive vulnerable/hardened/malformed captures; zero scanner egress;
zero model calls for human lifecycle; full encrypted audit capture; schema and
secret-reflection checks; independent review; wheel/source/human-kit inspection.

The source release distinguishes offline fixture evidence, native executable
fixture evidence, unavailable tools and live profile acceptance. A discovered
binary or a successful build does not admit a capability.

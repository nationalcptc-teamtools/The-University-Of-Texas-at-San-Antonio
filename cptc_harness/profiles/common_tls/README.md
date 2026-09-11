# Common TLS receipt parser

`parse_tls_receipt(receipt)` accepts one complete `trusted_tls_receipt_v1`
mapping from the parent-owned collection boundary. The mapping must contain
exactly the closed receipt fields. The parser binds the receipt profile ID to
its one SNI in `catalog.json`. It accepts only TLS 1.2 or TLS 1.3, a
catalog-listed cipher name, a lowercase SHA-256 certificate digest, bounded
canonical DNS SANs, and canonical UTC certificate and capture times.

The output contains only the negotiated TLS version and cipher name,
certificate SHA-256, exact SAN-match Boolean, validity interval, and the
valid-at-capture Boolean. Wildcards do not satisfy exact SAN matching. SAN
names, SNI, certificate subject text, other certificate extensions, and any
unknown receipt field are not returned.

Malformed, partial, incomplete, oversized, unpinned, or schema-expanded
receipts raise `TlsReceiptError` and produce no partial facts. Structural
validation does not make an arbitrary caller-supplied mapping trustworthy; the
integration layer must supply the receipt from its trusted, sealed worker
contract.

This module performs zero network operations. It never creates a socket, TLS
context, or TLS handshake and it performs no HTTP request. The parent worker
owns collection, wire accounting, encrypted raw evidence, and trust binding.

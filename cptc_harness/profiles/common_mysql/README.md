# Common MySQL greeting parser

`parse_mysql_greeting(packet)` accepts immutable `bytes` containing exactly one
complete MySQL HandshakeV10 server packet. The packet, including its four-byte
header, must be no larger than the bound in `catalog.json`. The parser validates
the declared payload length, sequence zero, protocol 10, the closed version
grammar, all required NUL terminators, reserved bytes, known capability bits,
and capability-dependent auth field lengths.

The output contains only `protocol_version`, `product_family`, normalized
`version`, and a tuple of closed capability names. The parser discards the
connection identifier, both auth-plugin-data parts, status flags, character
set, auth plugin name, and raw greeting. A greeting is version evidence only;
it does not establish vulnerability or patch applicability.

Malformed, partial, truncated, oversized, multi-packet, or unsupported
greetings raise `MysqlGreetingError` and produce no partial facts. The parser
does not recover data from a second packet.

This module performs zero network operations. It never creates a socket and
never sends a MySQL client handshake or any other client bytes. A parent worker
must enforce the one-connect, zero-application-transmit collection contract and
must keep the raw greeting outside model-visible output.

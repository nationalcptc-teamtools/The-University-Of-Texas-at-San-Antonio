from __future__ import annotations

from pathlib import Path

import pytest

from cptc_harness.scanner_protocols import (
    ExtraRequest,
    HTTPGetRootValidator,
    MalformedMessage,
    NMAP_NBSTAT_WILDCARD_REQUEST,
    NMAP_SMB2_NEGOTIATE_REQUEST,
    SMBMessageKind,
    SMBRelayValidator,
    classify_smb_tcp_frame,
)


def _http_request(host="127.0.0.1", port=80):
    return f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode()


def _smb2_frame(command=0):
    frame = bytearray(NMAP_SMB2_NEGOTIATE_REQUEST)
    frame[16:18] = command.to_bytes(2, "little")
    return bytes(frame)


def _nbstat():
    return NMAP_NBSTAT_WILDCARD_REQUEST


def _smb_response(body_size=65, *, status=0, dialect=0x0202):
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[8:12] = status.to_bytes(4, "little")
    header[16:20] = (1).to_bytes(4, "little")
    body = bytearray(body_size)
    if body_size >= 2:
        body[:2] = (65 if status == 0 else 9).to_bytes(2, "little")
    if status == 0 and body_size >= 6:
        body[4:6] = dialect.to_bytes(2, "little")
    payload = bytes(header + body)
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def test_http_validator_accepts_only_one_fragmented_fixed_get_root():
    request = _http_request()
    validator = HTTPGetRootValidator("127.0.0.1", 80)
    assert validator.feed(request[:7]) == request[:7]
    assert validator.feed(request[7:]) == request[7:]
    validator.finish()
    assert validator.request_count == 1
    with pytest.raises(ExtraRequest):
        validator.feed(request)


def test_http_validator_rejects_method_path_host_and_extra_headers():
    for request in (
        _http_request().replace(b"GET /", b"POST /", 1),
        _http_request().replace(b"GET / ", b"GET /?x=1 ", 1),
        _http_request().replace(b"127.0.0.1:80", b"127.0.0.2:80", 1),
        _http_request().replace(b"Connection: close", b"X-Test: 1\r\nConnection: close", 1),
    ):
        with pytest.raises(MalformedMessage):
            HTTPGetRootValidator("127.0.0.1", 80).feed(request)


def test_http_validator_rejects_incomplete_message_and_non_loopback_endpoint():
    validator = HTTPGetRootValidator("127.0.0.1", 80)
    validator.feed(b"GET / HTTP/1.1\r\n")
    with pytest.raises(MalformedMessage, match="incomplete"):
        validator.finish()
    for host in ("localhost", "192.0.2.10", "::1"):
        with pytest.raises(ValueError, match="loopback IPv4"):
            HTTPGetRootValidator(host, 80)


def test_smb_validator_buffers_tcp_fragments_and_classifies_negotiate():
    frame = _smb2_frame()
    validator = SMBRelayValidator("127.0.0.1", 445)
    assert validator.feed_tcp(frame[:3]) == frame[:3]
    assert validator.feed_tcp(frame[3:17]) == frame[3:17]
    assert validator.feed_tcp(frame[17:]) == frame[17:]
    validator.finish_tcp()
    assert validator.protocol_requests == 1
    assert classify_smb_tcp_frame(frame) is SMBMessageKind.SMB2_NEGOTIATE


def test_pinned_nmap_requests_have_stable_lengths_and_hashes():
    import hashlib
    assert len(NMAP_SMB2_NEGOTIATE_REQUEST) == 184
    assert hashlib.sha256(NMAP_SMB2_NEGOTIATE_REQUEST).hexdigest() == (
        "df36284962f3ca182e53bbbc6328f247e86de0e42eee51db97d553242ae9f78d"
    )
    assert len(NMAP_NBSTAT_WILDCARD_REQUEST) == 50
    assert hashlib.sha256(NMAP_NBSTAT_WILDCARD_REQUEST).hexdigest() == (
        "ceea3d122f7ab944367b4a65f6c6699471a3aee6163c145e0e804a1b10b80a64"
    )
    fixture_root = Path(__file__).parent / "fixtures" / "scanner" / "relay"
    assert (fixture_root / "nmap-7.991-smb2-negotiate.bin").read_bytes() == NMAP_SMB2_NEGOTIATE_REQUEST
    assert (fixture_root / "nmap-7.991-nbstat-wildcard.bin").read_bytes() == NMAP_NBSTAT_WILDCARD_REQUEST


@pytest.mark.parametrize("command", [1, 3, 5, 8, 9, 11, 14, 16, 17])
def test_smb_validator_rejects_session_tree_transaction_and_file_commands(command):
    with pytest.raises(MalformedMessage, match="forbidden"):
        SMBRelayValidator("127.0.0.1", 445).feed_tcp(_smb2_frame(command))


def test_smb_validator_rejects_malformed_and_extra_tcp_frames():
    validator = SMBRelayValidator("127.0.0.1", 445)
    with pytest.raises(MalformedMessage):
        validator.feed_tcp(b"\x00\x00\x00\x04bad")
    validator.feed_tcp(_smb2_frame())
    with pytest.raises(ExtraRequest):
        validator.feed_tcp(_smb2_frame())


@pytest.mark.parametrize("offset", [10, 14, 18, 20, 28, 44, 68, 70, 72, 100, 112, 130, 150, 183])
def test_smb_validator_rejects_any_mutated_fixed_negotiate_field(offset):
    frame = bytearray(NMAP_SMB2_NEGOTIATE_REQUEST)
    frame[offset] ^= 1
    with pytest.raises(MalformedMessage):
        SMBRelayValidator("127.0.0.1", 445).feed_tcp(bytes(frame))


def test_smb_validator_rejects_smb1_bad_lengths_and_incomplete_fragments():
    smb1 = bytearray(_smb2_frame()); smb1[4:8] = b"\xffSMB"
    for frame in (bytes(smb1), b"\x00\x00\x00\x40" + b"\xfeSMB" + b"\x00" * 20):
        with pytest.raises(MalformedMessage):
            SMBRelayValidator("127.0.0.1", 445).feed_tcp(frame)
    validator = SMBRelayValidator("127.0.0.1", 445)
    validator.feed_tcp(_smb2_frame()[:20])
    with pytest.raises(MalformedMessage, match="incomplete"):
        validator.finish_tcp()


def test_netbios_validator_preserves_datagram_boundary_and_rejects_second_datagram():
    validator = SMBRelayValidator("127.0.0.1", 445)
    datagram = _nbstat()
    assert validator.feed_udp(datagram) == datagram
    with pytest.raises(ExtraRequest):
        validator.feed_udp(datagram)
    assert validator.udp_datagrams == 1


def test_netbios_validator_rejects_malformed_question_without_counting_it():
    validator = SMBRelayValidator("127.0.0.1", 445)
    with pytest.raises(MalformedMessage):
        validator.feed_udp(_nbstat()[:-1])
    assert validator.udp_datagrams == 0


def test_netbios_validator_rejects_trailing_data():
    with pytest.raises(MalformedMessage):
        SMBRelayValidator("127.0.0.1", 445).feed_udp(_nbstat() + b"\x00")


@pytest.mark.parametrize("offset", [0, 1, 2, 5, 12, 13, 14, 44, 45, 46, 49])
def test_netbios_validator_rejects_noncanonical_transaction_and_wildcard_name(offset):
    datagram = bytearray(NMAP_NBSTAT_WILDCARD_REQUEST)
    datagram[offset] ^= 1
    with pytest.raises(MalformedMessage):
        SMBRelayValidator("127.0.0.1", 445).feed_udp(bytes(datagram))


def test_smb_response_requires_a_complete_negotiate_structure():
    validator = SMBRelayValidator("127.0.0.1", 445)
    validator.feed_tcp(NMAP_SMB2_NEGOTIATE_REQUEST)
    assert validator.accept_tcp_response(_smb_response()) == _smb_response()

    for response in (
        _smb_response(2),
        _smb_response(64),
        _smb_response(65, dialect=0x9999),
        _smb_response(8, status=0xC0000001),
    ):
        candidate = SMBRelayValidator("127.0.0.1", 445)
        candidate.feed_tcp(NMAP_SMB2_NEGOTIATE_REQUEST)
        with pytest.raises(MalformedMessage):
            candidate.accept_tcp_response(response)

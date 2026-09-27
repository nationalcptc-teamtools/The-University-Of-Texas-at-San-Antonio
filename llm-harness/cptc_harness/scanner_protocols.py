"""Closed protocol validators for pinned scanner request fixtures."""
from __future__ import annotations

from enum import Enum
import ipaddress
import struct


class ProtocolError(ValueError):
    """A worker message is outside the reviewed protocol."""


class MalformedMessage(ProtocolError):
    """A message is malformed or requests a forbidden operation."""


class ExtraRequest(ProtocolError):
    """A worker requested more protocol operations than admitted."""


def _loopback_ipv4(host: str, port: int, expected_port: int) -> tuple[str, int]:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("validator requires one numeric loopback IPv4 endpoint") from None
    if address.version != 4 or not address.is_loopback:
        raise ValueError("validator requires one numeric loopback IPv4 endpoint")
    if type(port) is not int or port != expected_port:
        raise ValueError("validator port is outside the reviewed profile")
    return str(address), port


def _nmap_smb2_negotiate_request() -> bytes:
    """Build the fixed Nmap 7.991 SMB2 negotiate message admitted by the catalog."""
    header = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB", 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        b"1234567890123456",
    )
    dialects = (0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
    data = struct.pack(
        "<HHHHI16s", 36, len(dialects), 1, 0, 0,
        b"1234567890123456",
    )
    total = len(header) + len(data) + 2 * len(dialects)
    padding = b"\0" * ((8 - total % 8) % 8)
    total += len(padding)
    data += struct.pack("<IHH", total + 8, 2, 0)
    data += struct.pack("<" + "H" * len(dialects), *dialects) + padding

    encryption = struct.pack("<HHH", 2, 2, 1)
    data += struct.pack("<HHI", 2, len(encryption), 0) + encryption
    total = len(header) + len(data)
    data += b"\0" * ((8 - total % 8) % 8)

    # Nmap 7.991 prefixes this context payload with its encryption payload.
    preauth = encryption + struct.pack(
        "<HHH16s16s", 1, 0x20, 1,
        (0).to_bytes(16, "little"), (1).to_bytes(16, "little"),
    )
    data += struct.pack("<HHI", 1, len(preauth), 0) + preauth
    body = header + data
    return b"\0" + len(body).to_bytes(3, "big") + body


# These request bytes match the pinned, installed Nmap 7.991 package. The
# source package identities and licenses are recorded in the scanner catalog.
NMAP_SMB2_NEGOTIATE_REQUEST = _nmap_smb2_negotiate_request()
NMAP_NBSTAT_WILDCARD_REQUEST = (
    b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x20CK" + b"A" * 30 + b"\x00\x00\x21\x00\x01"
)


class HTTPGetRootValidator:
    """Accept exactly one fixed HTTP/1.1 GET request and no extra headers."""

    def __init__(self, host: str, port: int) -> None:
        self.host, self.port = _loopback_ipv4(host, port, 80)
        self._expected = (
            f"GET / HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        self._buffer = bytearray()
        self._complete = False
        self.request_count = 0

    @property
    def protocol_requests(self) -> int:
        return self.request_count

    def feed(self, data: bytes) -> bytes:
        if type(data) is not bytes or not data:
            raise MalformedMessage("HTTP request chunk is malformed")
        if self._complete:
            raise ExtraRequest("extra HTTP request")
        candidate = bytes(self._buffer) + data
        if len(candidate) > len(self._expected):
            if candidate.startswith(self._expected):
                raise ExtraRequest("extra HTTP request")
            raise MalformedMessage("HTTP request is outside the fixed profile")
        if candidate != self._expected[:len(candidate)]:
            raise MalformedMessage("HTTP request is outside the fixed profile")
        self._buffer.extend(data)
        if len(self._buffer) == len(self._expected):
            self._complete = True
            self.request_count = 1
        return data

    def finish(self) -> None:
        if not self._complete:
            raise MalformedMessage("HTTP request is incomplete")


class SMBMessageKind(Enum):
    SMB2_NEGOTIATE = "smb2_negotiate"


def classify_smb_tcp_frame(frame: bytes) -> SMBMessageKind:
    if type(frame) is not bytes or frame != NMAP_SMB2_NEGOTIATE_REQUEST:
        raise MalformedMessage("SMB2 negotiate request is outside the pinned profile")
    return SMBMessageKind.SMB2_NEGOTIATE


def _validate_smb_negotiate_response(frame: bytes) -> None:
    if type(frame) is not bytes or len(frame) < 77 or frame[0] != 0:
        raise MalformedMessage("SMB2 negotiate response is malformed")
    if int.from_bytes(frame[1:4], "big") != len(frame) - 4:
        raise MalformedMessage("SMB2 response length is malformed")
    header = frame[4:68]
    if header[:4] != b"\xfeSMB" or header[4:6] != b"\x40\x00":
        raise MalformedMessage("SMB2 response header is malformed")
    if int.from_bytes(header[12:14], "little") != 0:
        raise MalformedMessage("SMB2 response command is outside the profile")
    if not int.from_bytes(header[16:20], "little") & 1:
        raise MalformedMessage("SMB2 message is not a server response")
    if int.from_bytes(header[20:24], "little") != 0:
        raise MalformedMessage("compound SMB2 response is not admitted")
    if int.from_bytes(header[24:32], "little") != 0:
        raise MalformedMessage("SMB2 response message identity is unexpected")
    status = int.from_bytes(header[8:12], "little")
    body = frame[68:]
    if status == 0:
        if len(body) < 65 or body[:2] != b"\x41\x00":
            raise MalformedMessage("SMB2 negotiate response body is truncated")
        if int.from_bytes(body[2:4], "little") & ~3:
            raise MalformedMessage("SMB2 negotiate security mode is malformed")
        if int.from_bytes(body[4:6], "little") not in {0x0202, 0x0210, 0x0300, 0x0302, 0x0311}:
            raise MalformedMessage("SMB2 negotiate dialect is outside the request")
        security_offset = int.from_bytes(body[56:58], "little")
        security_length = int.from_bytes(body[58:60], "little")
        if security_length and (
            security_offset < 128 or 4 + security_offset + security_length > len(frame)
        ):
            raise MalformedMessage("SMB2 negotiate security buffer is truncated")
    elif len(body) < 9 or body[:2] != b"\x09\x00":
        raise MalformedMessage("SMB2 error response body is truncated")


def _validate_nbstat_response(datagram: bytes) -> None:
    if type(datagram) is not bytes or len(datagram) < 50:
        raise MalformedMessage("NBSTAT response is malformed")
    if datagram[:2] != b"\x13\x37" or not int.from_bytes(datagram[2:4], "big") & 0x8000:
        raise MalformedMessage("NBSTAT response identity is malformed")
    if datagram[4:8] != b"\x00\x01\x00\x01":
        raise MalformedMessage("NBSTAT response counts are outside the profile")
    if datagram[12:50] != NMAP_NBSTAT_WILDCARD_REQUEST[12:]:
        raise MalformedMessage("NBSTAT response question differs from the fixed request")


class SMBRelayValidator:
    """Accept one exact Nmap negotiate request and one exact NBSTAT request."""

    def __init__(self, host: str, port: int) -> None:
        self.host, self.port = _loopback_ipv4(host, port, 445)
        self.udp_port = 137
        self._tcp = bytearray()
        self._tcp_complete = False
        self._tcp_response = False
        self._udp_response = False
        self.protocol_requests = 0
        self.udp_datagrams = 0

    def feed_tcp(self, data: bytes) -> bytes:
        if type(data) is not bytes or not data:
            raise MalformedMessage("SMB request chunk is malformed")
        if self._tcp_complete:
            raise ExtraRequest("extra SMB request")
        candidate = bytes(self._tcp) + data
        expected = NMAP_SMB2_NEGOTIATE_REQUEST
        if len(candidate) > len(expected):
            if candidate.startswith(expected):
                raise ExtraRequest("extra SMB request")
            raise MalformedMessage("SMB request is outside the fixed profile")
        if len(candidate) >= 18 and int.from_bytes(candidate[16:18], "little") != 0:
            raise MalformedMessage("forbidden SMB2 command")
        if candidate != expected[:len(candidate)]:
            raise MalformedMessage("SMB request is outside the fixed profile")
        self._tcp.extend(data)
        if len(self._tcp) == len(expected):
            classify_smb_tcp_frame(bytes(self._tcp))
            self._tcp_complete = True
            self.protocol_requests += 1
        return data

    def finish_tcp(self) -> None:
        if not self._tcp_complete:
            raise MalformedMessage("SMB request is incomplete")

    def feed_udp(self, datagram: bytes) -> bytes:
        if self.udp_datagrams:
            raise ExtraRequest("extra NetBIOS datagram")
        if type(datagram) is not bytes or datagram != NMAP_NBSTAT_WILDCARD_REQUEST:
            raise MalformedMessage("NBSTAT wildcard question is outside the pinned profile")
        self.udp_datagrams = 1
        self.protocol_requests += 1
        return datagram

    def accept_tcp_response(self, frame: bytes) -> bytes:
        if self._tcp_response:
            raise ExtraRequest("extra SMB response")
        if not self._tcp_complete:
            raise MalformedMessage("SMB response arrived before its fixed request")
        _validate_smb_negotiate_response(frame)
        self._tcp_response = True
        return frame

    def accept_udp_response(self, datagram: bytes) -> bytes:
        if self._udp_response:
            raise ExtraRequest("extra NBSTAT response")
        if not self.udp_datagrams:
            raise MalformedMessage("NBSTAT response arrived before its fixed request")
        _validate_nbstat_response(datagram)
        self._udp_response = True
        return datagram

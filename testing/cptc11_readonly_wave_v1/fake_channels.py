from __future__ import annotations


class ScriptedChannel:
    def __init__(self, response: bytes, *, http: bool = False, close_error: bool = False,
                 send_chunk: int | None = None, recv_chunk: int | None = None):
        self.response = (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(response)).encode() + b"\r\n\r\n" + response) if http else response
        self.close_error = close_error
        self.send_chunk = send_chunk
        self.recv_chunk = recv_chunk
        self.sent = bytearray()
        self.closed = False

    def send(self, data):
        amount = len(data) if self.send_chunk is None else min(self.send_chunk, len(data))
        self.sent.extend(bytes(data[:amount]))
        return amount

    def recv(self, maximum):
        if not self.response:
            return b""
        amount = min(maximum, len(self.response))
        if self.recv_chunk is not None:
            amount = min(amount, self.recv_chunk)
        result, self.response = self.response[:amount], self.response[amount:]
        return result

    def close(self):
        self.closed = True
        if self.close_error:
            raise OSError("synthetic close failure")

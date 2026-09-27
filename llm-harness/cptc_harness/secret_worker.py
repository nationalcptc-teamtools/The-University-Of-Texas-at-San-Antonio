"""Ephemeral credential custody inside a networkless namespace; RPC on fd0 only."""
import array
import json
import os
import resource
import socket
import time
import uuid

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_AS, (134217728, 134217728))
resource.setrlimit(resource.RLIMIT_FSIZE, (8192, 8192))
channel = socket.socket(fileno=0)
values = {}
while True:
    raw = channel.recv(65536)
    if not raw:
        break
    try:
        request = json.loads(raw)
        now = time.monotonic()
        values = {k: v for k, v in values.items() if v[2] > now and v[3] > 0}
        operation = request.get("operation")
        if operation == "close":
            break
        if operation == "deposit":
            secret = request["secret"]
            binding = request["profile_hash"]
            allowance = request["allowance"]
            if not isinstance(secret, str) or not 0 < len(secret) <= 8192 or any(ord(c) < 33 or ord(c) > 126 for c in secret) or len(binding) != 64 or type(allowance) is not int or not 1 <= allowance <= 12:
                raise ValueError()
            reference = uuid.uuid4().hex
            values[reference] = (secret, binding, now + 300, allowance)
            channel.send(json.dumps({"ok": True, "reference": reference}).encode())
        elif operation == "grant":
            reference = request["reference"]
            secret, binding, expiry, remaining = values[reference]
            if request["profile_hash"] != binding:
                raise ValueError()
            descriptor = os.memfd_create("cptc-credential", os.MFD_CLOEXEC)
            try:
                os.write(descriptor, secret.encode())
                os.lseek(descriptor, 0, 0)
                values[reference] = (secret, binding, expiry, remaining - 1)
                channel.sendmsg([b'{"ok":true}'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]))])
            finally:
                os.close(descriptor)
        else:
            raise ValueError()
    except Exception:
        channel.send(b'{"ok":false,"reason":"secret grant denied"}')

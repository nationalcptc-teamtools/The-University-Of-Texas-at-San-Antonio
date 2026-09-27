import pytest

from cptc11_readonly_wave_v1.parsers import ParserError
from cptc11_readonly_wave_v1.parsers.redis import parse_redis


@pytest.mark.parametrize(
    ("frame", "state"),
    ((b"+PONG\r\n", "pong"), (b"-NOAUTH Authentication required.\r\n", "authentication_required"), (b"+OK\r\n", "unexpected"), (b"-ERR nope\r\n", "unexpected"), (b"+PON", "incomplete")),
)
def test_redis_retains_only_closed_state(frame, state):
    assert parse_redis(frame).state == state


@pytest.mark.parametrize("frame", (b"+PONG\r\n+OK\r\n", b"$4\r\nPONG\r\n", b"$4", b"*1\r\n+PONG\r\n", b"+" + b"x" * 126 + b"\r\n"))
def test_redis_rejects_extra_unsupported_or_oversize(frame):
    with pytest.raises(ParserError):
        parse_redis(frame)


@pytest.mark.parametrize(
    "frame",
    (
        b"+OK\x00AY\r\n", b"+OK\x1f\r\n", b"+OK\x7f\r\n",
        b"+OK\rX\r\n", b"+OK\nX\r\n", b"-NOAUTHENTICATED nope\r\n",
    ),
)
def test_redis_rejects_controls_and_requires_noauth_token_boundary(frame):
    if frame.startswith(b"-NOAUTHENTICATED"):
        assert parse_redis(frame).state == "unexpected"
    else:
        with pytest.raises(ParserError):
            parse_redis(frame)

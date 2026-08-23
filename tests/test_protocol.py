import pytest

from akita_ddns.protocol import Command, ProtocolError, decode, encode


def test_protocol_round_trip_preserves_binary_fields():
    payload = encode(Command.RESOLVE, "mesh", "router", b"x" * 64, b"n" * 16)

    message = decode(payload)

    assert message == [1, Command.RESOLVE, "mesh", "router", b"x" * 64, b"n" * 16]


def test_protocol_rejects_oversized_payload():
    with pytest.raises(ProtocolError, match="maximum"):
        encode(Command.RESOLVE, "x" * 500)


def test_protocol_rejects_trailing_data():
    payload = encode(Command.RESOLVE, "mesh") + b"trailing"

    with pytest.raises(ProtocolError, match="Malformed"):
        decode(payload)

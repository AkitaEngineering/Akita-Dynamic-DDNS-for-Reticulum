"""Versioned, bounded wire encoding for Akita DDNS packets."""

from enum import IntEnum
from typing import Any, List

import msgpack

PROTOCOL_VERSION = 1


class Command(IntEnum):
    REGISTER = 1
    RESOLVE = 2
    RESPONSE = 3
    GOSSIP_REGISTER = 4
    NAMESPACE_CREATE = 5
    NAMESPACE_TRANSFER = 6
    GOSSIP_NAMESPACE_CREATE = 7
    GOSSIP_NAMESPACE_TRANSFER = 8


class ProtocolError(ValueError):
    """Raised when a packet is malformed or uses an unsupported protocol."""


def encode(command: Command, *fields: Any, max_size: int = 464) -> bytes:
    """Encode a packet and refuse payloads larger than Reticulum can carry."""
    try:
        payload = msgpack.packb(
            [PROTOCOL_VERSION, int(command), *fields],
            use_bin_type=True,
            strict_types=True,
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise ProtocolError(f"Packet could not be encoded: {exc}") from exc
    if len(payload) > max_size:
        raise ProtocolError(f"Packet is {len(payload)} bytes; maximum is {max_size}")
    return payload


def decode(payload: bytes, max_size: int = 464) -> List[Any]:
    """Decode and minimally validate a versioned packet envelope."""
    if not isinstance(payload, bytes) or not payload:
        raise ProtocolError("Packet must be non-empty bytes")
    if len(payload) > max_size:
        raise ProtocolError("Packet exceeds the maximum size")
    try:
        message = msgpack.unpackb(
            payload,
            raw=False,
            strict_map_key=True,
            max_array_len=16,
            max_map_len=0,
            max_str_len=max_size,
            max_bin_len=max_size,
            max_ext_len=0,
        )
    except (
        ValueError,
        TypeError,
        msgpack.ExtraData,
        msgpack.FormatError,
        msgpack.StackError,
    ) as exc:
        raise ProtocolError("Malformed packet") from exc
    if not isinstance(message, list) or len(message) < 2:
        raise ProtocolError("Invalid packet envelope")
    if message[0] != PROTOCOL_VERSION:
        raise ProtocolError(f"Unsupported protocol version: {message[0]!r}")
    try:
        message[1] = Command(message[1])
    except (TypeError, ValueError) as exc:
        raise ProtocolError("Unknown packet command") from exc
    return message

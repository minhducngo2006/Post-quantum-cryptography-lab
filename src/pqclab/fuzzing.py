"""Bounded Atheris target for the authenticated streaming-envelope parser."""

from __future__ import annotations

from io import BytesIO

from pqclab.crypto.streaming import HEADER_BYTES, MAGIC, MAX_CHUNK_SIZE, decrypt_stream
from pqclab.errors import CryptoFailure, FormatError

MAX_FUZZ_INPUT_BYTES = 1024 * 1024
MAX_FUZZ_PLAINTEXT_BYTES = 8 * 1024 * 1024
_FUZZ_KEY = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")


def _header(chunk_size: int) -> bytes:
    return MAGIC + chunk_size.to_bytes(4, "big") + bytes(16) + bytes(4)


def malformed_stream_corpus() -> tuple[bytes, ...]:
    return (
        b"",
        MAGIC[:-1],
        MAGIC + bytes(HEADER_BYTES - len(MAGIC)),
        _header(0),
        _header(MAX_CHUNK_SIZE + 1),
        _header(1) + (0xFFFFFFFF).to_bytes(4, "big"),
        _header(1) + bytes(4) + bytes(15),
        _header(1) + (1).to_bytes(4, "big") + bytes(3),
        _header(32) + (1).to_bytes(4, "big") + bytes(17),
        _header(32) + (32).to_bytes(4, "big") + bytes(48),
    )


def _input_is_rejected(data: bytes) -> bool:
    try:
        decrypt_stream(BytesIO(data), BytesIO(), _FUZZ_KEY, max_bytes=MAX_FUZZ_PLAINTEXT_BYTES)
    except (CryptoFailure, FormatError):
        return True
    return False


def run_parser_smoke_corpus() -> int:
    return sum(_input_is_rejected(data) for data in malformed_stream_corpus())


def fuzz_stream_parser(data: bytes) -> None:
    """Atheris entry point; unexpected exceptions are intentionally not swallowed."""
    if not isinstance(data, bytes) or len(data) > MAX_FUZZ_INPUT_BYTES:
        return
    _input_is_rejected(data)

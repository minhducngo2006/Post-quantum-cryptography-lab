"""Authenticated chunked file encryption with a 4 MiB default and 1 TiB ceiling."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqclab.errors import CryptoFailure, FormatError, OutputExists

MAGIC = b"PQCS" + bytes((1, 0, 0, 0))
HEADER_BYTES = 32
SALT_BYTES = 16
NONCE_PREFIX_BYTES = 4
TAG_BYTES = 16
KEY_BYTES = 32
CHUNK_SIZE = 4 * 1024 * 1024
MAX_CHUNK_SIZE = CHUNK_SIZE
MAX_STREAM_BYTES = 1 << 40
_SPOOL_MEMORY_LIMIT = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class StreamStats:
    plaintext_bytes: int
    chunks: int


def _validate(shared_secret: bytes, associated_data: bytes, max_bytes: int) -> None:
    if not isinstance(shared_secret, bytes) or len(shared_secret) != KEY_BYTES:
        raise FormatError("Streaming key material must be exactly 32 bytes.")
    if not isinstance(associated_data, bytes):
        raise FormatError("Streaming associated data must be bytes.")
    if not isinstance(max_bytes, int) or not 0 <= max_bytes <= MAX_STREAM_BYTES:
        raise FormatError("Maximum stream size must be between zero and 1 TiB.")


def _write_all(destination: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = destination.write(view)
        if written is None or written <= 0:
            raise OSError("Destination stream did not accept the complete write.")
        view = view[written:]


def _read_exact(source: BinaryIO, size: int) -> bytes:
    parts: list[bytes] = []
    remaining = size
    while remaining:
        part = source.read(remaining)
        if not part:
            raise FormatError("Encrypted stream is truncated.")
        parts.append(part)
        remaining -= len(part)
    return b"".join(parts)


def _read_chunk(source: BinaryIO, size: int) -> bytes:
    parts: list[bytes] = []
    remaining = size
    while remaining:
        part = source.read(remaining)
        if not part:
            break
        parts.append(part)
        remaining -= len(part)
    return b"".join(parts)


def _derive_key(shared_secret: bytes, salt: bytes, associated_data: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        info=b"pqclab/stream-aead/v1" + len(associated_data).to_bytes(8, "big") + associated_data,
    ).derive(shared_secret)


def _nonce(prefix: bytes, index: int) -> bytes:
    return prefix + index.to_bytes(8, "big")


def _aad(header: bytes, associated_data: bytes, index: int, length: int, final: bool) -> bytes:
    return (
        header
        + len(associated_data).to_bytes(8, "big")
        + associated_data
        + index.to_bytes(8, "big")
        + length.to_bytes(4, "big")
        + (b"final" if final else b"chunk")
    )


def encrypt_stream(
    source: BinaryIO,
    destination: BinaryIO,
    shared_secret: bytes,
    *,
    associated_data: bytes = b"",
    chunk_size: int = CHUNK_SIZE,
    max_bytes: int = MAX_STREAM_BYTES,
) -> StreamStats:
    """Encrypt a binary stream; each chunk and the final marker are independently authenticated."""
    _validate(shared_secret, associated_data, max_bytes)
    if not isinstance(chunk_size, int) or not 1 <= chunk_size <= MAX_CHUNK_SIZE:
        raise FormatError("Chunk size must be between one byte and 4 MiB.")

    import os

    salt = os.urandom(SALT_BYTES)
    nonce_prefix = os.urandom(NONCE_PREFIX_BYTES)
    header = MAGIC + chunk_size.to_bytes(4, "big") + salt + nonce_prefix
    key = _derive_key(shared_secret, salt, associated_data)
    cipher = AESGCM(key)
    _write_all(destination, header)

    total = 0
    index = 0
    while True:
        plaintext = _read_chunk(source, chunk_size)
        if not plaintext:
            break
        if total + len(plaintext) > max_bytes:
            raise FormatError("Plaintext exceeds the configured stream size limit.")
        aad = _aad(header, associated_data, index, len(plaintext), False)
        encrypted = cipher.encrypt(_nonce(nonce_prefix, index), plaintext, aad)
        _write_all(destination, len(plaintext).to_bytes(4, "big"))
        _write_all(destination, encrypted)
        total += len(plaintext)
        index += 1

    final_aad = _aad(header, associated_data, index, 0, True)
    final_tag = cipher.encrypt(_nonce(nonce_prefix, index), b"", final_aad)
    _write_all(destination, (0).to_bytes(4, "big"))
    _write_all(destination, final_tag)
    return StreamStats(total, index)


def decrypt_stream(
    source: BinaryIO,
    destination: BinaryIO,
    shared_secret: bytes,
    *,
    associated_data: bytes = b"",
    max_bytes: int = MAX_STREAM_BYTES,
) -> StreamStats:
    """Authenticate the complete stream before publishing any plaintext to destination."""
    _validate(shared_secret, associated_data, max_bytes)
    header = _read_exact(source, HEADER_BYTES)
    if header[: len(MAGIC)] != MAGIC:
        raise FormatError("Unsupported encrypted stream format or version.")
    chunk_size = int.from_bytes(header[len(MAGIC) : len(MAGIC) + 4], "big")
    if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
        raise FormatError("Encrypted stream declares an invalid chunk size.")

    salt_start = len(MAGIC) + 4
    nonce_start = salt_start + SALT_BYTES
    salt = header[salt_start:nonce_start]
    nonce_prefix = header[nonce_start:HEADER_BYTES]
    key = _derive_key(shared_secret, salt, associated_data)
    cipher = AESGCM(key)

    total = 0
    index = 0
    with tempfile.SpooledTemporaryFile(max_size=_SPOOL_MEMORY_LIMIT, mode="w+b") as verified:
        while True:
            record_length = int.from_bytes(_read_exact(source, 4), "big")
            if record_length == 0:
                final_tag = _read_exact(source, TAG_BYTES)
                final_aad = _aad(header, associated_data, index, 0, True)
                try:
                    cipher.decrypt(_nonce(nonce_prefix, index), final_tag, final_aad)
                except InvalidTag as exc:
                    raise CryptoFailure("Encrypted stream final authentication failed.") from exc
                if source.read(1):
                    raise FormatError("Encrypted stream contains trailing data.")
                verified.seek(0)
                while block := verified.read(CHUNK_SIZE):
                    _write_all(destination, block)
                return StreamStats(total, index)

            if record_length > chunk_size:
                raise FormatError("Encrypted stream contains an oversized chunk.")
            if total + record_length > max_bytes:
                raise FormatError("Decrypted stream exceeds the configured size limit.")
            encrypted = _read_exact(source, record_length + TAG_BYTES)
            chunk_aad = _aad(header, associated_data, index, record_length, False)
            try:
                plaintext = cipher.decrypt(_nonce(nonce_prefix, index), encrypted, chunk_aad)
            except InvalidTag as exc:
                raise CryptoFailure("Encrypted stream chunk authentication failed.") from exc
            if len(plaintext) != record_length:
                raise CryptoFailure(
                    "Decrypted chunk length does not match its authenticated record."
                )
            verified.write(plaintext)
            total += len(plaintext)
            index += 1


def _publish_atomic(
    destination: str | Path,
    writer,
) -> StreamStats:
    target = Path(destination)
    if not target.parent.is_dir():
        raise FormatError("Destination parent directory does not exist.")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".pqclab-stream-", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            stats = writer(output)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, target)
        except FileExistsError as exc:
            raise OutputExists("Refusing to overwrite an existing encrypted output.") from exc
        directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return stats
    finally:
        temporary.unlink(missing_ok=True)


def encrypt_file(
    source_path: str | Path,
    destination_path: str | Path,
    shared_secret: bytes,
    *,
    associated_data: bytes = b"",
    chunk_size: int = CHUNK_SIZE,
    max_bytes: int = MAX_STREAM_BYTES,
) -> StreamStats:
    """Encrypt a file to a new owner-only destination, publishing only a complete file."""
    with Path(source_path).open("rb") as source:
        return _publish_atomic(
            destination_path,
            lambda destination: encrypt_stream(
                source,
                destination,
                shared_secret,
                associated_data=associated_data,
                chunk_size=chunk_size,
                max_bytes=max_bytes,
            ),
        )


def decrypt_file(
    source_path: str | Path,
    destination_path: str | Path,
    shared_secret: bytes,
    *,
    associated_data: bytes = b"",
    max_bytes: int = MAX_STREAM_BYTES,
) -> StreamStats:
    """Authenticate a complete encrypted file before atomically publishing plaintext."""
    with Path(source_path).open("rb") as source:
        return _publish_atomic(
            destination_path,
            lambda destination: decrypt_stream(
                source,
                destination,
                shared_secret,
                associated_data=associated_data,
                max_bytes=max_bytes,
            ),
        )

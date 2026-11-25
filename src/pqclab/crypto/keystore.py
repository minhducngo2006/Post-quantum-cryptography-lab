"""Versioned AES-256-GCM envelope for in-memory private-key material."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from pqclab.errors import CryptoFailure, FormatError, OutputExists

MAGIC = b"PQK" + bytes((1,))
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
TAG_BYTES = 16
MAX_PRIVATE_KEY_BYTES = 1024 * 1024
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1


def _validate(plaintext: bytes, passphrase: bytes, associated_data: bytes) -> None:
    if not isinstance(plaintext, bytes) or not isinstance(passphrase, bytes):
        raise FormatError("Private key material and passphrase must be bytes.")
    if not isinstance(associated_data, bytes):
        raise FormatError("Associated data must be bytes.")
    if not plaintext or len(plaintext) > MAX_PRIVATE_KEY_BYTES:
        raise FormatError("Private key material is empty or exceeds the size limit.")
    if not passphrase:
        raise FormatError("Passphrase must not be empty.")


def _derive_key(passphrase: bytes, salt: bytes) -> bytes:
    return Scrypt(
        salt=salt,
        length=KEY_BYTES,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
    ).derive(passphrase)


def encrypt_private_key(
    plaintext: bytes,
    passphrase: bytes,
    *,
    associated_data: bytes = b"",
) -> bytes:
    """Encrypt private key bytes using Scrypt and AES-256-GCM.

    The binary envelope is MAGIC || salt || nonce || authenticated ciphertext.
    Header and caller-provided associated data are authenticated but not encrypted.
    """
    _validate(plaintext, passphrase, associated_data)
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    header = MAGIC + salt + nonce
    key = _derive_key(passphrase, salt)
    return header + AESGCM(key).encrypt(nonce, plaintext, header + associated_data)


def decrypt_private_key(
    envelope: bytes,
    passphrase: bytes,
    *,
    associated_data: bytes = b"",
) -> bytes:
    """Decrypt a private-key envelope; never fall back to plaintext on failure."""
    if not isinstance(envelope, bytes) or not isinstance(passphrase, bytes):
        raise FormatError("Private key envelope and passphrase must be bytes.")
    if not isinstance(associated_data, bytes):
        raise FormatError("Associated data must be bytes.")
    if not passphrase:
        raise FormatError("Passphrase must not be empty.")
    header_bytes = len(MAGIC) + SALT_BYTES + NONCE_BYTES
    if (
        len(envelope) < header_bytes + TAG_BYTES
        or len(envelope) > MAX_PRIVATE_KEY_BYTES + header_bytes + TAG_BYTES
    ):
        raise FormatError("Private key envelope has an invalid size.")
    if envelope[: len(MAGIC)] != MAGIC:
        raise FormatError("Unsupported private key envelope version.")

    salt_start = len(MAGIC)
    nonce_start = salt_start + SALT_BYTES
    salt = envelope[salt_start:nonce_start]
    nonce = envelope[nonce_start:header_bytes]
    header = envelope[:header_bytes]
    key = _derive_key(passphrase, salt)
    try:
        return AESGCM(key).decrypt(nonce, envelope[header_bytes:], header + associated_data)
    except InvalidTag as exc:
        raise CryptoFailure("Private key decryption or authentication failed.") from exc


def save_private_key(
    path: str | Path,
    plaintext: bytes,
    passphrase: bytes,
    *,
    associated_data: bytes = b"",
) -> None:
    """Atomically create an encrypted key file with owner-only permissions; never overwrite."""
    target = Path(path)
    if not target.parent.is_dir():
        raise FormatError("Private key parent directory does not exist.")
    envelope = encrypt_private_key(plaintext, passphrase, associated_data=associated_data)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".pqclab-key-", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(envelope)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, target)
        except FileExistsError as exc:
            raise OutputExists("Refusing to overwrite an existing private key file.") from exc
        directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def load_private_key(
    path: str | Path,
    passphrase: bytes,
    *,
    associated_data: bytes = b"",
) -> bytes:
    """Read only a regular owner-private file and authenticate it before returning bytes."""
    target = Path(path)
    try:
        metadata = target.lstat()
    except FileNotFoundError as exc:
        raise FormatError("Private key file does not exist.") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
        raise FormatError("Private key file must be regular and accessible only by its owner.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags)
    with os.fdopen(descriptor, "rb") as stream:
        envelope = stream.read(
            MAX_PRIVATE_KEY_BYTES + len(MAGIC) + SALT_BYTES + NONCE_BYTES + TAG_BYTES + 1
        )
    return decrypt_private_key(envelope, passphrase, associated_data=associated_data)

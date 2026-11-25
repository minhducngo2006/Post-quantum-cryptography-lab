"""Allowlisted ML-KEM key generation and encapsulation operations."""

from __future__ import annotations

from dataclasses import dataclass, field

from pqclab.backend import require_backend
from pqclab.errors import BackendUnavailable, FormatError

KEM_ALGORITHMS = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")
DEFAULT_KEM = "ML-KEM-768"


@dataclass(frozen=True, slots=True)
class KEMKeyPair:
    algorithm: str
    public_key: bytes
    secret_key: bytes = field(repr=False)


def _algorithm(value: str) -> str:
    if value not in KEM_ALGORITHMS:
        raise FormatError(f"Unsupported KEM algorithm: {value}")
    return value


def _wrapper():
    require_backend()
    import oqs

    return oqs


def generate_kem_keypair(algorithm: str = DEFAULT_KEM) -> KEMKeyPair:
    algorithm = _algorithm(algorithm)
    oqs = _wrapper()
    with oqs.KeyEncapsulation(algorithm) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        if len(public_key) != kem.details["length_public_key"]:
            raise BackendUnavailable("Native KEM returned a public key with an invalid length.")
        if len(secret_key) != kem.details["length_secret_key"]:
            raise BackendUnavailable("Native KEM returned a secret key with an invalid length.")
    return KEMKeyPair(algorithm, bytes(public_key), bytes(secret_key))


def encapsulate(public_key: bytes, algorithm: str = DEFAULT_KEM) -> tuple[bytes, bytes]:
    algorithm = _algorithm(algorithm)
    if not isinstance(public_key, bytes):
        raise FormatError("KEM public key must be bytes.")
    oqs = _wrapper()
    with oqs.KeyEncapsulation(algorithm) as kem:
        if len(public_key) != kem.details["length_public_key"]:
            raise FormatError("KEM public key has an invalid length.")
        ciphertext, shared_secret = kem.encap_secret(public_key)
        if len(ciphertext) != kem.details["length_ciphertext"]:
            raise BackendUnavailable("Native KEM returned a ciphertext with an invalid length.")
        if len(shared_secret) != kem.details["length_shared_secret"]:
            raise BackendUnavailable("Native KEM returned a shared secret with an invalid length.")
    return bytes(ciphertext), bytes(shared_secret)


def decapsulate(secret_key: bytes, ciphertext: bytes, algorithm: str = DEFAULT_KEM) -> bytes:
    algorithm = _algorithm(algorithm)
    if not isinstance(secret_key, bytes) or not isinstance(ciphertext, bytes):
        raise FormatError("KEM secret key and ciphertext must be bytes.")
    oqs = _wrapper()
    try:
        kem = oqs.KeyEncapsulation(algorithm, secret_key=secret_key)
    except ValueError as exc:
        raise FormatError("KEM secret key has an invalid length.") from exc
    try:
        if len(ciphertext) != kem.details["length_ciphertext"]:
            raise FormatError("KEM ciphertext has an invalid length.")
        shared_secret = kem.decap_secret(ciphertext)
        if len(shared_secret) != kem.details["length_shared_secret"]:
            raise BackendUnavailable("Native KEM returned a shared secret with an invalid length.")
        return bytes(shared_secret)
    finally:
        kem.free()

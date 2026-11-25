"""Hybrid ML-KEM + X25519 key establishment with transcript-bound HKDF."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqclab.crypto.kem import (
    DEFAULT_KEM,
    KEM_ALGORITHMS,
    decapsulate,
    encapsulate,
    generate_kem_keypair,
)
from pqclab.errors import FormatError

DEFAULT_HYBRID_KEM = f"{DEFAULT_KEM}+X25519"


@dataclass(frozen=True, slots=True)
class HybridPublicKey:
    algorithm: str
    kem_public_key: bytes
    x25519_public_key: bytes


@dataclass(frozen=True, slots=True)
class HybridKeyPair:
    public_key: HybridPublicKey
    kem_secret_key: bytes = field(repr=False)
    x25519_secret_key: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class HybridCiphertext:
    version: int
    kem_algorithm: str
    kem_ciphertext: bytes
    ephemeral_public_key: bytes


def _frame(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def _transcript(
    public_key: HybridPublicKey,
    ciphertext: HybridCiphertext,
    context: bytes,
) -> bytes:
    fields = (
        b"pqclab/hybrid-kem/v1",
        public_key.algorithm.encode("ascii"),
        public_key.kem_public_key,
        public_key.x25519_public_key,
        ciphertext.kem_algorithm.encode("ascii"),
        ciphertext.kem_ciphertext,
        ciphertext.ephemeral_public_key,
        context,
    )
    return b"".join(_frame(value) for value in fields)


def _derive_secret(pq_secret: bytes, classical_secret: bytes, transcript: bytes) -> bytes:
    # Length-prefixing avoids ambiguity; HKDF, not XOR, combines both independent secrets.
    ikm = _frame(pq_secret) + _frame(classical_secret)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(transcript).digest(),
        info=b"pqclab/hybrid-kem/v1",
    ).derive(ikm)


def generate_hybrid_keypair(kem_algorithm: str = DEFAULT_KEM) -> HybridKeyPair:
    if kem_algorithm not in KEM_ALGORITHMS:
        raise FormatError(f"Unsupported hybrid KEM algorithm: {kem_algorithm}")
    kem_pair = generate_kem_keypair(kem_algorithm)
    classical_private = X25519PrivateKey.generate()
    classical_public = classical_private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    classical_secret = classical_private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return HybridKeyPair(
        HybridPublicKey(kem_algorithm, kem_pair.public_key, classical_public),
        kem_pair.secret_key,
        classical_secret,
    )


def hybrid_encapsulate(
    recipient: HybridPublicKey,
    *,
    context: bytes = b"",
) -> tuple[HybridCiphertext, bytes]:
    if not isinstance(recipient, HybridPublicKey) or not isinstance(context, bytes):
        raise FormatError("Hybrid recipient key and context have invalid types.")
    if recipient.algorithm not in KEM_ALGORITHMS:
        raise FormatError("Hybrid recipient uses an unsupported KEM algorithm.")
    if len(recipient.x25519_public_key) != 32:
        raise FormatError("X25519 recipient public key has an invalid length.")
    try:
        recipient_classical_public = X25519PublicKey.from_public_bytes(recipient.x25519_public_key)
    except ValueError as exc:
        raise FormatError("X25519 recipient public key is malformed.") from exc

    kem_ciphertext, pq_secret = encapsulate(recipient.kem_public_key, recipient.algorithm)
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    classical_secret = ephemeral_private.exchange(recipient_classical_public)
    ciphertext = HybridCiphertext(
        version=1,
        kem_algorithm=recipient.algorithm,
        kem_ciphertext=kem_ciphertext,
        ephemeral_public_key=ephemeral_public,
    )
    transcript = _transcript(recipient, ciphertext, context)
    return ciphertext, _derive_secret(pq_secret, classical_secret, transcript)


def hybrid_decapsulate(
    recipient: HybridKeyPair,
    ciphertext: HybridCiphertext,
    *,
    context: bytes = b"",
) -> bytes:
    if not isinstance(recipient, HybridKeyPair) or not isinstance(ciphertext, HybridCiphertext):
        raise FormatError("Hybrid key pair or ciphertext has an invalid type.")
    if not isinstance(context, bytes):
        raise FormatError("Hybrid context must be bytes.")
    if ciphertext.version != 1:
        raise FormatError("Unsupported hybrid ciphertext version.")
    public_key = recipient.public_key
    if ciphertext.kem_algorithm != public_key.algorithm:
        raise FormatError("Hybrid ciphertext algorithm does not match the recipient key.")
    if len(ciphertext.ephemeral_public_key) != 32:
        raise FormatError("X25519 ephemeral public key has an invalid length.")
    try:
        ephemeral_public = X25519PublicKey.from_public_bytes(ciphertext.ephemeral_public_key)
        classical_private = X25519PrivateKey.from_private_bytes(recipient.x25519_secret_key)
        classical_secret = classical_private.exchange(ephemeral_public)
    except ValueError as exc:
        raise FormatError("Hybrid X25519 key material is malformed.") from exc

    pq_secret = decapsulate(
        recipient.kem_secret_key,
        ciphertext.kem_ciphertext,
        public_key.algorithm,
    )
    transcript = _transcript(public_key, ciphertext, context)
    return _derive_secret(pq_secret, classical_secret, transcript)

"""Hybrid ML-DSA + ECDSA-P256 signatures; both verifications are mandatory."""

from __future__ import annotations

from dataclasses import dataclass, field

from pqclab.crypto.classical import ecdsa_p256_sign, ecdsa_p256_verify, generate_ecdh_keypair
from pqclab.crypto.signatures import (
    DEFAULT_SIGNATURE,
    generate_signature_keypair,
    sign,
    verify,
)
from pqclab.errors import FormatError

DEFAULT_HYBRID_SIGNATURE = f"{DEFAULT_SIGNATURE}+ECDSA-P256"


@dataclass(frozen=True, slots=True)
class HybridSignaturePublicKey:
    algorithm: str
    pq_public_key: bytes
    classical_public_key: bytes


@dataclass(frozen=True, slots=True)
class HybridSignatureKeyPair:
    public_key: HybridSignaturePublicKey
    pq_secret_key: bytes = field(repr=False)
    classical_secret_key: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class HybridSignature:
    version: int
    pq_signature: bytes
    classical_signature: bytes


def _payload(message: bytes, context: bytes) -> bytes:
    if not isinstance(message, bytes) or not isinstance(context, bytes):
        raise FormatError("Hybrid signature message and context must be bytes.")
    domain = b"pqclab/hybrid-signature/v1"
    return (
        len(domain).to_bytes(8, "big")
        + domain
        + len(context).to_bytes(8, "big")
        + context
        + len(message).to_bytes(8, "big")
        + message
    )


def generate_hybrid_signature_keypair(
    algorithm: str = DEFAULT_SIGNATURE,
) -> HybridSignatureKeyPair:
    pq_pair = generate_signature_keypair(algorithm)
    classical_pair = generate_ecdh_keypair("P-256")
    public_key = HybridSignaturePublicKey(
        algorithm,
        pq_pair.public_key,
        classical_pair.public_key,
    )
    return HybridSignatureKeyPair(public_key, pq_pair.secret_key, classical_pair.private_key)


def hybrid_sign(
    key_pair: HybridSignatureKeyPair,
    message: bytes,
    *,
    context: bytes = b"",
) -> HybridSignature:
    if not isinstance(key_pair, HybridSignatureKeyPair):
        raise FormatError("Hybrid signature key pair is invalid.")
    payload = _payload(message, context)
    pq_signature = sign(key_pair.pq_secret_key, payload, key_pair.public_key.algorithm)
    classical_signature = ecdsa_p256_sign(key_pair.classical_secret_key, payload)
    return HybridSignature(1, pq_signature, classical_signature)


def hybrid_verify(
    public_key: HybridSignaturePublicKey,
    message: bytes,
    signature: HybridSignature,
    *,
    context: bytes = b"",
) -> bool:
    if not isinstance(public_key, HybridSignaturePublicKey) or not isinstance(
        signature, HybridSignature
    ):
        raise FormatError("Hybrid signature public key or signature is invalid.")
    if signature.version != 1:
        raise FormatError("Unsupported hybrid signature version.")
    payload = _payload(message, context)
    pq_valid = verify(
        public_key.pq_public_key,
        payload,
        signature.pq_signature,
        public_key.algorithm,
    )
    classical_valid = ecdsa_p256_verify(
        public_key.classical_public_key,
        payload,
        signature.classical_signature,
    )
    return pq_valid and classical_valid

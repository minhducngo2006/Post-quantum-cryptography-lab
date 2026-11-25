"""Domain-separated fingerprints for hybrid public keys; no private material is accepted."""

from __future__ import annotations

import hashlib
import hmac

from pqclab.crypto.hybrid import HybridPublicKey
from pqclab.crypto.hybrid_signatures import HybridSignaturePublicKey
from pqclab.crypto.kem import KEM_ALGORITHMS
from pqclab.crypto.signatures import SIGNATURE_ALGORITHMS
from pqclab.errors import FormatError

_HEX_DIGITS = frozenset("0123456789abcdef")


def _frame(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def _fingerprint(domain: bytes, algorithm: str, components: tuple[bytes, ...]) -> str:
    digest = hashlib.sha256()
    digest.update(_frame(domain))
    digest.update(_frame(algorithm.encode("ascii")))
    for component in components:
        digest.update(_frame(component))
    return digest.hexdigest()


def hybrid_kem_public_key_fingerprint(public_key: HybridPublicKey) -> str:
    """Return a stable SHA-256 fingerprint binding the KEM and X25519 public keys."""
    if not isinstance(public_key, HybridPublicKey):
        raise FormatError("Expected a hybrid KEM public key.")
    if public_key.algorithm not in KEM_ALGORITHMS:
        raise FormatError("Hybrid KEM public key uses an unsupported algorithm.")
    if not isinstance(public_key.kem_public_key, bytes) or not public_key.kem_public_key:
        raise FormatError("Hybrid KEM public key component must be non-empty bytes.")
    if (
        not isinstance(public_key.x25519_public_key, bytes)
        or len(public_key.x25519_public_key) != 32
    ):
        raise FormatError("Hybrid X25519 public key must be exactly 32 bytes.")
    return _fingerprint(
        b"pqclab/hybrid-kem-public-key-fingerprint/v1",
        public_key.algorithm,
        (public_key.kem_public_key, public_key.x25519_public_key),
    )


def hybrid_signature_public_key_fingerprint(public_key: HybridSignaturePublicKey) -> str:
    """Return a stable SHA-256 fingerprint binding ML-DSA/SLH-DSA and P-256 public keys."""
    if not isinstance(public_key, HybridSignaturePublicKey):
        raise FormatError("Expected a hybrid signature public key.")
    if public_key.algorithm not in SIGNATURE_ALGORITHMS:
        raise FormatError("Hybrid signature public key uses an unsupported algorithm.")
    if not isinstance(public_key.pq_public_key, bytes) or not public_key.pq_public_key:
        raise FormatError("Post-quantum signature public key must be non-empty bytes.")
    classical = public_key.classical_public_key
    if not isinstance(classical, bytes) or len(classical) != 65 or classical[0] != 0x04:
        raise FormatError("P-256 public key must be an uncompressed 65-byte point.")
    return _fingerprint(
        b"pqclab/hybrid-signature-public-key-fingerprint/v1",
        public_key.algorithm,
        (public_key.pq_public_key, classical),
    )


def fingerprint_matches(expected: str, actual: str) -> bool:
    """Compare two 64-character SHA-256 hex fingerprints without timing-sensitive equality."""
    if not isinstance(expected, str) or not isinstance(actual, str):
        return False
    if len(expected) != 64 or len(actual) != 64:
        return False
    if not set(expected.lower()).issubset(_HEX_DIGITS) or not set(actual.lower()).issubset(
        _HEX_DIGITS
    ):
        return False
    return hmac.compare_digest(expected.lower(), actual.lower())

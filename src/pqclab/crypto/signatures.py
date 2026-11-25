"""Allowlisted ML-DSA and SLH-DSA signing and verification operations."""

from __future__ import annotations

from dataclasses import dataclass, field

from pqclab.backend import require_backend
from pqclab.errors import BackendUnavailable, FormatError

SIGNATURE_ALGORITHMS = (
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-256s",
)
DEFAULT_SIGNATURE = "ML-DSA-65"
_BACKEND_IDS = {
    "SLH-DSA-SHA2-128s": "SLH_DSA_PURE_SHA2_128S",
    "SLH-DSA-SHA2-192s": "SLH_DSA_PURE_SHA2_192S",
    "SLH-DSA-SHA2-256s": "SLH_DSA_PURE_SHA2_256S",
}


def _backend_algorithm(value: str) -> str:
    return _BACKEND_IDS.get(value, value)


@dataclass(frozen=True, slots=True)
class SignatureKeyPair:
    algorithm: str
    public_key: bytes
    secret_key: bytes = field(repr=False)


def _algorithm(value: str) -> str:
    if value not in SIGNATURE_ALGORITHMS:
        raise FormatError(f"Unsupported signature algorithm: {value}")
    return value


def _wrapper():
    require_backend()
    import oqs

    return oqs


def generate_signature_keypair(algorithm: str = DEFAULT_SIGNATURE) -> SignatureKeyPair:
    algorithm = _algorithm(algorithm)
    oqs = _wrapper()
    with oqs.Signature(_backend_algorithm(algorithm)) as signature:
        public_key = signature.generate_keypair()
        secret_key = signature.export_secret_key()
        if len(public_key) != signature.details["length_public_key"]:
            raise BackendUnavailable("Native signature backend returned an invalid public key.")
        if len(secret_key) != signature.details["length_secret_key"]:
            raise BackendUnavailable("Native signature backend returned an invalid secret key.")
    return SignatureKeyPair(algorithm, bytes(public_key), bytes(secret_key))


def sign(secret_key: bytes, message: bytes, algorithm: str = DEFAULT_SIGNATURE) -> bytes:
    algorithm = _algorithm(algorithm)
    if not isinstance(secret_key, bytes) or not isinstance(message, bytes):
        raise FormatError("Signature secret key and message must be bytes.")
    oqs = _wrapper()
    try:
        signature = oqs.Signature(_backend_algorithm(algorithm), secret_key=secret_key)
    except ValueError as exc:
        raise FormatError("Signature secret key has an invalid length.") from exc
    try:
        result = signature.sign(message)
        if len(result) != signature.details["length_signature"]:
            raise BackendUnavailable("Native signature backend returned an invalid signature.")
        return bytes(result)
    finally:
        signature.free()


def verify(
    public_key: bytes,
    message: bytes,
    signature_bytes: bytes,
    algorithm: str = DEFAULT_SIGNATURE,
) -> bool:
    algorithm = _algorithm(algorithm)
    if not all(isinstance(value, bytes) for value in (public_key, message, signature_bytes)):
        raise FormatError("Signature public key, message and signature must be bytes.")
    oqs = _wrapper()
    with oqs.Signature(_backend_algorithm(algorithm)) as verifier:
        if len(public_key) != verifier.details["length_public_key"]:
            raise FormatError("Signature public key has an invalid length.")
        if len(signature_bytes) != verifier.details["length_signature"]:
            return False
        return bool(verifier.verify(message, signature_bytes, public_key))

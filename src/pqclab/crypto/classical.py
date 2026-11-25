"""Classical cryptographic primitives used by hybrid research profiles."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519

from pqclab.errors import CryptoFailure, FormatError

ECDHAlgorithm = Literal["X25519", "P-256"]


@dataclass(frozen=True, slots=True)
class ECDHKeyPair:
    algorithm: ECDHAlgorithm
    public_key: bytes
    private_key: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class RSAKeyPair:
    public_key: bytes
    private_key: bytes = field(repr=False)


def generate_ecdh_keypair(algorithm: ECDHAlgorithm = "X25519") -> ECDHKeyPair:
    if algorithm == "X25519":
        private = x25519.X25519PrivateKey.generate()
        public_bytes = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        private_bytes = private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        return ECDHKeyPair(algorithm, public_bytes, private_bytes)
    if algorithm == "P-256":
        private = ec.generate_private_key(ec.SECP256R1())
        public_bytes = private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        private_bytes = private.private_numbers().private_value.to_bytes(32, "big")
        return ECDHKeyPair(algorithm, public_bytes, private_bytes)
    raise FormatError(f"Unsupported ECDH algorithm: {algorithm}")


def ecdh_exchange(
    private_key: bytes,
    peer_public_key: bytes,
    algorithm: ECDHAlgorithm = "X25519",
) -> bytes:
    if not isinstance(private_key, bytes) or not isinstance(peer_public_key, bytes):
        raise FormatError("ECDH keys must be bytes.")
    try:
        if algorithm == "X25519":
            if len(private_key) != 32 or len(peer_public_key) != 32:
                raise FormatError("X25519 keys must be exactly 32 bytes.")
            private = x25519.X25519PrivateKey.from_private_bytes(private_key)
            peer = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
            return private.exchange(peer)
        if algorithm == "P-256":
            if len(private_key) != 32 or len(peer_public_key) != 65:
                raise FormatError("P-256 private/public keys must be 32/65 bytes.")
            private = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256R1())
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public_key)
            return private.exchange(ec.ECDH(), peer)
    except ValueError as exc:
        raise FormatError("ECDH key material is invalid.") from exc
    raise FormatError(f"Unsupported ECDH algorithm: {algorithm}")


def generate_rsa_keypair() -> RSAKeyPair:
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_bytes = private.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return RSAKeyPair(public_bytes, private_bytes)


def _load_rsa_public(public_key: bytes):
    try:
        key = serialization.load_der_public_key(public_key)
    except (TypeError, ValueError) as exc:
        raise FormatError("RSA public key is malformed.") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 3072:
        raise FormatError("Expected an RSA-3072 public key.")
    return key


def _load_rsa_private(private_key: bytes):
    try:
        key = serialization.load_der_private_key(private_key, password=None)
    except (TypeError, ValueError) as exc:
        raise FormatError("RSA private key is malformed.") from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 3072:
        raise FormatError("Expected an RSA-3072 private key.")
    return key


def rsa_oaep_encrypt(public_key: bytes, plaintext: bytes) -> bytes:
    if not isinstance(plaintext, bytes):
        raise FormatError("RSA plaintext must be bytes.")
    key = _load_rsa_public(public_key)
    try:
        return key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=b"pqclab/rsa-oaep/v1",
            ),
        )
    except ValueError as exc:
        raise FormatError("RSA-OAEP plaintext is too large for the selected key.") from exc


def rsa_oaep_decrypt(private_key: bytes, ciphertext: bytes) -> bytes:
    if not isinstance(ciphertext, bytes):
        raise FormatError("RSA ciphertext must be bytes.")
    key = _load_rsa_private(private_key)
    if len(ciphertext) != key.key_size // 8:
        raise FormatError("RSA-3072 ciphertext must be exactly 384 bytes.")
    try:
        return key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=b"pqclab/rsa-oaep/v1",
            ),
        )
    except ValueError as exc:
        raise CryptoFailure("RSA-OAEP decryption failed.") from exc


def rsa_pss_sign(private_key: bytes, message: bytes) -> bytes:
    if not isinstance(message, bytes):
        raise FormatError("RSA message must be bytes.")
    key = _load_rsa_private(private_key)
    return key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def rsa_pss_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if not isinstance(message, bytes) or not isinstance(signature, bytes):
        raise FormatError("RSA message and signature must be bytes.")
    key = _load_rsa_public(public_key)
    if len(signature) != key.key_size // 8:
        return False
    try:
        key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    return True


def ecdsa_p256_sign(private_key: bytes, message: bytes) -> bytes:
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise FormatError("P-256 private key must be exactly 32 bytes.")
    if not isinstance(message, bytes):
        raise FormatError("ECDSA message must be bytes.")
    try:
        key = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256R1())
    except ValueError as exc:
        raise FormatError("P-256 private key is invalid.") from exc
    return key.sign(message, ec.ECDSA(hashes.SHA256()))


def ecdsa_p256_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if not isinstance(public_key, bytes) or len(public_key) != 65:
        raise FormatError("P-256 public key must be exactly 65 bytes.")
    if not isinstance(message, bytes) or not isinstance(signature, bytes):
        raise FormatError("ECDSA message and signature must be bytes.")
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
        key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    except ValueError as exc:
        raise FormatError("P-256 public key is invalid.") from exc
    return True

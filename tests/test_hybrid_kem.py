import pytest

from pqclab.crypto.hybrid import (
    DEFAULT_HYBRID_KEM,
    HybridCiphertext,
    generate_hybrid_keypair,
    hybrid_decapsulate,
    hybrid_encapsulate,
)
from pqclab.errors import FormatError


def test_hybrid_kem_combines_ml_kem_and_x25519():
    recipient = generate_hybrid_keypair()
    ciphertext, sender_secret = hybrid_encapsulate(recipient.public_key, context=b"file:report.bin")
    receiver_secret = hybrid_decapsulate(recipient, ciphertext, context=b"file:report.bin")

    assert DEFAULT_HYBRID_KEM == "ML-KEM-768+X25519"
    assert len(sender_secret) == 32
    assert receiver_secret == sender_secret
    assert isinstance(ciphertext, HybridCiphertext)


def test_hybrid_kem_binds_context_and_transcript():
    recipient = generate_hybrid_keypair()
    ciphertext, sender_secret = hybrid_encapsulate(recipient.public_key, context=b"tenant-a")

    assert hybrid_decapsulate(recipient, ciphertext, context=b"tenant-a") == sender_secret
    assert hybrid_decapsulate(recipient, ciphertext, context=b"tenant-b") != sender_secret


def test_hybrid_kem_rejects_malformed_or_mismatched_inputs():
    recipient = generate_hybrid_keypair()
    ciphertext, _ = hybrid_encapsulate(recipient.public_key)

    with pytest.raises(FormatError):
        hybrid_decapsulate(recipient, ciphertext, context="not-bytes")
    with pytest.raises(FormatError):
        hybrid_decapsulate(
            recipient,
            HybridCiphertext(
                version=2,
                kem_algorithm=ciphertext.kem_algorithm,
                kem_ciphertext=ciphertext.kem_ciphertext,
                ephemeral_public_key=ciphertext.ephemeral_public_key,
            ),
        )
    with pytest.raises(FormatError):
        hybrid_encapsulate(
            type(recipient.public_key)(
                algorithm="ML-KEM-512",
                kem_public_key=recipient.public_key.kem_public_key,
                x25519_public_key=recipient.public_key.x25519_public_key,
            )
        )

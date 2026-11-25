import pytest

from pqclab.crypto.kem import (
    DEFAULT_KEM,
    KEM_ALGORITHMS,
    decapsulate,
    encapsulate,
    generate_kem_keypair,
)
from pqclab.crypto.signatures import (
    DEFAULT_SIGNATURE,
    SIGNATURE_ALGORITHMS,
    generate_signature_keypair,
    sign,
    verify,
)
from pqclab.errors import FormatError


def test_default_algorithm_profiles_are_allowlisted():
    assert DEFAULT_KEM == "ML-KEM-768"
    assert DEFAULT_SIGNATURE == "ML-DSA-65"
    assert set(KEM_ALGORITHMS) == {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}
    assert set(SIGNATURE_ALGORITHMS) == {
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "SLH-DSA-SHA2-128s",
        "SLH-DSA-SHA2-192s",
        "SLH-DSA-SHA2-256s",
    }


def test_ml_kem_round_trip_and_rejects_truncated_inputs():
    pair = generate_kem_keypair()
    ciphertext, sender_secret = encapsulate(pair.public_key)
    receiver_secret = decapsulate(pair.secret_key, ciphertext)

    assert len(sender_secret) == 32
    assert receiver_secret == sender_secret

    with pytest.raises(FormatError):
        encapsulate(pair.public_key[:-1])
    with pytest.raises(FormatError):
        decapsulate(pair.secret_key[:-1], ciphertext)
    with pytest.raises(FormatError):
        decapsulate(pair.secret_key, ciphertext[:-1])


def test_ml_dsa_sign_verify_and_tamper_rejection():
    pair = generate_signature_keypair()
    message = b"Post-quantum cryptography lab test vector"
    signature = sign(pair.secret_key, message)

    assert verify(pair.public_key, message, signature)
    assert not verify(pair.public_key, message + b"!", signature)
    assert not verify(pair.public_key, message, signature[:-1])

    with pytest.raises(FormatError):
        verify(pair.public_key[:-1], message, signature)
    with pytest.raises(FormatError):
        sign(pair.secret_key[:-1], message)


def test_unknown_algorithms_are_rejected():
    with pytest.raises(FormatError):
        generate_kem_keypair("Kyber768")
    with pytest.raises(FormatError):
        generate_signature_keypair("Dilithium3")


@pytest.mark.parametrize("algorithm", sorted(KEM_ALGORITHMS))
def test_all_enabled_kem_profiles_round_trip(algorithm):
    pair = generate_kem_keypair(algorithm)
    ciphertext, sender_secret = encapsulate(pair.public_key, algorithm)
    assert decapsulate(pair.secret_key, ciphertext, algorithm) == sender_secret


@pytest.mark.parametrize("algorithm", sorted(SIGNATURE_ALGORITHMS))
def test_all_enabled_signature_profiles_round_trip(algorithm):
    pair = generate_signature_keypair(algorithm)
    message = b"algorithm profile interoperability"
    signature = sign(pair.secret_key, message, algorithm)
    assert verify(pair.public_key, message, signature, algorithm)
    assert not verify(pair.public_key, message + b"!", signature, algorithm)

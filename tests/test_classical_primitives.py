import pytest

from pqclab.crypto.classical import (
    ecdh_exchange,
    generate_ecdh_keypair,
    generate_rsa_keypair,
    rsa_oaep_decrypt,
    rsa_oaep_encrypt,
    rsa_pss_sign,
    rsa_pss_verify,
)
from pqclab.errors import FormatError


@pytest.mark.parametrize("algorithm", ["X25519", "P-256"])
def test_ecdh_round_trip(algorithm):
    alice = generate_ecdh_keypair(algorithm)
    bob = generate_ecdh_keypair(algorithm)

    assert ecdh_exchange(alice.private_key, bob.public_key, algorithm) == ecdh_exchange(
        bob.private_key, alice.public_key, algorithm
    )


def test_ecdh_rejects_malformed_key_material():
    with pytest.raises(FormatError):
        ecdh_exchange(b"x", b"y", "X25519")


def test_rsa_3072_oaep_and_pss_round_trip():
    pair = generate_rsa_keypair()
    message = b"hybrid key establishment compatibility test"
    ciphertext = rsa_oaep_encrypt(pair.public_key, message)
    assert len(ciphertext) == 384
    assert rsa_oaep_decrypt(pair.private_key, ciphertext) == message

    signature = rsa_pss_sign(pair.private_key, message)
    assert rsa_pss_verify(pair.public_key, message, signature)
    assert not rsa_pss_verify(pair.public_key, message + b"!", signature)
    assert not rsa_pss_verify(pair.public_key, message, signature[:-1])


def test_rsa_oaep_rejects_malformed_ciphertext():
    pair = generate_rsa_keypair()
    with pytest.raises(FormatError):
        rsa_oaep_decrypt(pair.private_key, b"short")

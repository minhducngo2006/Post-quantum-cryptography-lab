import pytest

from pqclab.crypto.fingerprints import (
    fingerprint_matches,
    hybrid_kem_public_key_fingerprint,
    hybrid_signature_public_key_fingerprint,
)
from pqclab.crypto.hybrid import generate_hybrid_keypair
from pqclab.crypto.hybrid_signatures import generate_hybrid_signature_keypair
from pqclab.errors import FormatError


def test_hybrid_kem_public_key_fingerprint_detects_substitution():
    first = generate_hybrid_keypair()
    second = generate_hybrid_keypair()

    expected = hybrid_kem_public_key_fingerprint(first.public_key)
    assert hybrid_kem_public_key_fingerprint(first.public_key) == expected
    assert fingerprint_matches(expected, expected)
    assert not fingerprint_matches(expected, hybrid_kem_public_key_fingerprint(second.public_key))


def test_hybrid_signature_fingerprint_binds_both_public_components():
    first = generate_hybrid_signature_keypair()
    second = generate_hybrid_signature_keypair()

    expected = hybrid_signature_public_key_fingerprint(first.public_key)
    assert fingerprint_matches(expected, hybrid_signature_public_key_fingerprint(first.public_key))
    assert not fingerprint_matches(
        expected, hybrid_signature_public_key_fingerprint(second.public_key)
    )


@pytest.mark.parametrize("value", ["", "not-a-fingerprint", "0" * 63, "g" * 64])
def test_fingerprint_comparison_rejects_malformed_values(value):
    assert not fingerprint_matches(value, "0" * 64)
    assert not fingerprint_matches("0" * 64, value)


def test_fingerprint_rejects_malformed_public_key_objects():
    with pytest.raises(FormatError):
        hybrid_kem_public_key_fingerprint(object())
    with pytest.raises(FormatError):
        hybrid_signature_public_key_fingerprint(object())

from dataclasses import replace

import pytest

from pqclab.crypto.hybrid_signatures import (
    DEFAULT_HYBRID_SIGNATURE,
    generate_hybrid_signature_keypair,
    hybrid_sign,
    hybrid_verify,
)
from pqclab.errors import FormatError


def test_hybrid_signature_requires_both_algorithms():
    pair = generate_hybrid_signature_keypair()
    message = b"hybrid signature test"
    signature = hybrid_sign(pair, message, context=b"document-v1")

    assert DEFAULT_HYBRID_SIGNATURE == "ML-DSA-65+ECDSA-P256"
    assert hybrid_verify(pair.public_key, message, signature, context=b"document-v1")
    assert not hybrid_verify(pair.public_key, message + b"!", signature, context=b"document-v1")
    assert not hybrid_verify(pair.public_key, message, signature, context=b"document-v2")
    assert not hybrid_verify(pair.public_key, message, replace(signature, pq_signature=b"bad"))
    assert not hybrid_verify(
        pair.public_key, message, replace(signature, classical_signature=b"bad")
    )


def test_hybrid_signature_rejects_unsupported_version():
    pair = generate_hybrid_signature_keypair()
    signature = hybrid_sign(pair, b"message")
    with pytest.raises(FormatError):
        hybrid_verify(pair.public_key, b"message", replace(signature, version=2))

from io import BytesIO

import pytest

from pqclab.crypto.streaming import (
    CHUNK_SIZE,
    decrypt_file,
    decrypt_stream,
    encrypt_file,
    encrypt_stream,
)
from pqclab.errors import CryptoFailure, FormatError, OutputExists

KEY = bytes(range(32))


def round_trip(data, *, context=b"", chunk_size=64):
    encrypted = BytesIO()
    encrypted_stats = encrypt_stream(
        BytesIO(data), encrypted, KEY, associated_data=context, chunk_size=chunk_size
    )
    ciphertext = encrypted.getvalue()
    plaintext = BytesIO()
    decrypted_stats = decrypt_stream(BytesIO(ciphertext), plaintext, KEY, associated_data=context)
    assert plaintext.getvalue() == data
    assert encrypted_stats.plaintext_bytes == len(data)
    assert decrypted_stats.plaintext_bytes == len(data)
    return ciphertext


@pytest.mark.parametrize("data", [b"", b"a", b"x" * 64, b"x" * 65, b"x" * 193])
def test_streaming_round_trip_boundaries(data):
    round_trip(data)


def test_streaming_context_binding_and_tamper_detection():
    ciphertext = round_trip(b"payload" * 30, context=b"object:abc")
    with pytest.raises(CryptoFailure):
        decrypt_stream(BytesIO(ciphertext), BytesIO(), KEY, associated_data=b"object:xyz")

    changed = bytearray(ciphertext)
    changed[36 + 10] ^= 1
    with pytest.raises(CryptoFailure):
        decrypt_stream(BytesIO(changed), BytesIO(), KEY, associated_data=b"object:abc")


def test_streaming_rejects_truncation_and_trailing_bytes_without_publishing():
    ciphertext = round_trip(b"payload" * 40)
    destination = BytesIO(b"existing")
    destination.seek(0, 2)
    with pytest.raises(FormatError):
        decrypt_stream(BytesIO(ciphertext[:-5]), destination, KEY)
    assert destination.getvalue() == b"existing"

    with pytest.raises(FormatError):
        decrypt_stream(BytesIO(ciphertext + b"extra"), BytesIO(), KEY)


def test_streaming_enforces_maximum_and_chunk_bounds():
    with pytest.raises(FormatError):
        encrypt_stream(BytesIO(b"12345"), BytesIO(), KEY, chunk_size=64, max_bytes=4)
    with pytest.raises(FormatError):
        encrypt_stream(BytesIO(b"data"), BytesIO(), KEY, chunk_size=CHUNK_SIZE + 1)
    with pytest.raises(FormatError):
        encrypt_stream(BytesIO(b"data"), BytesIO(), b"short")


def test_streaming_file_api_is_atomic_private_and_no_overwrite(tmp_path):
    source = tmp_path / "plain.bin"
    encrypted = tmp_path / "data.pqc"
    decrypted = tmp_path / "roundtrip.bin"
    source.write_bytes(b"streamed payload" * 100)

    encrypt_file(source, encrypted, KEY, associated_data=b"file-id", chunk_size=128)
    assert encrypted.stat().st_mode & 0o777 == 0o600
    decrypt_file(encrypted, decrypted, KEY, associated_data=b"file-id")
    assert decrypted.read_bytes() == source.read_bytes()

    with pytest.raises(OutputExists):
        encrypt_file(source, encrypted, KEY, chunk_size=128)

    corrupted = bytearray(encrypted.read_bytes())
    corrupted[-20] ^= 1
    encrypted.write_bytes(corrupted)
    failed_output = tmp_path / "must-not-exist.bin"
    with pytest.raises((CryptoFailure, FormatError)):
        decrypt_file(encrypted, failed_output, KEY, associated_data=b"file-id")
    assert not failed_output.exists()

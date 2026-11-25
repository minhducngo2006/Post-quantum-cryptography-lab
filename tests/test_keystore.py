import pytest

from pqclab.crypto.keystore import (
    decrypt_private_key,
    encrypt_private_key,
    load_private_key,
    save_private_key,
)
from pqclab.errors import CryptoFailure, FormatError, OutputExists


def test_private_key_encryption_round_trip_and_context_binding():
    private_material = b"private-key-material\x00with-binary"
    encrypted = encrypt_private_key(
        private_material, b"correct horse battery staple", associated_data=b"key-id:alpha"
    )

    assert encrypted != private_material
    assert (
        decrypt_private_key(
            encrypted, b"correct horse battery staple", associated_data=b"key-id:alpha"
        )
        == private_material
    )
    with pytest.raises(CryptoFailure):
        decrypt_private_key(encrypted, b"wrong passphrase", associated_data=b"key-id:alpha")
    with pytest.raises(CryptoFailure):
        decrypt_private_key(
            encrypted, b"correct horse battery staple", associated_data=b"key-id:beta"
        )


def test_private_key_envelope_rejects_tampering_and_truncation():
    encrypted = encrypt_private_key(b"secret", b"passphrase")
    changed = encrypted[:-1] + bytes([encrypted[-1] ^ 1])

    with pytest.raises(CryptoFailure):
        decrypt_private_key(changed, b"passphrase")
    with pytest.raises(FormatError):
        decrypt_private_key(encrypted[:10], b"passphrase")
    with pytest.raises(FormatError):
        decrypt_private_key(b"BADMAGIC" + encrypted[8:], b"passphrase")


def test_private_key_envelope_rejects_invalid_parameters():
    with pytest.raises(FormatError):
        encrypt_private_key(b"", b"")
    with pytest.raises(FormatError):
        encrypt_private_key("secret", b"passphrase")
    with pytest.raises(FormatError):
        decrypt_private_key(b"", b"passphrase")


def test_private_key_file_is_owner_only_and_never_overwritten(tmp_path):
    path = tmp_path / "identity.pqkey"
    save_private_key(path, b"private-key", b"strong passphrase")
    assert path.stat().st_mode & 0o777 == 0o600
    assert load_private_key(path, b"strong passphrase") == b"private-key"
    with pytest.raises(OutputExists):
        save_private_key(path, b"replacement", b"strong passphrase")
    assert load_private_key(path, b"strong passphrase") == b"private-key"


def test_private_key_loader_rejects_symlinks_and_weak_permissions(tmp_path):
    real = tmp_path / "real.pqkey"
    save_private_key(real, b"private-key", b"strong passphrase")
    link = tmp_path / "linked.pqkey"
    link.symlink_to(real)
    with pytest.raises(FormatError):
        load_private_key(link, b"strong passphrase")

    real.chmod(0o644)
    with pytest.raises(FormatError):
        load_private_key(real, b"strong passphrase")

import os
import stat
from types import SimpleNamespace

import pytest

from pqclab import file_security
from pqclab.errors import FormatError


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode-bit test")
def test_posix_private_file_permissions_and_open(tmp_path):
    path = tmp_path / "private.bin"
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o666)
    try:
        file_security.secure_private_file(descriptor, path)
        os.write(descriptor, b"encrypted")
    finally:
        os.close(descriptor)

    metadata = path.lstat()
    file_security.verify_private_file(path, metadata)
    opened = file_security.open_private_file(path, metadata)
    try:
        assert os.read(opened, 9) == b"encrypted"
    finally:
        os.close(opened)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink test")
def test_posix_private_file_rejects_symlinks(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"data")
    link = tmp_path / "link.bin"
    link.symlink_to(target)
    with pytest.raises(FormatError):
        file_security.verify_private_file(link, link.lstat())


def test_windows_acl_is_replaced_with_current_user_only(tmp_path, monkeypatch):
    path = tmp_path / "private.bin"
    path.write_bytes(b"encrypted")
    calls = []

    def fake_run(arguments, **kwargs):
        calls.append(arguments)
        if arguments[0] == "whoami":
            return SimpleNamespace(stdout='"DOMAIN\\user","S-1-5-21-123-456-789-1001"\n')
        if "/grant:r" in arguments:
            return SimpleNamespace(stdout="processed")
        return SimpleNamespace(stdout=f"{path} DOMAIN\\user:(F)\n")

    monkeypatch.setattr(file_security.subprocess, "run", fake_run)
    monkeypatch.setattr(file_security.os, "name", "nt")
    file_security.secure_private_file(1, path)

    grant_call = next(call for call in calls if "/grant:r" in call)
    assert "/inheritance:r" in grant_call
    assert "*S-1-5-21-123-456-789-1001:(F)" in grant_call


def test_windows_acl_verification_rejects_additional_principals(tmp_path, monkeypatch):
    path = tmp_path / "private.bin"
    path.write_bytes(b"encrypted")

    def fake_run(arguments, **kwargs):
        if arguments[0] == "whoami":
            return SimpleNamespace(stdout='"DOMAIN\\user","S-1-5-21-123-456-789-1001"\n')
        if arguments[0] == "icacls":
            return SimpleNamespace(stdout=(f"{path} DOMAIN\\user:(F)\n{path} Everyone:(F)\n"))
        raise AssertionError("Unexpected command")

    monkeypatch.setattr(file_security.subprocess, "run", fake_run)
    monkeypatch.setattr(file_security.os, "name", "nt")
    with pytest.raises(FormatError):
        file_security.verify_private_file(
            path,
            SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0),
        )


def test_windows_reparse_points_are_rejected(tmp_path, monkeypatch):
    path = tmp_path / "reparse.bin"
    path.write_bytes(b"data")
    monkeypatch.setattr(file_security.os, "name", "nt")
    with pytest.raises(FormatError):
        file_security.verify_private_file(
            path,
            SimpleNamespace(
                st_mode=stat.S_IFREG,
                st_file_attributes=getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
            ),
        )

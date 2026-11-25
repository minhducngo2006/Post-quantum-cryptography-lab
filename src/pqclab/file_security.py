"""Cross-platform owner-only file permissions and safe no-follow opens."""

from __future__ import annotations

import csv
import io
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

from pqclab.errors import FormatError


def _windows_identity() -> tuple[str, str]:
    try:
        result = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FormatError("Could not identify the current Windows security principal.") from exc
    rows = list(csv.reader(io.StringIO(result.stdout)))
    if not rows or len(rows[0]) < 2:
        raise FormatError("Windows did not return the current user SID.")
    account, sid = rows[0][0].strip(), rows[0][1].strip()
    if not account or not sid.startswith("S-1-"):
        raise FormatError("Windows returned an invalid current user identity.")
    return account, sid


def _verify_windows_owner_acl(
    path: str | Path,
    *,
    account: str | None = None,
    sid: str | None = None,
) -> None:
    if account is None or sid is None:
        account, sid = _windows_identity()
    try:
        result = subprocess.run(
            ["icacls", str(path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FormatError("Could not verify the Windows private-file ACL.") from exc

    ace_lines = [line.strip() for line in result.stdout.splitlines() if ":(" in line]
    if len(ace_lines) != 1:
        raise FormatError("Windows private file must have exactly one explicit ACL entry.")
    ace = ace_lines[0]
    normalized_ace = ace.casefold()
    identity_matches = (
        f"{account.casefold()}:(" in normalized_ace or f"*{sid.casefold()}:(" in normalized_ace
    )
    inheritance_flags = ("(I)", "(OI)", "(CI)", "(IO)", "(NP)")
    if not identity_matches or "(F)" not in ace or any(flag in ace for flag in inheritance_flags):
        raise FormatError("Windows private file ACL must grant only current-user full control.")


def _set_windows_owner_acl(path: str | Path) -> None:
    account, sid = _windows_identity()
    try:
        subprocess.run(
            [
                "icacls",
                str(path),
                "/inheritance:r",
                "/grant:r",
                f"*{sid}:(F)",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FormatError("Could not restrict the Windows private-file ACL.") from exc
    _verify_windows_owner_acl(path, account=account, sid=sid)


def secure_private_file(descriptor: int, path: str | Path) -> None:
    """Restrict a newly created file before any plaintext is written to it."""
    if os.name == "nt":
        _set_windows_owner_acl(path)
    else:
        os.fchmod(descriptor, 0o600)


def _is_reparse_point(metadata: Any) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def verify_private_file(path: str | Path, metadata: Any) -> None:
    """Require a regular file with owner-only POSIX mode or a current-user-only Windows DACL."""
    if not stat.S_ISREG(metadata.st_mode) or (os.name == "nt" and _is_reparse_point(metadata)):
        raise FormatError("Private key file must be a regular non-reparse file.")
    if os.name == "nt":
        _verify_windows_owner_acl(path)
    elif metadata.st_mode & 0o077:
        raise FormatError("Private key file must be accessible only by its owner.")


def open_private_file(path: str | Path, metadata: Any) -> int:
    """Open without following links and verify the opened file is the inspected file."""
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOINHERIT", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise FormatError("Private key file could not be opened safely.") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise FormatError("Opened private key is not a regular file.")
        if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
            raise FormatError("Private key file changed while it was being opened.")
        verify_private_file(path, opened)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def fsync_directory(path: str | Path) -> None:
    """Persist directory metadata where the platform exposes directory fsync."""
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

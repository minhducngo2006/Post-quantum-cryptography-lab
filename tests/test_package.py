import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "pqclab.cli", *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_package_import():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import pqclab; assert 'oqs' not in sys.modules",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_cli_help():
    result = run_cli("--help")
    assert result.returncode == 0
    assert "doctor" in result.stdout
    assert not result.stderr


def test_usage_exit():
    result = run_cli("unknown-command")
    assert result.returncode == 2
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    "path",
    ["secret.pqkey", "output.pqc", "scratch.tmp", "benchmark-results/raw.csv", ".venv/bin/python"],
)
def test_sensitive_artifacts_ignored(path):
    result = subprocess.run(
        ["git", "check-ignore", "--quiet", "--no-index", path],
        check=False,
        cwd=ROOT,
        env=os.environ.copy(),
        timeout=10,
    )
    assert result.returncode == 0


def test_public_error_contract():
    from pqclab.errors import (
        BackendUnavailable,
        Cancelled,
        CryptoFailure,
        FormatError,
        LabError,
        OutputExists,
    )

    for cls in (BackendUnavailable, Cancelled, CryptoFailure, FormatError, OutputExists):
        assert isinstance(cls("failure"), LabError)


def test_crypto_import_does_not_load_native_wrapper():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import pqclab.crypto; assert 'oqs' not in sys.modules",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr

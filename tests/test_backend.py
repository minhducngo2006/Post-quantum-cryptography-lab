import ctypes
import importlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from pqclab.errors import BackendUnavailable

ROOT = Path(__file__).resolve().parents[1]


def test_backend_module_is_available():
    assert importlib.util.find_spec("pqclab.backend") is not None


@pytest.fixture
def backend():
    return pytest.importorskip("pqclab.backend")


def _probe(native_version="0.16.0", *, kems=None, signatures=None):
    return SimpleNamespace(
        version=native_version,
        enabled_kems=frozenset(kems if kems is not None else {"ML-KEM-768"}),
        enabled_signatures=frozenset(signatures if signatures is not None else {"ML-DSA-65"}),
    )


def _versions(*, native_wrapper="0.16.0.2", pyca="50.0.2"):
    versions = {
        "liboqs-python": native_wrapper,
        "cryptography": pyca,
    }
    return lambda name: versions[name]


def test_missing_library_no_network(backend, tmp_path):
    child = """
import json
import socket
import subprocess
import sys

def forbidden(*args, **kwargs):
    raise AssertionError("backend preflight attempted network or process execution")

socket.socket.connect = forbidden
socket.create_connection = forbidden
subprocess.run = forbidden

from pqclab.backend import doctor, require_backend
from pqclab.errors import BackendUnavailable

report = doctor()
assert report.status == "unavailable", report
try:
    require_backend()
except BackendUnavailable:
    pass
else:
    raise AssertionError("missing native library must fail before oqs import")
assert "oqs" not in sys.modules
print(json.dumps(report.to_dict()))
"""
    env = os.environ.copy()
    env["OQS_INSTALL_PATH"] = str(tmp_path)
    env["PYTHONPATH"] = str(ROOT / "src")
    result = subprocess.run(
        [sys.executable, "-c", child],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "unavailable"
    assert "liboqs shared library" in report["missing_required"]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("native_version", "wrapper_version", "expected"),
    [
        ("0.15.0", "0.16.0.2", "liboqs==0.16.0"),
        ("0.16.0", "0.16.0.1", "liboqs-python==0.16.0.2"),
    ],
)
def test_version_mismatch(backend, monkeypatch, native_version, wrapper_version, expected):
    monkeypatch.setattr(backend, "_probe_native", lambda: _probe(native_version))
    monkeypatch.setattr(
        backend,
        "_installed_version",
        _versions(native_wrapper=wrapper_version),
    )

    report = backend.doctor()

    assert report.status == "incompatible"
    assert any(expected in item for item in report.missing_required)


def test_missing_default(backend, monkeypatch, capsys):
    from pqclab import cli

    monkeypatch.setattr(
        backend,
        "_probe_native",
        lambda: _probe(kems=set(), signatures={"ML-DSA-65"}),
    )
    monkeypatch.setattr(backend, "_installed_version", _versions())
    report = backend.doctor()
    monkeypatch.setattr(cli, "doctor", lambda: report)

    assert report.status == "incompatible"
    assert "ML-KEM-768" in report.missing_required
    assert cli.main(["doctor"]) == 1
    assert "ML-KEM-768" in capsys.readouterr().err


def test_missing_optional_reported(backend, monkeypatch):
    monkeypatch.setattr(backend, "_probe_native", _probe)
    monkeypatch.setattr(backend, "_installed_version", _versions())

    report = backend.doctor()

    assert report.status == "ready"
    assert "ML-KEM-512" in report.missing_optional
    assert "ML-KEM-1024" in report.missing_optional
    assert "ML-DSA-44" in report.missing_optional
    assert "ML-DSA-87" in report.missing_optional
    assert "SLH-DSA-SHA2-128s" in report.missing_optional


def test_doctor_actual_native(backend):
    report = backend.doctor()

    assert report.status == "ready"
    assert report.native_version == "0.16.0"
    assert report.wrapper_version == "0.16.0.2"
    assert report.pyca_version == "50.0.2"
    assert "ML-KEM-768" in report.enabled_kems
    assert "ML-DSA-65" in report.enabled_signatures
    assert not report.missing_optional


def test_native_build_matches_algorithm_allowlist(backend):
    report = backend.doctor()
    assert report.status == "ready"
    assert set(report.enabled_kems) == {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}
    assert set(report.enabled_signatures) == {
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "SLH-DSA-SHA2-128s",
        "SLH-DSA-SHA2-192s",
        "SLH-DSA-SHA2-256s",
    }

    library = ctypes.CDLL(str(backend._native_library_path()))
    is_kem_enabled = library.OQS_KEM_alg_is_enabled
    is_kem_enabled.argtypes = [ctypes.c_char_p]
    is_kem_enabled.restype = ctypes.c_int
    is_sig_enabled = library.OQS_SIG_alg_is_enabled
    is_sig_enabled.argtypes = [ctypes.c_char_p]
    is_sig_enabled.restype = ctypes.c_int

    assert is_sig_enabled(b"SLH_DSA_PURE_SHA2_128S")
    assert is_sig_enabled(b"SLH_DSA_PURE_SHA2_192S")
    assert is_sig_enabled(b"SLH_DSA_PURE_SHA2_256S")
    assert not is_kem_enabled(b"NTRU-HPS-2048-509")
    assert not is_sig_enabled(b"Falcon-512")

    is_stateful_enabled = library.OQS_SIG_STFL_alg_is_enabled
    is_stateful_enabled.argtypes = [ctypes.c_char_p]
    is_stateful_enabled.restype = ctypes.c_int
    assert not is_stateful_enabled(b"LMS_SHA256_H5_W1")
    assert not is_stateful_enabled(b"XMSS-SHA2_10_256")


def test_require_backend_rejects_missing(backend, monkeypatch, tmp_path):
    monkeypatch.setenv("OQS_INSTALL_PATH", str(tmp_path))

    with pytest.raises(BackendUnavailable):
        backend.require_backend()

    assert "oqs" not in sys.modules
    assert list(tmp_path.iterdir()) == []


def test_require_backend_imports_only_after_preflight(backend, monkeypatch):
    if backend.doctor().status != "ready":
        pytest.skip("real pinned native backend is not provisioned")

    def forbidden(*args, **kwargs):
        raise AssertionError("native wrapper import attempted subprocess execution")

    monkeypatch.setattr(subprocess, "run", forbidden)
    assert "oqs" not in sys.modules
    backend.require_backend()
    oqs = importlib.import_module("oqs")

    assert oqs.oqs_version() == "0.16.0"
    assert oqs.oqs_python_version() == "0.16.0.2"
    assert "ML-KEM-768" in oqs.get_enabled_kem_mechanisms()
    assert "ML-DSA-65" in oqs.get_enabled_sig_mechanisms()
    assert "SLH_DSA_PURE_SHA2_128S" in oqs.get_enabled_sig_mechanisms()


def test_require_backend_rejects_missing_default(backend, monkeypatch):
    monkeypatch.setattr(backend, "_OQS_MODULE", None)
    monkeypatch.delitem(sys.modules, "oqs", raising=False)
    monkeypatch.setattr(
        backend,
        "_probe_native",
        lambda: _probe(kems=set(), signatures={"ML-DSA-65"}),
    )
    monkeypatch.setattr(backend, "_installed_version", _versions())

    with pytest.raises(BackendUnavailable):
        backend.require_backend()

    assert "oqs" not in sys.modules


def test_doctor_report_is_redacted(backend, monkeypatch):
    monkeypatch.setattr(backend, "_probe_native", _probe)
    monkeypatch.setattr(backend, "_installed_version", _versions())

    rendered = repr(backend.doctor())

    assert "passphrase" not in rendered.lower()
    assert "secret_key" not in rendered.lower()
    assert "private_key" not in rendered.lower()


def test_native_library_candidates_cover_windows_wrapper_layout(backend, tmp_path, monkeypatch):
    candidates = backend._native_library_candidates(tmp_path, "win32")
    assert candidates == (
        tmp_path / "bin" / "oqs.dll",
        tmp_path / "bin" / "liboqs.dll",
        tmp_path / "lib" / "oqs.dll",
        tmp_path / "lib" / "liboqs.dll",
    )

    candidates[1].parent.mkdir(parents=True)
    candidates[1].touch()
    monkeypatch.setattr(backend, "_install_prefix", lambda: tmp_path)
    monkeypatch.setattr(backend.sys, "platform", "win32")
    assert backend._native_library_path() == candidates[1]


def test_native_library_candidates_cover_macos_layout(backend, tmp_path):
    assert backend._native_library_candidates(tmp_path, "darwin") == (
        tmp_path / "lib" / "liboqs.dylib",
        tmp_path / "lib64" / "liboqs.dylib",
    )

"""Fail-closed native backend preflight for the explicitly provisioned liboqs."""

from __future__ import annotations

import ctypes
import ctypes.util
import importlib
import importlib.metadata
import os
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .errors import BackendUnavailable

EXPECTED_NATIVE_VERSION = "0.16.0"
EXPECTED_WRAPPER_VERSION = "0.16.0.2"
EXPECTED_PYCA_VERSION = "50.0.2"

REQUIRED_KEMS = ("ML-KEM-768",)
REQUIRED_SIGNATURES = ("ML-DSA-65",)
OPTIONAL_KEMS = ("ML-KEM-512", "ML-KEM-1024")
OPTIONAL_SIGNATURES = (
    "ML-DSA-44",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-256s",
)
SIGNATURE_BACKEND_IDS = {
    "SLH-DSA-SHA2-128s": "SLH_DSA_PURE_SHA2_128S",
    "SLH-DSA-SHA2-192s": "SLH_DSA_PURE_SHA2_192S",
    "SLH-DSA-SHA2-256s": "SLH_DSA_PURE_SHA2_256S",
}

_IMPORT_LOCK = threading.Lock()
_OQS_MODULE: Any | None = None


@dataclass(frozen=True, slots=True)
class DoctorReport:
    status: str
    python_version: str
    native_version: str | None
    wrapper_version: str | None
    pyca_version: str | None
    openssl_version: str | None
    enabled_kems: tuple[str, ...]
    enabled_signatures: tuple[str, ...]
    missing_required: tuple[str, ...]
    missing_optional: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class _NativeProbe:
    version: str
    enabled_kems: frozenset[str]
    enabled_signatures: frozenset[str]


def _install_prefix() -> Path:
    configured = os.environ.get("OQS_INSTALL_PATH")
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parents[2] / ".native" / "liboqs"


def _native_library_path() -> Path | None:
    prefix = _install_prefix()
    for directory in ("lib", "lib64"):
        candidate = prefix / directory / "liboqs.so"
        if candidate.is_file():
            return candidate
    return None


def _enabled(library: ctypes.CDLL, symbol: str, algorithm: str) -> bool:
    function = getattr(library, symbol)
    function.argtypes = [ctypes.c_char_p]
    function.restype = ctypes.c_int
    return bool(function(algorithm.encode("ascii")))


def _probe_native() -> _NativeProbe | None:
    path = _native_library_path()
    if path is None:
        return None
    try:
        library = ctypes.CDLL(str(path))
        version_function = library.OQS_version
        version_function.argtypes = []
        version_function.restype = ctypes.c_char_p
        version_bytes = version_function()
        if not version_bytes:
            return None
        version = version_bytes.decode("ascii")
        all_kems = REQUIRED_KEMS + OPTIONAL_KEMS
        all_signatures = REQUIRED_SIGNATURES + OPTIONAL_SIGNATURES
        enabled_kems = frozenset(
            name for name in all_kems if _enabled(library, "OQS_KEM_alg_is_enabled", name)
        )
        enabled_signatures = frozenset(
            name
            for name in all_signatures
            if _enabled(
                library,
                "OQS_SIG_alg_is_enabled",
                SIGNATURE_BACKEND_IDS.get(name, name),
            )
        )
        return _NativeProbe(version, enabled_kems, enabled_signatures)
    except (AttributeError, OSError, UnicodeDecodeError):
        return None


def _installed_version(distribution: str) -> str | None:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return None


def _openssl_version() -> str | None:
    try:
        from cryptography.hazmat.backends.openssl.backend import backend

        return backend.openssl_version_text()
    except (AttributeError, ImportError, OSError, RuntimeError):
        return None


def doctor() -> DoctorReport:
    """Inspect versions and enabled algorithms without importing the auto-installing wrapper."""
    native = _probe_native()
    wrapper_version = _installed_version("liboqs-python")
    pyca_version = _installed_version("cryptography")
    openssl_version = _openssl_version() if pyca_version else None
    python_version = ".".join(str(part) for part in sys.version_info[:3])

    missing_required: list[str] = []
    if sys.version_info[:2] != (3, 12):
        missing_required.append("Python 3.12")
    if native is None:
        missing_required.append("liboqs shared library")
    elif native.version != EXPECTED_NATIVE_VERSION:
        missing_required.append(f"liboqs=={EXPECTED_NATIVE_VERSION} (found {native.version})")
    if wrapper_version != EXPECTED_WRAPPER_VERSION:
        missing_required.append(
            f"liboqs-python=={EXPECTED_WRAPPER_VERSION} "
            f"(found {wrapper_version or 'not installed'})"
        )
    if pyca_version != EXPECTED_PYCA_VERSION:
        missing_required.append(
            f"cryptography=={EXPECTED_PYCA_VERSION} (found {pyca_version or 'not installed'})"
        )
    if pyca_version and openssl_version is None:
        missing_required.append("cryptography OpenSSL backend")

    enabled_kems = native.enabled_kems if native else frozenset()
    enabled_signatures = native.enabled_signatures if native else frozenset()
    for name in REQUIRED_KEMS:
        if name not in enabled_kems:
            missing_required.append(name)
    for name in REQUIRED_SIGNATURES:
        if name not in enabled_signatures:
            missing_required.append(name)

    missing_optional = tuple(
        sorted(
            (set(OPTIONAL_KEMS) - set(enabled_kems))
            | (set(OPTIONAL_SIGNATURES) - set(enabled_signatures))
        )
    )
    status = "unavailable" if native is None else "incompatible" if missing_required else "ready"
    return DoctorReport(
        status=status,
        python_version=python_version,
        native_version=native.version if native else None,
        wrapper_version=wrapper_version,
        pyca_version=pyca_version,
        openssl_version=openssl_version,
        enabled_kems=tuple(sorted(enabled_kems)),
        enabled_signatures=tuple(sorted(enabled_signatures)),
        missing_required=tuple(missing_required),
        missing_optional=missing_optional,
    )


def require_backend() -> None:
    """Load liboqs-python only after proving the pinned native library is already present."""
    global _OQS_MODULE
    if _OQS_MODULE is not None:
        return

    with _IMPORT_LOCK:
        if _OQS_MODULE is not None:
            return
        report = doctor()
        if report.status != "ready":
            details = ", ".join(report.missing_required) or "native backend unavailable"
            raise BackendUnavailable(f"Required PQC backend is not ready: {details}")

        prefix = _install_prefix().resolve()
        previous_install_path = os.environ.get("OQS_INSTALL_PATH")
        original_find_library = ctypes.util.find_library
        original_run = subprocess.run
        original_sleep = time.sleep
        importer_thread = threading.get_ident()

        def find_only_provisioned_oqs(name: str) -> str | None:
            if threading.get_ident() == importer_thread and name in {"oqs", "liboqs"}:
                return None
            return original_find_library(name)

        def reject_automatic_provisioning(*args: Any, **kwargs: Any) -> Any:
            if threading.get_ident() == importer_thread:
                raise RuntimeError("Automatic native provisioning is disabled")
            return original_run(*args, **kwargs)

        def reject_install_countdown(*args: Any, **kwargs: Any) -> Any:
            if threading.get_ident() == importer_thread:
                raise RuntimeError("Automatic native provisioning is disabled")
            return original_sleep(*args, **kwargs)

        try:
            os.environ["OQS_INSTALL_PATH"] = str(prefix)
            ctypes.util.find_library = find_only_provisioned_oqs
            subprocess.run = reject_automatic_provisioning
            time.sleep = reject_install_countdown
            module = importlib.import_module("oqs")
        except (Exception, SystemExit) as exc:
            sys.modules.pop("oqs", None)
            sys.modules.pop("oqs.oqs", None)
            raise BackendUnavailable(
                "The pre-provisioned liboqs library could not be loaded; "
                "automatic download and build are disabled."
            ) from exc
        finally:
            ctypes.util.find_library = original_find_library
            subprocess.run = original_run
            time.sleep = original_sleep
            if previous_install_path is None:
                os.environ.pop("OQS_INSTALL_PATH", None)
            else:
                os.environ["OQS_INSTALL_PATH"] = previous_install_path

        if module.oqs_version() != EXPECTED_NATIVE_VERSION:
            raise BackendUnavailable("Loaded liboqs version does not match the pinned release.")
        if module.oqs_python_version() != EXPECTED_WRAPPER_VERSION:
            raise BackendUnavailable(
                "Loaded liboqs-python version does not match the pinned release."
            )

        library_name = getattr(module.native(), "_name", "")
        expected_library = _native_library_path()
        if not expected_library or Path(str(library_name)).resolve() != expected_library.resolve():
            raise BackendUnavailable(
                "liboqs-python did not load the explicitly provisioned library."
            )

        enabled_kems = set(module.get_enabled_kem_mechanisms())
        enabled_signatures = set(module.get_enabled_sig_mechanisms())
        if not set(REQUIRED_KEMS).issubset(enabled_kems):
            raise BackendUnavailable("The loaded native library lacks the required ML-KEM profile.")
        if not set(REQUIRED_SIGNATURES).issubset(enabled_signatures):
            raise BackendUnavailable("The loaded native library lacks the required ML-DSA profile.")

        _OQS_MODULE = module

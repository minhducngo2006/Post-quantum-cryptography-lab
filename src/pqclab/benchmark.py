"""Reproducible benchmark runner using measured native cryptographic operations."""

from __future__ import annotations

import csv
import json
import platform
import re
import statistics
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from pqclab.backend import doctor, require_backend
from pqclab.crypto.kem import DEFAULT_KEM, decapsulate, encapsulate, generate_kem_keypair
from pqclab.crypto.signatures import (
    DEFAULT_SIGNATURE,
    generate_signature_keypair,
    sign,
    verify,
)
from pqclab.errors import BackendUnavailable, FormatError


@dataclass(frozen=True, slots=True)
class BenchmarkMetric:
    operation: str
    algorithm: str
    samples_ns: tuple[int, ...]
    mean_latency_ms: float
    median_latency_ms: float
    ops_per_second: float
    bytes_per_second: float | None
    message_bytes: int
    public_key_bytes: int
    secret_key_bytes: int
    ciphertext_bytes: int
    signature_bytes: int


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    run_id: str
    created_at: str
    iterations: int
    python_version: str
    platform_description: str
    machine: str
    processor: str
    native_version: str
    wrapper_version: str
    cryptography_version: str
    metrics: tuple[BenchmarkMetric, ...]

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "run_id": self.run_id,
            "created_at": self.created_at,
            "iterations": self.iterations,
            "environment": {
                "python": self.python_version,
                "platform": self.platform_description,
                "machine": self.machine,
                "processor": self.processor,
                "liboqs": self.native_version,
                "liboqs_python": self.wrapper_version,
                "cryptography": self.cryptography_version,
            },
            "metrics": [asdict(metric) for metric in self.metrics],
        }


@dataclass(frozen=True, slots=True)
class BenchmarkOutput:
    directory: Path
    json_path: Path
    csv_path: Path
    chart_path: Path


def _measure[T](operation: Callable[[], T], iterations: int) -> tuple[tuple[int, ...], T]:
    samples: list[int] = []
    last_result: T
    for _ in range(iterations):
        started = time.perf_counter_ns()
        last_result = operation()
        samples.append(time.perf_counter_ns() - started)
    return tuple(samples), last_result


def _metric(
    operation: str,
    algorithm: str,
    samples: tuple[int, ...],
    *,
    message_bytes: int = 0,
    public_key_bytes: int = 0,
    secret_key_bytes: int = 0,
    ciphertext_bytes: int = 0,
    signature_bytes: int = 0,
) -> BenchmarkMetric:
    mean_ns = statistics.fmean(samples)
    return BenchmarkMetric(
        operation=operation,
        algorithm=algorithm,
        samples_ns=samples,
        mean_latency_ms=mean_ns / 1_000_000,
        median_latency_ms=statistics.median(samples) / 1_000_000,
        ops_per_second=1_000_000_000 / mean_ns,
        bytes_per_second=(message_bytes * 1_000_000_000 / mean_ns) if message_bytes else None,
        message_bytes=message_bytes,
        public_key_bytes=public_key_bytes,
        secret_key_bytes=secret_key_bytes,
        ciphertext_bytes=ciphertext_bytes,
        signature_bytes=signature_bytes,
    )


def _processor_description() -> str:
    processor = platform.processor() or platform.uname().processor
    if processor or platform.system().lower() != "linux":
        return processor
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as cpuinfo:
            for line in cpuinfo:
                if line.lower().startswith("model name"):
                    return line.partition(":")[2].strip()
    except OSError:
        pass
    return ""


def run_benchmarks(*, iterations: int, message: bytes) -> BenchmarkResult:
    """Measure the approved default ML-KEM/ML-DSA workload using real operations only."""
    if (
        not isinstance(iterations, int)
        or isinstance(iterations, bool)
        or not 1 <= iterations <= 10_000
    ):
        raise FormatError("Benchmark iterations must be between 1 and 10000.")
    if not isinstance(message, bytes) or not message:
        raise FormatError("Benchmark message must be non-empty bytes.")

    report = doctor()
    if report.status != "ready":
        raise BackendUnavailable("Pinned native cryptographic backend is not ready.")
    require_backend()

    kem_samples, kem_pair = _measure(generate_kem_keypair, iterations)
    kem_ciphertext, _ = encapsulate(kem_pair.public_key, DEFAULT_KEM)
    encaps_samples, encapsulated = _measure(
        lambda: encapsulate(kem_pair.public_key, DEFAULT_KEM), iterations
    )
    ciphertext, encapsulated_secret = encapsulated
    decaps_samples, decapsulated = _measure(
        lambda: decapsulate(kem_pair.secret_key, ciphertext, DEFAULT_KEM), iterations
    )
    if decapsulated != encapsulated_secret:
        raise BackendUnavailable("ML-KEM benchmark self-check failed.")

    signature_samples, signature_pair = _measure(generate_signature_keypair, iterations)
    (signature,) = (sign(signature_pair.secret_key, message, DEFAULT_SIGNATURE),)
    sign_samples, signed = _measure(
        lambda: sign(signature_pair.secret_key, message, DEFAULT_SIGNATURE), iterations
    )
    verify_samples, verified = _measure(
        lambda: verify(signature_pair.public_key, message, signature, DEFAULT_SIGNATURE),
        iterations,
    )
    if not verified:
        raise BackendUnavailable("ML-DSA benchmark self-check failed.")
    # ML-DSA is randomized; each measured signature is valid, but need not be byte-identical.
    if signed != signature and not verify(
        signature_pair.public_key, message, signed, DEFAULT_SIGNATURE
    ):
        raise BackendUnavailable("ML-DSA benchmark produced an invalid signature.")

    metrics = (
        _metric(
            "kem_keygen",
            DEFAULT_KEM,
            kem_samples,
            public_key_bytes=len(kem_pair.public_key),
            secret_key_bytes=len(kem_pair.secret_key),
        ),
        _metric(
            "kem_encapsulate",
            DEFAULT_KEM,
            encaps_samples,
            public_key_bytes=len(kem_pair.public_key),
            ciphertext_bytes=len(kem_ciphertext),
        ),
        _metric(
            "kem_decapsulate",
            DEFAULT_KEM,
            decaps_samples,
            ciphertext_bytes=len(ciphertext),
        ),
        _metric(
            "signature_keygen",
            DEFAULT_SIGNATURE,
            signature_samples,
            public_key_bytes=len(signature_pair.public_key),
            secret_key_bytes=len(signature_pair.secret_key),
        ),
        _metric(
            "signature_sign",
            DEFAULT_SIGNATURE,
            sign_samples,
            message_bytes=len(message),
            public_key_bytes=len(signature_pair.public_key),
            signature_bytes=len(signature),
        ),
        _metric(
            "signature_verify",
            DEFAULT_SIGNATURE,
            verify_samples,
            message_bytes=len(message),
            public_key_bytes=len(signature_pair.public_key),
            signature_bytes=len(signature),
        ),
    )
    return BenchmarkResult(
        run_id=datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8],
        created_at=datetime.now(UTC).isoformat(),
        iterations=iterations,
        python_version=platform.python_version(),
        platform_description=platform.platform(),
        machine=platform.machine(),
        processor=_processor_description(),
        native_version=report.native_version or "",
        wrapper_version=report.wrapper_version or "",
        cryptography_version=report.pyca_version or "",
        metrics=metrics,
    )


def export_benchmark(result: BenchmarkResult, output_dir: str | Path) -> BenchmarkOutput:
    """Export actual measurements to JSON, CSV and a latency chart in a unique run directory."""
    if not isinstance(result, BenchmarkResult):
        raise FormatError("Benchmark result has an invalid type.")
    if (
        not isinstance(result.run_id, str)
        or re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}", result.run_id) is None
    ):
        raise FormatError("Benchmark result has an invalid run identifier.")
    if not result.metrics:
        raise FormatError("Benchmark result must contain at least one metric.")

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise FormatError("Install the benchmark extra to generate charts.") from exc

    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    run_dir = root / result.run_id
    run_dir.mkdir(exist_ok=False)
    json_path = run_dir / "results.json"
    csv_path = run_dir / "results.csv"
    chart_path = run_dir / "latency.png"

    json_path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n")
    columns = list(asdict(result.metrics[0]).keys())
    with csv_path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for metric in result.metrics:
            row = asdict(metric)
            row["samples_ns"] = ";".join(str(value) for value in metric.samples_ns)
            writer.writerow(row)

    figure, axis = plt.subplots(figsize=(10, 5))
    labels = [metric.operation for metric in result.metrics]
    values = [metric.median_latency_ms for metric in result.metrics]
    axis.bar(labels, values)
    axis.set_ylabel("Median latency (ms)")
    axis.set_title(f"PQC benchmark — {result.run_id}")
    axis.tick_params(axis="x", rotation=25)
    figure.tight_layout()
    figure.savefig(chart_path, dpi=150)
    plt.close(figure)
    return BenchmarkOutput(run_dir, json_path, csv_path, chart_path)

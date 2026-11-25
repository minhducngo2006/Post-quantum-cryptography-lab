"""Command-line interface with lazy, fail-closed backend loading."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .backend import doctor


def _doctor() -> int:
    report = doctor()
    print(f"Status: {report.status}")
    print(f"Python: {report.python_version}")
    print(f"liboqs: {report.native_version or 'unavailable'}")
    print(f"liboqs-python: {report.wrapper_version or 'not installed'}")
    print(f"cryptography: {report.pyca_version or 'not installed'}")
    print(f"OpenSSL: {report.openssl_version or 'unavailable'}")
    print(f"Enabled KEMs: {', '.join(report.enabled_kems) or 'none'}")
    print(f"Enabled signatures: {', '.join(report.enabled_signatures) or 'none'}")
    if report.missing_optional:
        print(f"Optional algorithms unavailable: {', '.join(report.missing_optional)}")
    if report.missing_required:
        print(
            f"Required backend components missing: {', '.join(report.missing_required)}",
            file=sys.stderr,
        )
        print(
            "Provision the pinned native library explicitly; doctor never installs it.",
            file=sys.stderr,
        )
        return 1
    return 0


def _benchmark(args: argparse.Namespace) -> int:
    from .benchmark import export_benchmark, run_benchmarks
    from .errors import LabError

    try:
        message = args.message_file.read_bytes()
        result = run_benchmarks(iterations=args.iterations, message=message)
        output = export_benchmark(result, args.output_dir)
    except (OSError, LabError) as exc:
        print(f"Benchmark failed: {exc}", file=sys.stderr)
        return 1
    print(f"Benchmark run: {result.run_id}")
    print(f"JSON: {output.json_path}")
    print(f"CSV: {output.csv_path}")
    print(f"Chart: {output.chart_path}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pqclab", description="Research-only PQC lab")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Check the pinned cryptographic backend")
    benchmark = commands.add_parser("benchmark", help="Measure real ML-KEM and ML-DSA operations")
    benchmark.add_argument("--iterations", type=int, required=True)
    benchmark.add_argument("--message-file", type=Path, required=True)
    benchmark.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "doctor":
        return _doctor()
    if args.command == "benchmark":
        return _benchmark(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

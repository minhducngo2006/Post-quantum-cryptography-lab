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


def _research(args: argparse.Namespace) -> int:
    from .errors import LabError
    from .research import export_security_report, run_security_research

    try:
        report = run_security_research()
        output = export_security_report(report, args.output_dir)
    except (OSError, LabError) as exc:
        print(f"Security research failed: {exc}", file=sys.stderr)
        return 1
    print(f"Research run: {report.run_id}")
    for scenario in report.scenarios:
        status = "PASS" if scenario.passed else "FAIL"
        print(f"{status}: {scenario.scenario_id} — {scenario.observed}")
    print(f"JSON: {output.json_path}")
    print(f"Markdown: {output.markdown_path}")
    return 0 if report.passed else 1


def _ui() -> int:
    try:
        from .tui import run
    except ImportError:
        print("Install the TUI extra with uv sync --extra tui.", file=sys.stderr)
        return 1
    run()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pqclab", description="Research-only PQC lab")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Check the pinned cryptographic backend")
    benchmark = commands.add_parser("benchmark", help="Measure real ML-KEM and ML-DSA operations")
    benchmark.add_argument("--iterations", type=int, required=True)
    benchmark.add_argument("--message-file", type=Path, required=True)
    benchmark.add_argument("--output-dir", type=Path, required=True)
    research = commands.add_parser("research", help="Run isolated synthetic security experiments")
    research.add_argument("--output-dir", type=Path, required=True)
    commands.add_parser("ui", help="Open the interactive backend dashboard")
    args = parser.parse_args(argv)
    if args.command == "doctor":
        return _doctor()
    if args.command == "benchmark":
        return _benchmark(args)
    if args.command == "research":
        return _research(args)
    if args.command == "ui":
        return _ui()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

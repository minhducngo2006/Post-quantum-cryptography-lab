"""Command-line interface with lazy, fail-closed backend loading."""

import argparse
import sys
from collections.abc import Sequence

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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pqclab", description="Research-only PQC lab")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Check the pinned cryptographic backend")
    args = parser.parse_args(argv)
    if args.command == "doctor":
        return _doctor()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

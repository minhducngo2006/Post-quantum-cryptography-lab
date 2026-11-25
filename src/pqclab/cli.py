"""Command-line interface, with no native import during startup."""

import argparse
import sys
from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pqclab", description="Research-only PQC lab")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Check the cryptographic backend")
    args = parser.parse_args(argv)
    if args.command == "doctor":
        print("Backend preflight not implemented", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

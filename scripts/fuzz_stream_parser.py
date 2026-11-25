#!/usr/bin/env python3
"""Run the streaming parser fuzzer with hard input, time, run and memory bounds."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path


def _bounded_arguments(arguments: list[str], max_input_bytes: int) -> list[str]:
    limits = {
        "-max_len": max_input_bytes,
        "-max_total_time": 30,
        "-rss_limit_mb": 512,
        "-timeout": 5,
        "-runs": 10_000,
    }
    result = list(arguments)
    for flag, maximum in limits.items():
        supplied = [item for item in result[1:] if item.startswith(flag + "=")]
        if not supplied:
            result.append(f"{flag}={maximum}")
            continue
        for argument in supplied:
            try:
                value = int(argument.partition("=")[2])
            except ValueError as exc:
                raise SystemExit(f"{flag} must be an integer.") from exc
            if value <= 0 or value > maximum:
                raise SystemExit(f"{flag} must be between 1 and {maximum}.")
    return result


def main() -> None:
    try:
        import atheris
    except ImportError as exc:
        raise SystemExit("Install the optional fuzz extra: uv sync --extra fuzz") from exc

    with atheris.instrument_imports():
        from pqclab.fuzzing import (
            MAX_FUZZ_INPUT_BYTES,
            fuzz_stream_parser,
            malformed_stream_corpus,
        )

    with tempfile.TemporaryDirectory(prefix="pqclab-fuzz-corpus-") as corpus_dir:
        corpus_path = Path(corpus_dir)
        for index, sample in enumerate(malformed_stream_corpus()):
            (corpus_path / f"seed-{index:02d}").write_bytes(sample)
        arguments = _bounded_arguments(sys.argv, MAX_FUZZ_INPUT_BYTES)
        arguments.append(str(corpus_path))
        atheris.Setup(arguments, fuzz_stream_parser)
        atheris.Fuzz()


if __name__ == "__main__":
    main()

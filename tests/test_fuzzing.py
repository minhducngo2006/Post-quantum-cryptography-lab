import runpy
from pathlib import Path

import pytest

from pqclab.fuzzing import (
    MAX_FUZZ_INPUT_BYTES,
    fuzz_stream_parser,
    malformed_stream_corpus,
    run_parser_smoke_corpus,
)


def test_parser_fuzz_corpus_rejects_all_malformed_envelopes():
    corpus = malformed_stream_corpus()
    assert len(corpus) >= 7
    assert run_parser_smoke_corpus() == len(corpus)


def test_fuzz_target_is_bounded_and_handles_expected_parser_errors():
    fuzz_stream_parser(b"")
    fuzz_stream_parser(b"PQCS" + bytes(40))
    fuzz_stream_parser(b"x" * (MAX_FUZZ_INPUT_BYTES + 1))


def test_fuzzer_command_enforces_hard_limits_even_with_duplicate_flags():
    script = Path(__file__).parents[1] / "scripts" / "fuzz_stream_parser.py"
    namespace = runpy.run_path(str(script), run_name="fuzz_target_test")
    bounded_arguments = namespace["_bounded_arguments"]

    with pytest.raises(SystemExit):
        bounded_arguments(["fuzz", "-max_len=1048577"], MAX_FUZZ_INPUT_BYTES)
    with pytest.raises(SystemExit):
        bounded_arguments(["fuzz", "-runs=10", "-runs=10001"], MAX_FUZZ_INPUT_BYTES)

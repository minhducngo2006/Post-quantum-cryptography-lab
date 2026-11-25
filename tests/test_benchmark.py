import csv
import json

from pqclab.benchmark import export_benchmark, run_benchmarks


def test_benchmark_records_real_operations_and_exports_all_formats(tmp_path):
    result = run_benchmarks(iterations=1, message=b"benchmark integration message")

    assert result.iterations == 1
    assert result.metrics
    assert {metric.operation for metric in result.metrics} == {
        "kem_keygen",
        "kem_encapsulate",
        "kem_decapsulate",
        "signature_keygen",
        "signature_sign",
        "signature_verify",
    }
    assert all(metric.samples_ns and min(metric.samples_ns) > 0 for metric in result.metrics)
    assert all(metric.ops_per_second > 0 for metric in result.metrics)
    assert all("secret" not in metric.operation for metric in result.metrics)

    output = export_benchmark(result, tmp_path)
    payload = json.loads(output.json_path.read_text())
    rows = list(csv.DictReader(output.csv_path.open()))
    assert payload["iterations"] == 1
    assert len(rows) == len(result.metrics)
    assert output.chart_path.stat().st_size > 0


def test_benchmark_rejects_invalid_iterations_and_empty_message():
    import pytest

    from pqclab.benchmark import run_benchmarks
    from pqclab.errors import FormatError

    with pytest.raises(FormatError):
        run_benchmarks(iterations=0, message=b"data")
    with pytest.raises(FormatError):
        run_benchmarks(iterations=1, message=b"")

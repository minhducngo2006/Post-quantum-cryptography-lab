import json

import pytest

from pqclab.cli import main
from pqclab.errors import FormatError
from pqclab.research import (
    ResearchScenario,
    SecurityResearchReport,
    export_security_report,
    run_security_research,
)

EXPECTED_SCENARIOS = {
    "ciphertext-tampering",
    "protocol-downgrade",
    "recipient-key-substitution",
    "hybrid-signature-stripping",
    "stream-chunk-reordering",
    "stream-truncation",
    "stream-parser-fuzz-corpus",
}


def test_security_research_runs_isolated_adversarial_scenarios():
    report = run_security_research()

    assert report.passed
    assert {scenario.scenario_id for scenario in report.scenarios} == EXPECTED_SCENARIOS
    assert all(scenario.passed for scenario in report.scenarios)
    assert all(scenario.observed for scenario in report.scenarios)


def test_security_research_report_exports_sanitized_json_and_markdown(tmp_path):
    report = run_security_research()
    output = export_security_report(report, tmp_path)

    payload = json.loads(output.json_path.read_text())
    markdown = output.markdown_path.read_text()
    assert payload["passed"] is True
    assert len(payload["scenarios"]) == len(EXPECTED_SCENARIOS)
    assert "secret_key" not in json.dumps(payload)
    assert "shared_secret" not in json.dumps(payload)
    assert "PRIVATE KEY" not in markdown
    assert output.json_path.exists()
    assert output.markdown_path.exists()


def test_research_cli_runs_and_reports_sanitized_artifacts(tmp_path, capsys):
    assert main(["research", "--output-dir", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "PASS: ciphertext-tampering" in output
    assert "JSON:" in output
    assert "Markdown:" in output


def test_security_report_export_rejects_path_traversal_run_id(tmp_path):
    report = SecurityResearchReport(
        run_id="../outside",
        created_at="2026-11-25T00:00:00+00:00",
        python_version="3.12",
        native_version="0.16.0",
        wrapper_version="0.16.0.2",
        scenarios=(ResearchScenario("example", "Example", "reject", "rejected", True),),
    )
    with pytest.raises(FormatError):
        export_security_report(report, tmp_path)

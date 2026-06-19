from pathlib import Path

from rich.console import Console

from agent_security_scanner.commands import render_doctor, render_rules_table
from agent_security_scanner.i18n import Language
from agent_security_scanner.models import Category, Finding, Remediation, ScanResult, Severity
from agent_security_scanner.output import render_terminal


def test_rules_use_card_layout_on_narrow_terminal(monkeypatch):
    monkeypatch.setenv("AGENT_SCAN_TERMINAL_WIDTH", "70")
    console = Console(width=70, record=True, no_color=True)

    render_rules_table(console, category="secrets", language=Language.EN)

    rendered = console.export_text()
    assert "SEC001 | critical" in rendered
    assert "OpenAI API key detected" in rendered
    assert "Rule" not in rendered


def test_doctor_hides_detail_column_on_narrow_terminal(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("AGENT_SCAN_TERMINAL_WIDTH", "68")
    console = Console(width=68, record=True, no_color=True)

    render_doctor(console, tmp_path, tmp_path / "output", language=Language.EN)

    rendered = console.export_text()
    assert "Agent Security Scanner Doctor" in rendered
    assert "Check" in rendered
    assert "Status" in rendered
    assert "Detail" not in rendered


def test_scan_results_use_card_layout_on_narrow_terminal(monkeypatch):
    monkeypatch.setenv("AGENT_SCAN_TERMINAL_WIDTH", "70")
    console = Console(width=70, record=True, no_color=True)
    result = ScanResult.from_findings(
        Path("."),
        [
            Finding(
                rule_id="SEC001",
                title="OpenAI API key detected",
                description="A secret was found.",
                severity=Severity.CRITICAL,
                category=Category.SECRETS,
                file_path="very/long/path/app.py",
                line=12,
                recommendation="Move the key into a secret manager.",
                remediation=Remediation(summary="Rotate the key.", effort="medium"),
            )
        ],
    )

    render_terminal(result, console, language=Language.EN)

    rendered = console.export_text()
    assert "SEC001 | critical" in rendered
    assert "OpenAI API key detected" in rendered
    assert "very/long/path/app.py:12" in rendered
    assert "Severity" not in rendered

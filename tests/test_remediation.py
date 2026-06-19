from pathlib import Path

from agent_security_scanner.scanner import Scanner


def test_findings_include_structured_remediation(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    result = Scanner().scan(tmp_path)

    assert result.findings[0].remediation is not None
    assert result.findings[0].remediation.steps
    assert result.findings[0].remediation.effort in {"low", "medium", "high"}

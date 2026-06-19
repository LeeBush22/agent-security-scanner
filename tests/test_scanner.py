from pathlib import Path

from agent_security_scanner.scanner import Scanner


def test_scanner_recurses_and_returns_scan_result(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    result = Scanner().scan(project)

    assert result.summary.total >= 1
    assert any(f.rule_id == "SEC001" for f in result.findings)


def test_scanner_skips_excluded_directories(tmp_path: Path):
    project = tmp_path / "project"
    ignored = project / "node_modules"
    ignored.mkdir(parents=True)
    (ignored / "bad.js").write_text('const key = "sk-example1234567890example1234567890"', encoding="utf-8")

    result = Scanner().scan(project)

    assert result.summary.total == 0

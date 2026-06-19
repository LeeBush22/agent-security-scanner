from pathlib import Path

from agent_security_scanner.config import load_project_config, path_matches
from agent_security_scanner.scanner import Scanner


def test_path_matches_plain_directory():
    assert path_matches("output/report.md", "output/")
    assert path_matches("generated/client/file.py", "generated/**")


def test_config_can_ignore_rule_for_path(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".agent-scan.yml").write_text(
        """
        ignore:
          - rule_id: SEC001
            path: app.py
            reason: fixture
        """,
        encoding="utf-8",
    )
    (project / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    config = load_project_config(project)
    result = Scanner(project_config=config).scan(project)

    assert result.summary.total == 0


def test_config_can_exclude_paths(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".agent-scan.yml").write_text("exclude:\n  - ignored/\n", encoding="utf-8")
    ignored = project / "ignored"
    ignored.mkdir()
    (ignored / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    config = load_project_config(project)
    result = Scanner(project_config=config).scan(project)

    assert result.summary.total == 0


def test_config_can_disable_rules(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".agent-scan.yml").write_text("disabled_rules:\n  - SEC001\n", encoding="utf-8")
    (project / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    config = load_project_config(project)
    result = Scanner(project_config=config).scan(project)

    assert result.summary.total == 0


def test_config_can_enable_only_selected_rules(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".agent-scan.yml").write_text("enabled_rules:\n  - SEC002\n", encoding="utf-8")
    (project / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    config = load_project_config(project)
    result = Scanner(project_config=config).scan(project)

    assert result.summary.total == 0

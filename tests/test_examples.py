from pathlib import Path

from agent_security_scanner.scanner import Scanner


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_sample_project_covers_new_rule_families():
    result = Scanner().scan(PROJECT_ROOT / "examples" / "sample-project")
    rule_ids = {finding.rule_id for finding in result.findings}

    assert {"SEC018", "SEC034", "SEC035", "SEC036", "SEC037"} <= rule_ids
    assert {"AIT011", "AIT013", "AIT014", "AIT016"} <= rule_ids
    assert {"MCP015", "MCP016", "MCP017", "MCP018"} <= rule_ids
    assert {"SC015", "SC016", "GHA012"} <= rule_ids


def test_shell_example_covers_package_manager_immediate_execution():
    result = Scanner().scan(PROJECT_ROOT / "examples" / "unsafe-script.sh")
    rule_ids = {finding.rule_id for finding in result.findings}

    assert "SH010" in rule_ids

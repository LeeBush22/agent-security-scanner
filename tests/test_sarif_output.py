import json
from pathlib import Path

from agent_security_scanner.output import render_sarif
from agent_security_scanner.scanner import Scanner


def test_render_sarif_has_expected_shape(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")
    result = Scanner().scan(tmp_path)

    payload = json.loads(render_sarif(result))

    assert payload["version"] == "2.1.0"
    driver = payload["runs"][0]["tool"]["driver"]
    assert driver["name"] == "agent-security-scanner"
    assert driver["semanticVersion"] == "1.0.3"
    assert payload["runs"][0]["results"][0]["ruleId"] == "SEC001"
    assert payload["runs"][0]["results"][0]["properties"]["remediation"]["steps"]

    rule = driver["rules"][0]
    assert rule["id"] == "SEC001"
    assert rule["helpUri"].endswith("#sec001-openai-api-key-detected")
    assert rule["properties"]["category"] == "secrets"
    assert rule["properties"]["precision"] == "high"
    assert "security" in rule["properties"]["tags"]

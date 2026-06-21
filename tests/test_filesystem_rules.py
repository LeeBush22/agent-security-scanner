from pathlib import Path

from agent_security_scanner.models import FileContext
from agent_security_scanner.rules.filesystem import FilesystemRiskRule


def scan_file(path: str, text: str = ""):
    return FilesystemRiskRule().scan(FileContext(path=Path(path), relative_path=path, text=text))


def test_detects_sensitive_local_file():
    findings = scan_file(".env", "OPENAI_API_KEY=sk-example")

    assert any(finding.rule_id == "FS001" for finding in findings)


def test_detects_sensitive_host_directory_path():
    findings = scan_file(".ssh/id_rsa", "private")

    assert {finding.rule_id for finding in findings} >= {"FS001", "FS002"}


def test_detects_broad_permission_command():
    findings = scan_file("scripts/setup.sh", "chmod -R 777 .\n")

    assert any(finding.rule_id == "FS003" and finding.line == 1 for finding in findings)

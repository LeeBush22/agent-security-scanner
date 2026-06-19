from pathlib import Path

from agent_security_scanner.models import FileContext
from agent_security_scanner.rules.github_actions import GitHubActionsRule


WORKFLOW_PATH = Path(".github/workflows/ci.yml")


def scan_workflow(text: str):
    return GitHubActionsRule().scan(
        FileContext(path=WORKFLOW_PATH, relative_path=".github/workflows/ci.yml", text=text)
    )


def test_detects_pull_request_target_with_checkout():
    findings = scan_workflow(
        """
        on:
          pull_request_target:
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@main
        """
    )

    assert any(f.rule_id == "GHA001" for f in findings)


def test_detects_write_all_permissions():
    findings = scan_workflow(
        """
        on: push
        permissions: write-all
        jobs:
          test:
            runs-on: ubuntu-latest
            steps: []
        """
    )

    assert any(f.rule_id == "GHA005" for f in findings)


def test_detects_unpinned_action():
    findings = scan_workflow(
        """
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: third-party/example-action@v1
        """
    )

    assert any(f.rule_id == "GHA002" for f in findings)


def test_detects_untrusted_context_expression_in_run():
    findings = scan_workflow(
        """
        on: pull_request
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.pull_request.title }}" | bash
        """
    )

    assert any(f.rule_id == "GHA007" for f in findings)


def test_detects_oidc_permission():
    findings = scan_workflow(
        """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              id-token: write
            steps:
              - uses: aws-actions/configure-aws-credentials@v4
        """
    )

    assert any(f.rule_id == "GHA008" for f in findings)


def test_detects_oidc_cloud_trust_policy_verification_needed():
    findings = scan_workflow(
        """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              id-token: write
            steps:
              - uses: aws-actions/configure-aws-credentials@v4
                with:
                  role-to-assume: arn:aws:iam::123456789012:role/deploy
        """
    )

    assert any(f.rule_id == "GHA012" for f in findings)


def test_oidc_policy_hint_suppresses_cloud_trust_policy_warning():
    findings = scan_workflow(
        """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              id-token: write
            environment: production
            steps:
              - uses: aws-actions/configure-aws-credentials@v4
                with:
                  role-to-assume: arn:aws:iam::123456789012:role/deploy
                  audience: sts.amazonaws.com
        """
    )

    assert any(f.rule_id == "GHA008" for f in findings)
    assert not any(f.rule_id == "GHA012" for f in findings)


def test_detects_cache_action_on_pull_request():
    findings = scan_workflow(
        """
        on: pull_request
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  path: .cache
                  key: deps-${{ github.event.pull_request.head.sha }}
        """
    )

    assert any(f.rule_id == "GHA009" for f in findings)


def test_detects_execution_of_artifact_content():
    findings = scan_workflow(
        """
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4
              - run: bash artifact/build.sh
        """
    )

    assert any(f.rule_id == "GHA010" for f in findings)


def test_detects_workflow_run_with_artifact_processing():
    findings = scan_workflow(
        """
        on:
          workflow_run:
            workflows: ["CI"]
            types: [completed]
        permissions:
          contents: write
        jobs:
          promote:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4
        """
    )

    assert any(f.rule_id == "GHA011" for f in findings)

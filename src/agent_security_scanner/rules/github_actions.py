from __future__ import annotations

from typing import Any, cast

import yaml

from agent_security_scanner.models import Category, FileContext, Finding, Severity
from agent_security_scanner.rules.base import Rule
from agent_security_scanner.rules.shell import ShellDangerRule


class GitHubActionsRule(Rule):
    def scan(self, context: FileContext) -> list[Finding]:
        if not _is_workflow(context):
            return []

        try:
            data = yaml.safe_load(context.text) or {}
        except yaml.YAMLError:
            return []

        findings: list[Finding] = []
        findings.extend(_check_permissions(context, data))
        findings.extend(_check_pull_request_target(context, data))
        findings.extend(_check_workflow_run(context, data))
        findings.extend(_check_jobs(context, data))

        shell_findings = [
            finding.model_copy(update={"category": Category.GITHUB_ACTIONS})
            for finding in ShellDangerRule(skip_github_workflows=False).scan(context)
            if finding.rule_id in {"SH002", "SH004", "SH005"}
        ]
        for finding in shell_findings:
            finding.rule_id = "GHA004" if finding.rule_id == "SH002" else finding.rule_id
            if finding.rule_id == "GHA004":
                finding.title = "Dangerous script download in GitHub Actions"
        findings.extend(shell_findings)
        return findings


def _is_workflow(context: FileContext) -> bool:
    normalized = context.relative_path.replace("\\", "/")
    return "/.github/workflows/" in f"/{normalized}" and context.path.suffix.lower() in {".yml", ".yaml"}


def _check_permissions(context: FileContext, data: dict[str, Any]) -> list[Finding]:
    permissions = data.get("permissions")
    findings: list[Finding] = []
    if permissions == "write-all":
        findings.append(
            _finding(
                context,
                "GHA005",
                "Overly broad GitHub Actions permissions",
                Severity.HIGH,
                "Workflow grants write-all permissions.",
                "permissions: write-all",
                "Grant only the permissions needed by the workflow, usually contents: read by default.",
            )
        )
    if isinstance(permissions, dict):
        for key in ("actions", "checks", "contents", "deployments", "id-token", "packages", "pull-requests"):
            if permissions.get(key) == "write":
                findings.append(
                    _finding(
                        context,
                        "GHA005",
                        "Write permission granted in GitHub Actions",
                        Severity.HIGH,
                        f"Workflow grants {key}: write.",
                        f"{key}: write",
                        "Use read permissions unless this workflow explicitly needs to write that scope.",
                    )
                )
    return findings


def _check_job_permissions(context: FileContext, job: dict[str, Any]) -> list[Finding]:
    permissions = job.get("permissions")
    findings: list[Finding] = []
    if permissions == "write-all":
        findings.append(
            _finding(
                context,
                "GHA005",
                "Overly broad GitHub Actions job permissions",
                Severity.HIGH,
                "Job grants write-all permissions.",
                "permissions: write-all",
                "Grant only the permissions needed by this job, usually contents: read by default.",
            )
        )
    if isinstance(permissions, dict):
        for key in ("actions", "checks", "contents", "deployments", "id-token", "packages", "pull-requests"):
            if permissions.get(key) == "write":
                findings.append(
                    _finding(
                        context,
                        "GHA005",
                        "Write permission granted in GitHub Actions job",
                        Severity.HIGH,
                        f"Job grants {key}: write.",
                        f"{key}: write",
                        "Use read permissions unless this job explicitly needs to write that scope.",
                    )
                )
    return findings


def _check_pull_request_target(context: FileContext, data: dict[str, Any]) -> list[Finding]:
    if not _has_event(_workflow_events(data), "pull_request_target"):
        return []
    if "actions/checkout" not in context.text:
        return []
    return [
        _finding(
            context,
            "GHA001",
            "pull_request_target workflow checks out code",
            Severity.HIGH,
            "pull_request_target runs with elevated token context and checks out repository code.",
            "pull_request_target",
            "Prefer pull_request for untrusted code, or avoid checking out attacker-controlled refs under pull_request_target.",
        )
    ]


def _check_workflow_run(context: FileContext, data: dict[str, Any]) -> list[Finding]:
    if not _has_event(_workflow_events(data), "workflow_run"):
        return []
    if not _workflow_uses_write_or_secrets(data) and "actions/download-artifact" not in context.text:
        return []
    return [
        _finding(
            context,
            "GHA011",
            "workflow_run workflow may process untrusted artifacts with elevated permissions",
            Severity.HIGH,
            "workflow_run can run with privileged context after another workflow and may consume attacker-controlled artifacts.",
            "workflow_run",
            "Keep workflow_run jobs read-only unless required, validate downloaded artifacts, and avoid executing artifact content.",
        )
    ]


def _check_jobs(context: FileContext, data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    jobs = data.get("jobs", {})
    if not isinstance(jobs, dict):
        return findings
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        findings.extend(_check_job_permissions(context, job))
        runs_on = job.get("runs-on")
        if _uses_self_hosted(runs_on):
            findings.append(
                _finding(
                    context,
                    "GHA006",
                    "Self-hosted GitHub Actions runner",
                    Severity.MEDIUM,
                    "Self-hosted runners can expose local infrastructure to workflow code.",
                    "self-hosted",
                    "Use GitHub-hosted runners for untrusted code, or isolate and harden self-hosted runners.",
                )
            )
        steps = job.get("steps", [])
        if isinstance(steps, list):
            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses")
                if isinstance(uses, str) and _is_unpinned_action(uses):
                    findings.append(
                        _finding(
                            context,
                            "GHA002",
                            "Unpinned GitHub Action reference",
                            Severity.MEDIUM,
                            "Action references a mutable branch or tag instead of a commit SHA.",
                            uses,
                            "Pin third-party actions to a full commit SHA and review updates deliberately.",
                        )
                    )
                run = step.get("run")
                if isinstance(run, str) and "${{ secrets." in run and "echo" in run.lower():
                    findings.append(
                        _finding(
                            context,
                            "GHA003",
                            "Secret echoed in GitHub Actions shell",
                            Severity.CRITICAL,
                            "Workflow shell step echoes a GitHub secret expression.",
                            "${{ secrets.",
                            "Never echo secrets. Pass them only to trusted tools through environment variables or secret inputs.",
                        )
                    )
                if isinstance(run, str) and _has_untrusted_expression(run):
                    findings.append(
                        _finding(
                            context,
                            "GHA007",
                            "Untrusted GitHub context used directly in shell",
                            Severity.HIGH,
                            "Workflow shell step interpolates untrusted event data directly into a run command.",
                            _first_untrusted_expression(run),
                            "Pass untrusted context through environment variables and quote it safely before using it in shell commands.",
                        )
                    )
                if isinstance(run, str) and _runs_artifact_or_cache_content(run):
                    findings.append(
                        _finding(
                            context,
                            "GHA010",
                            "Downloaded artifact or cache content is executed",
                            Severity.HIGH,
                            "Workflow appears to execute content from an artifact or cache path.",
                            run.splitlines()[0].strip()[:120],
                            "Do not execute artifact or cache contents from untrusted workflows without validation and integrity checks.",
                        )
                    )
                if isinstance(uses, str) and _is_cache_or_artifact_action(uses) and _is_untrusted_event(_workflow_events(data)):
                    findings.append(
                        _finding(
                            context,
                            "GHA009",
                            "Cache or artifact action used in untrusted workflow context",
                            Severity.MEDIUM,
                            "Workflow uses cache or artifact transfer on an event that may be influenced by untrusted contributors.",
                            uses,
                            "Avoid trusting cache or artifact contents from untrusted pull requests, and isolate restore/save keys.",
                        )
                    )
        findings.extend(_check_oidc_permissions(context, data, job))
    return findings


def _check_oidc_permissions(context: FileContext, data: dict[str, Any], job: dict[str, Any]) -> list[Finding]:
    permissions = _effective_permissions(data, job)
    if not isinstance(permissions, dict) or permissions.get("id-token") != "write":
        return []
    text = str(job)
    findings: list[Finding] = []
    if any(marker in text for marker in ("aws-actions/configure-aws-credentials", "azure/login", "google-github-actions/auth")):
        findings.append(
            _finding(
                context,
                "GHA008",
                "OIDC token permission granted to cloud authentication job",
                Severity.MEDIUM,
                "Job can mint GitHub OIDC tokens for cloud authentication; the cloud trust policy must restrict repository, branch, workflow, and audience.",
                "id-token: write",
                "Verify the cloud role trust policy has strict subject, repository, branch, workflow, and audience conditions.",
            )
        )
        if not _job_has_oidc_policy_hint(job):
            findings.append(
                _finding(
                    context,
                    "GHA012",
                    "OIDC cloud trust policy constraints require verification",
                    Severity.MEDIUM,
                    "Workflow grants id-token: write for cloud authentication, but repository-side YAML cannot prove strict cloud subject and audience constraints.",
                    "id-token: write",
                    "Verify the cloud IAM trust policy restricts subject, audience, repository, branch, environment, and workflow before trusting this OIDC flow.",
                )
            )
        return findings
    findings.append(
        _finding(
            context,
            "GHA008",
            "OIDC token permission granted",
            Severity.MEDIUM,
            "Job can mint GitHub OIDC tokens.",
            "id-token: write",
            "Grant id-token: write only to jobs that need OIDC and verify cloud trust policy conditions.",
        )
    )
    return findings


def _has_event(on_value: Any, event_name: str) -> bool:
    if isinstance(on_value, str):
        return on_value == event_name
    if isinstance(on_value, list):
        return event_name in on_value
    if isinstance(on_value, dict):
        return event_name in on_value
    return False


def _workflow_events(data: dict[str, Any]) -> Any:
    # PyYAML follows YAML 1.1 booleans, so GitHub's "on" key can parse as True.
    if "on" in data:
        return data["on"]
    return cast(Any, data).get(True)


def _uses_self_hosted(value: Any) -> bool:
    if isinstance(value, str):
        return value == "self-hosted"
    if isinstance(value, list):
        return "self-hosted" in value
    return False


def _is_unpinned_action(uses: str) -> bool:
    if "@" not in uses:
        return True
    if uses.startswith("./") or uses.startswith("docker://"):
        return False
    version = uses.rsplit("@", 1)[-1]
    if len(version) == 40 and all(char in "0123456789abcdefABCDEF" for char in version):
        return False
    return version in {"main", "master"} or version.startswith("v")


UNTRUSTED_EXPRESSION_MARKERS = (
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.head_ref",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.pages",
    "github.event.client_payload",
)


def _has_untrusted_expression(value: str) -> bool:
    lowered = value.lower()
    return any(f"${{{{ {marker}" in lowered or f"${{{{{marker}" in lowered for marker in UNTRUSTED_EXPRESSION_MARKERS)


def _first_untrusted_expression(value: str) -> str:
    lowered = value.lower()
    for marker in UNTRUSTED_EXPRESSION_MARKERS:
        spaced = f"${{{{ {marker}"
        compact = f"${{{{{marker}"
        if spaced in lowered:
            return f"${{{{ {marker} }}}}"
        if compact in lowered:
            return f"${{{{{marker}}}}}"
    return "${{ github.event.* }}"


def _effective_permissions(data: dict[str, Any], job: dict[str, Any]) -> Any:
    return job.get("permissions", data.get("permissions"))


def _job_has_oidc_policy_hint(job: dict[str, Any]) -> bool:
    text = str(job).lower()
    return any(
        marker in text
        for marker in (
            "subject_claim",
            "subject-claim",
            "sub:",
            "audience",
            "allowed_account_ids",
            "role-session-name",
            "environment:",
            "token_format",
        )
    )


def _workflow_uses_write_or_secrets(data: dict[str, Any]) -> bool:
    permissions = data.get("permissions")
    if permissions == "write-all":
        return True
    if isinstance(permissions, dict) and any(value == "write" for value in permissions.values()):
        return True
    return "secrets." in str(data)


def _is_untrusted_event(on_value: Any) -> bool:
    return any(_has_event(on_value, event) for event in ("pull_request", "pull_request_target", "issue_comment"))


def _is_cache_or_artifact_action(uses: str) -> bool:
    normalized = uses.lower()
    return normalized.startswith(("actions/cache@", "actions/upload-artifact@", "actions/download-artifact@"))


def _runs_artifact_or_cache_content(run: str) -> bool:
    lowered = run.lower()
    if not any(marker in lowered for marker in ("artifact", ".cache", "cache/")):
        return False
    return any(marker in lowered for marker in ("bash ", "sh ", "python ", "node ", "chmod +x", "./"))


def _finding(
    context: FileContext,
    rule_id: str,
    title: str,
    severity: Severity,
    description: str,
    evidence: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        category=Category.GITHUB_ACTIONS,
        file_path=context.relative_path,
        line=_find_line(context.text, evidence),
        evidence=evidence,
        recommendation=recommendation,
    )


def _find_line(text: str, needle: str) -> int | None:
    for line_number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return line_number
    return None

from __future__ import annotations

import re
from pathlib import Path

from agent_security_scanner.models import Category, FileContext, Finding, Severity
from agent_security_scanner.rules.base import Rule


SENSITIVE_FILENAMES = {
    ".aws/credentials",
    ".azure/accessTokens.json",
    ".config/gcloud/credentials.db",
    ".docker/config.json",
    ".env",
    ".env.local",
    ".env.production",
    ".kube/config",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "id_ed25519",
    "id_rsa",
}

PERMISSIVE_PERMISSION_RE = re.compile(r"(?i)\bchmod\s+(?:-R\s+)?(?:777|666|a\+rw|a\+rwx|ugo\+rw|ugo\+rwx)\b")
SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:^|[/\\])(?:\.ssh|\.aws|\.azure|\.gcp|\.gnupg|\.kube|\.docker|\.config[/\\]gh)(?:[/\\]|$)"
)


class FilesystemRiskRule(Rule):
    def scan(self, context: FileContext) -> list[Finding]:
        findings: list[Finding] = []
        normalized_path = _normalize_path(context.relative_path)
        if _is_sensitive_file(normalized_path):
            findings.append(
                _finding(
                    context,
                    "FS001",
                    "Sensitive local file is included in the scanned project",
                    Severity.HIGH,
                    "Project contains a file path commonly used for local credentials or security-sensitive configuration.",
                    context.relative_path,
                    "Remove sensitive local files from the project, add them to .gitignore, and rotate exposed credentials if needed.",
                )
            )

        if SENSITIVE_PATH_RE.search(normalized_path):
            findings.append(
                _finding(
                    context,
                    "FS002",
                    "Sensitive host directory path is present",
                    Severity.HIGH,
                    "Project contains a path under a sensitive host credential or configuration directory.",
                    context.relative_path,
                    "Avoid storing host credential directories inside project workspaces or sharing them with agent tools.",
                )
            )

        for line_number, line in enumerate(context.text.splitlines(), start=1):
            match = PERMISSIVE_PERMISSION_RE.search(line)
            if not match:
                continue
            findings.append(
                _finding(
                    context,
                    "FS003",
                    "Broad filesystem permission command detected",
                    Severity.MEDIUM,
                    "A command grants broad read/write/execute permissions to users or groups.",
                    match.group(0),
                    "Use the narrowest permission mode required, such as owner-only access for credentials and scripts.",
                    line=line_number,
                )
            )
        return _dedupe(findings)


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").lower().strip("/")


def _is_sensitive_file(path: str) -> bool:
    if path in SENSITIVE_FILENAMES:
        return True
    name = Path(path).name.lower()
    return name in SENSITIVE_FILENAMES


def _finding(
    context: FileContext,
    rule_id: str,
    title: str,
    severity: Severity,
    description: str,
    evidence: str,
    recommendation: str,
    line: int | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        category=Category.FILESYSTEM,
        file_path=context.relative_path,
        line=line,
        evidence=evidence,
        recommendation=recommendation,
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int | None, str | None]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file_path, finding.line, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique

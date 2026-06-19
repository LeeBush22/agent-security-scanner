from __future__ import annotations

import re
from dataclasses import dataclass

from agent_security_scanner.models import Category, FileContext, Finding, Severity
from agent_security_scanner.rules.base import Rule


SHELL_SUFFIXES = {
    ".bat",
    ".cmd",
    ".json",
    ".js",
    ".mjs",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".yaml",
    ".yml",
}
SHELL_FILENAMES = {"Dockerfile", "Makefile", "Justfile", "Rakefile"}


@dataclass(frozen=True)
class ShellPattern:
    rule_id: str
    title: str
    regex: re.Pattern[str]
    severity: Severity
    recommendation: str


class ShellDangerRule(Rule):
    def __init__(self, skip_github_workflows: bool = True) -> None:
        self.skip_github_workflows = skip_github_workflows

    patterns = [
        ShellPattern(
            "SH001",
            "Recursive force delete command",
            re.compile(r"(?i)\b(rm\s+-[a-z]*rf[a-z]*\s+(?:/|\*|~|\\)|Remove-Item\b.*\b-Recurse\b.*\b-Force\b)"),
            Severity.CRITICAL,
            "Avoid broad destructive deletion. Restrict the target path and add explicit safety checks.",
        ),
        ShellPattern(
            "SH002",
            "Downloaded script piped to shell",
            re.compile(r"(?i)\b(curl|wget|iwr|Invoke-WebRequest)\b[^\n|;&]*\|\s*(sh|bash|zsh|iex|Invoke-Expression)\b"),
            Severity.CRITICAL,
            "Download scripts to a reviewed file, verify integrity, then execute with least privilege.",
        ),
        ShellPattern(
            "SH003",
            "Disabled execution safety controls",
            re.compile(r"(?i)(--dangerously-skip-permissions|--no-sandbox|\bchmod\s+(?:-R\s+)?777\b|Set-ExecutionPolicy\s+Bypass)"),
            Severity.HIGH,
            "Keep sandbox and permission checks enabled; avoid world-writable permissions.",
        ),
        ShellPattern(
            "SH004",
            "Potential secret exfiltration command",
            re.compile(r"(?i)\b(curl|wget)\b[^\n]*(\$[A-Z_]*(TOKEN|SECRET|KEY)|\.ssh|\.env|id_rsa)"),
            Severity.HIGH,
            "Do not send local secrets or key material through shell commands. Use scoped credentials and reviewed destinations.",
        ),
        ShellPattern(
            "SH005",
            "Encoded command execution",
            re.compile(r"(?i)(powershell(?:\.exe)?[^\n]*-(?:e|enc|encodedcommand)\b|base64\s+-d[^\n|;&]*\|\s*(sh|bash))"),
            Severity.HIGH,
            "Avoid opaque encoded command execution. Commit readable scripts and review their behavior.",
        ),
        ShellPattern(
            "SH006",
            "PowerShell expression execution",
            re.compile(r"(?i)\b(?:Invoke-Expression|iex)\b"),
            Severity.HIGH,
            "Avoid dynamic PowerShell expression execution. Use explicit commands or reviewed scripts instead.",
        ),
        ShellPattern(
            "SH007",
            "Reverse shell pattern",
            re.compile(
                r"(?i)(\b(?:nc|ncat|netcat)\b[^\n]*(?:-e\s+|/bin/(?:sh|bash)|cmd\.exe|powershell)"
                r"|bash\s+-i\s*>\s*&\s*/dev/tcp/|/dev/tcp/[^\s]+/[0-9]+)"
            ),
            Severity.CRITICAL,
            "Remove reverse shell behavior and use authenticated, audited remote administration channels.",
        ),
        ShellPattern(
            "SH008",
            "Destructive disk or filesystem command",
            re.compile(r"(?i)\b(dd\s+if=.*\bof=/dev/|mkfs(?:\.[a-z0-9]+)?\s+/dev/|format\s+[a-z]:|diskpart\b)"),
            Severity.CRITICAL,
            "Do not run destructive disk operations from project scripts unless they are isolated and heavily guarded.",
        ),
        ShellPattern(
            "SH009",
            "Inline dynamic code execution",
            re.compile(r"(?i)\b(python(?:3)?|node|ruby|perl)\s+-[ce]\s+"),
            Severity.MEDIUM,
            "Prefer committed, reviewable scripts over inline dynamic code in automation paths.",
        ),
        ShellPattern(
            "SH010",
            "Package manager immediate execution command",
            re.compile(
                r"(?i)\b("
                r"npx\s+(?:-y\s+|--yes\s+)?(?:@?[a-z0-9._-]+(?:/[a-z0-9._-]+)?|https?:|github:)|"
                r"(?:npm|pnpm|yarn)\s+(?:create|init)\s+[^#\n;&|]+|"
                r"(?:pnpm|yarn)\s+dlx\s+[^#\n;&|]+"
                r")"
            ),
            Severity.MEDIUM,
            "Avoid immediate execution from package registries unless the package, version, and source are pinned and reviewed.",
        ),
    ]

    def scan(self, context: FileContext) -> list[Finding]:
        if not _looks_shell_relevant(context):
            return []
        if self.skip_github_workflows and _is_github_workflow(context):
            return []

        findings: list[Finding] = []
        for line_number, line in enumerate(context.text.splitlines(), start=1):
            for pattern in self.patterns:
                match = pattern.regex.search(line)
                if not match:
                    continue
                findings.append(
                    Finding(
                        rule_id=pattern.rule_id,
                        title=pattern.title,
                        description="A shell command pattern can create destructive, opaque, or data-exfiltration behavior.",
                        severity=pattern.severity,
                        category=Category.SHELL,
                        file_path=context.relative_path,
                        line=line_number,
                        column=match.start() + 1,
                        evidence=line.strip()[:240],
                        recommendation=pattern.recommendation,
                    )
                )
        return findings


def _looks_shell_relevant(context: FileContext) -> bool:
    suffix = context.path.suffix.lower()
    return context.path.name in SHELL_FILENAMES or suffix in SHELL_SUFFIXES


def _is_github_workflow(context: FileContext) -> bool:
    normalized = context.relative_path.replace("\\", "/")
    return "/.github/workflows/" in f"/{normalized}" and context.path.suffix.lower() in {".yml", ".yaml"}

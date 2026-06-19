from __future__ import annotations

from collections import Counter
from hashlib import sha256
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(str, Enum):
    SECRETS = "secrets"
    MCP = "mcp"
    SHELL = "shell"
    GITHUB_ACTIONS = "github-actions"
    AI_TOOL = "ai-tool"
    FILESYSTEM = "filesystem"
    SUPPLY_CHAIN = "supply-chain"


SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Finding(BaseModel):
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    file_path: str
    line: int | None = None
    column: int | None = None
    evidence: str | None = None
    recommendation: str
    remediation: "Remediation | None" = None
    fingerprint: str | None = None

    def stable_fingerprint(self) -> str:
        parts = [
            self.rule_id,
            self.file_path.replace("\\", "/"),
            str(self.line or ""),
            self.evidence or "",
        ]
        return sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


class Remediation(BaseModel):
    summary: str
    steps: list[str] = Field(default_factory=list)
    effort: str = "medium"
    automatable: bool = False


class ScanSummary(BaseModel):
    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)


class ScanResult(BaseModel):
    target: str
    findings: list[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)

    @classmethod
    def from_findings(cls, target: Path, findings: list[Finding]) -> "ScanResult":
        findings = [
            finding if finding.fingerprint else finding.model_copy(update={"fingerprint": finding.stable_fingerprint()})
            for finding in findings
        ]
        severities = Counter(f.severity.value for f in findings)
        categories = Counter(f.category.value for f in findings)
        return cls(
            target=str(target),
            findings=findings,
            summary=ScanSummary(
                total=len(findings),
                by_severity=dict(sorted(severities.items())),
                by_category=dict(sorted(categories.items())),
            ),
        )


class FileContext(BaseModel):
    path: Path
    relative_path: str
    text: str

    model_config = {"arbitrary_types_allowed": True}

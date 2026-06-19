from __future__ import annotations

import json
from json import JSONDecodeError
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from agent_security_scanner.models import Finding, ScanResult


class BaselineEntry(BaseModel):
    fingerprint: str
    rule_id: str
    file_path: str
    line: int | None = None
    severity: str
    title: str


class Baseline(BaseModel):
    version: int = 1
    generated_at: str
    entries: list[BaselineEntry] = Field(default_factory=list)

    @property
    def fingerprints(self) -> set[str]:
        return {entry.fingerprint for entry in self.entries}


class BaselineLoadError(ValueError):
    """Raised when a baseline file cannot be loaded safely."""


def load_baseline(path: Path) -> Baseline:
    if not path.exists():
        raise BaselineLoadError(f"Baseline file does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return Baseline.model_validate(payload)
    except OSError as exc:
        raise BaselineLoadError(f"Cannot read baseline file: {path}") from exc
    except JSONDecodeError as exc:
        raise BaselineLoadError(f"Baseline file is not valid JSON: {path}") from exc
    except ValidationError as exc:
        raise BaselineLoadError(f"Baseline file has an invalid structure: {path}") from exc



def write_baseline(path: Path, result: ScanResult) -> Baseline:
    baseline = Baseline(
        generated_at=datetime.now(timezone.utc).isoformat(),
        entries=[_entry_for(finding) for finding in result.findings],
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(baseline.model_dump(mode="json"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return baseline


def filter_baseline(result: ScanResult, baseline: Baseline) -> ScanResult:
    known = baseline.fingerprints
    return ScanResult.from_findings(
        Path(result.target),
        [finding for finding in result.findings if finding.fingerprint not in known],
    )


def _entry_for(finding: Finding) -> BaselineEntry:
    return BaselineEntry(
        fingerprint=finding.fingerprint or finding.stable_fingerprint(),
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        line=finding.line,
        severity=finding.severity.value,
        title=finding.title,
    )

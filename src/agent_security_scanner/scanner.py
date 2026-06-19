from __future__ import annotations

from pathlib import Path

from agent_security_scanner.config import IgnoreRule, ProjectConfig, ScannerConfig, path_matches
from agent_security_scanner.models import FileContext, Finding, ScanResult, Severity, SEVERITY_ORDER
from agent_security_scanner.remediation import enrich_remediation
from agent_security_scanner.rules import DEFAULT_RULES
from agent_security_scanner.rules.base import Rule
from agent_security_scanner.utils.files import iter_candidate_files, read_text_file


class Scanner:
    def __init__(
        self,
        config: ScannerConfig | None = None,
        rules: list[Rule] | None = None,
        project_config: ProjectConfig | None = None,
    ) -> None:
        self.config = config or ScannerConfig()
        self.project_config = project_config or ProjectConfig.empty()
        if self.project_config.max_file_size_bytes:
            self.config = ScannerConfig(
                excluded_dirs=self.config.excluded_dirs,
                max_file_size_bytes=self.project_config.max_file_size_bytes,
                exclude_patterns=self.config.exclude_patterns,
            )
        self.rules = rules or DEFAULT_RULES

    def scan(self, target: Path, min_severity: Severity = Severity.INFO) -> ScanResult:
        root = target.resolve()
        findings: list[Finding] = []
        for path in iter_candidate_files(root, self.config):
            text = read_text_file(path)
            if text is None:
                continue
            relative_path = _relative_to_root(path, root)
            if self._is_excluded(relative_path):
                continue
            context = FileContext(path=path, relative_path=relative_path, text=text)
            for rule in self.rules:
                findings.extend(rule.scan(context))

        effective_min_severity = self.project_config.min_severity or min_severity
        filtered = [
            finding
            for finding in findings
            if SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[effective_min_severity]
            and self._rule_is_enabled(finding.rule_id)
            and not self._is_ignored(finding)
        ]
        filtered = enrich_remediation(filtered)
        filtered.sort(key=lambda item: (-SEVERITY_ORDER[item.severity], item.file_path, item.line or 0, item.rule_id))
        return ScanResult.from_findings(root, filtered)

    def _is_excluded(self, relative_path: str) -> bool:
        patterns = (*self.config.exclude_patterns, *self.project_config.exclude)
        return any(path_matches(relative_path, pattern) for pattern in patterns)

    def _rule_is_enabled(self, rule_id: str) -> bool:
        normalized = rule_id.upper()
        if self.project_config.enabled_rules and normalized not in self.project_config.enabled_rules:
            return False
        return normalized not in self.project_config.disabled_rules

    def _is_ignored(self, finding: Finding) -> bool:
        return any(_ignore_matches(finding, ignore_rule) for ignore_rule in self.project_config.ignore)


def _relative_to_root(path: Path, root: Path) -> str:
    base = root.parent if root.is_file() else root
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


def _ignore_matches(finding: Finding, ignore_rule: IgnoreRule) -> bool:
    if ignore_rule.rule_id and ignore_rule.rule_id.upper() != finding.rule_id.upper():
        return False
    if ignore_rule.path and not path_matches(finding.file_path, ignore_rule.path):
        return False
    return bool(ignore_rule.rule_id or ignore_rule.path)

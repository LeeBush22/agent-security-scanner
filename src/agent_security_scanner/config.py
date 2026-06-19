from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

import yaml

from agent_security_scanner.i18n import Language, normalize_language
from agent_security_scanner.models import Severity


@dataclass(frozen=True)
class ScannerConfig:
    excluded_dirs: set[str] = field(
        default_factory=lambda: {
            ".git",
            ".hg",
            ".svn",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".tox",
            ".venv",
            "__pycache__",
            "build",
            "dist",
            "node_modules",
            "output",
            "venv",
        }
    )
    max_file_size_bytes: int = 1_000_000
    exclude_patterns: tuple[str, ...] = ()


@dataclass(frozen=True)
class IgnoreRule:
    rule_id: str | None = None
    path: str | None = None
    reason: str | None = None

    @classmethod
    def from_mapping(cls, value: object) -> "IgnoreRule":
        if not isinstance(value, dict):
            return cls()
        return cls(
            rule_id=_as_optional_str(value.get("rule_id")),
            path=_as_optional_str(value.get("path")),
            reason=_as_optional_str(value.get("reason")),
        )


@dataclass(frozen=True)
class ProjectConfig:
    config_path: Path | None = None
    min_severity: Severity | None = None
    language: Language | None = None
    exclude: tuple[str, ...] = ()
    disabled_rules: frozenset[str] = frozenset()
    enabled_rules: frozenset[str] = frozenset()
    ignore: tuple[IgnoreRule, ...] = ()
    max_file_size_bytes: int | None = None

    @classmethod
    def empty(cls) -> "ProjectConfig":
        return cls()


CONFIG_FILENAMES = (
    ".agent-scan.yml",
    ".agent-scan.yaml",
)


def load_project_config(target: Path, config_path: Path | None = None, no_config: bool = False) -> ProjectConfig:
    if no_config:
        return ProjectConfig.empty()

    resolved_path = config_path if config_path else find_project_config(target)
    if resolved_path is None:
        return ProjectConfig.empty()

    try:
        raw = yaml.safe_load(resolved_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return ProjectConfig.empty()

    if not isinstance(raw, dict):
        return ProjectConfig.empty()

    ignored = [_rule for _rule in _as_list(raw.get("ignore"))]
    ignored.extend(_as_list(raw.get("allowlist")))

    return ProjectConfig(
        config_path=resolved_path,
        min_severity=_parse_severity(raw.get("min_severity")),
        language=_parse_language(raw.get("language")),
        exclude=tuple(_as_str_list(raw.get("exclude"))),
        disabled_rules=frozenset(rule.upper() for rule in _as_str_list(raw.get("disabled_rules"))),
        enabled_rules=frozenset(rule.upper() for rule in _as_str_list(raw.get("enabled_rules"))),
        ignore=tuple(IgnoreRule.from_mapping(item) for item in ignored),
        max_file_size_bytes=_parse_positive_int(raw.get("max_file_size_bytes")),
    )


def find_project_config(target: Path) -> Path | None:
    base = target.resolve()
    if base.is_file():
        base = base.parent
    for directory in (base, *base.parents):
        for filename in CONFIG_FILENAMES:
            candidate = directory / filename
            if candidate.is_file():
                return candidate
    return None


def path_matches(path: str, pattern: str) -> bool:
    normalized_path = path.replace("\\", "/").lstrip("./")
    normalized_pattern = pattern.replace("\\", "/").lstrip("./")
    if not normalized_pattern:
        return False
    if fnmatch(normalized_path, normalized_pattern) or fnmatch(f"./{normalized_path}", normalized_pattern):
        return True
    if _is_plain_path(normalized_pattern):
        plain = normalized_pattern.rstrip("/")
        return normalized_path == plain or normalized_path.startswith(f"{plain}/")
    return False


def _is_plain_path(pattern: str) -> bool:
    return not any(char in pattern for char in "*?[]")


def _as_optional_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _as_list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _as_str_list(value: object) -> list[str]:
    return [str(item) for item in _as_list(value) if str(item).strip()]


def _parse_severity(value: object) -> Severity | None:
    if value is None:
        return None
    try:
        return Severity(str(value).lower())
    except ValueError:
        return None


def _parse_positive_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _parse_language(value: object) -> Language | None:
    if value is None:
        return None
    parsed = normalize_language(value, default=Language.EN)
    return parsed if str(value).strip().lower() in {"en", "zh"} else None

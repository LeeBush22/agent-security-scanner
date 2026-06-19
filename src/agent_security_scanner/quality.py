from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from agent_security_scanner.models import Category, Severity
from agent_security_scanner.rules_catalog import RULE_CATALOG, RULE_ID_RE, RULE_PREFIX_CATEGORY, rule_by_id, rule_prefix


@dataclass(frozen=True)
class QualityCheck:
    name: str
    ok: bool
    detail: str


def collect_quality_checks(source_root: Path | None = None) -> list[QualityCheck]:
    source_root = source_root or Path(__file__).resolve().parent
    checks = [
        _check_duplicate_rule_ids(),
        _check_rule_id_format(),
        _check_rule_prefix_categories(),
        _check_rule_metadata_completeness(),
    ]
    checks.extend(_check_emitted_rule_ids(source_root))
    return checks


def quality_checks_pass(source_root: Path | None = None) -> bool:
    return all(check.ok for check in collect_quality_checks(source_root))


def _check_duplicate_rule_ids() -> QualityCheck:
    seen: set[str] = set()
    duplicates: list[str] = []
    for rule in RULE_CATALOG:
        if rule.rule_id in seen:
            duplicates.append(rule.rule_id)
        seen.add(rule.rule_id)
    return QualityCheck("rule_catalog_unique_ids", not duplicates, ", ".join(sorted(duplicates)) or f"{len(seen)} rules")


def _check_rule_id_format() -> QualityCheck:
    invalid = [rule.rule_id for rule in RULE_CATALOG if not RULE_ID_RE.match(rule.rule_id)]
    return QualityCheck("rule_catalog_id_format", not invalid, ", ".join(invalid) or "all rule IDs use PREFIX###")


def _check_rule_prefix_categories() -> QualityCheck:
    mismatches = [
        f"{rule.rule_id}:{rule.category.value}"
        for rule in RULE_CATALOG
        if RULE_PREFIX_CATEGORY.get(rule_prefix(rule.rule_id)) != rule.category
    ]
    return QualityCheck(
        "rule_catalog_prefix_category",
        not mismatches,
        ", ".join(mismatches) or "all prefixes match categories",
    )


def _check_rule_metadata_completeness() -> QualityCheck:
    invalid = [
        rule.rule_id
        for rule in RULE_CATALOG
        if not rule.title.strip()
        or not rule.description.strip()
        or not isinstance(rule.category, Category)
        or not isinstance(rule.severity, Severity)
    ]
    return QualityCheck(
        "rule_catalog_metadata",
        not invalid,
        ", ".join(invalid) or "all rules have title, description, category, and severity",
    )


def _check_emitted_rule_ids(source_root: Path) -> list[QualityCheck]:
    rules_dir = source_root / "rules"
    if not rules_dir.exists():
        return [QualityCheck("rule_emitters_present", False, f"missing rules directory: {rules_dir}")]

    emitted_ids = _collect_literal_rule_ids(rules_dir)
    missing = sorted(rule_id for rule_id in emitted_ids if rule_by_id(rule_id) is None)
    stale = sorted(rule.rule_id for rule in RULE_CATALOG if rule.rule_id not in emitted_ids)
    return [
        QualityCheck(
            "rule_emitters_registered",
            not missing,
            ", ".join(missing) or f"{len(emitted_ids)} emitted rule IDs registered",
        ),
        QualityCheck(
            "rule_catalog_reachable",
            not stale,
            ", ".join(stale) or "all catalog rules are emitted by scanners",
        ),
    ]


def _collect_literal_rule_ids(rules_dir: Path) -> set[str]:
    rule_ids: set[str] = set()
    for path in rules_dir.glob("*.py"):
        if path.name in {"__init__.py", "base.py"}:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and RULE_ID_RE.match(node.value):
                rule_ids.add(node.value)
    return rule_ids

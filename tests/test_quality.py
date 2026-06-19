from pathlib import Path

from agent_security_scanner.quality import collect_quality_checks, quality_checks_pass
from agent_security_scanner.rules_catalog import RULE_CATALOG, RULE_ID_RE, rule_by_id, rule_help_uri


def test_rule_catalog_quality_checks_pass():
    checks = collect_quality_checks()

    assert checks
    assert all(check.ok for check in checks), [check for check in checks if not check.ok]
    assert quality_checks_pass()


def test_rule_catalog_ids_are_lookupable_and_have_help_uris():
    for rule in RULE_CATALOG:
        assert RULE_ID_RE.match(rule.rule_id)
        assert rule_by_id(rule.rule_id) == rule
        assert rule_help_uri(rule.rule_id).endswith(rule.rule_id.lower() + "-" + _slug(rule.title))


def test_quality_check_detects_unregistered_emitted_rule(tmp_path: Path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "custom.py").write_text('rule_id = "SEC999"\n', encoding="utf-8")

    checks = collect_quality_checks(tmp_path)
    registered_check = next(check for check in checks if check.name == "rule_emitters_registered")

    assert not registered_check.ok
    assert "SEC999" in registered_check.detail


def _slug(value: str) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")

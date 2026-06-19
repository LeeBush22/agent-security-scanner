from __future__ import annotations

from collections import defaultdict

from agent_security_scanner.i18n import Language, category_label, rule_description, rule_title, severity_label
from agent_security_scanner.rules_catalog import RULE_CATALOG, RuleInfo, rule_anchor


def render_rules_markdown(language: Language = Language.EN) -> str:
    return _render_rules_markdown_zh() if language == Language.ZH else _render_rules_markdown_en()


def _render_rules_markdown_en() -> str:
    lines = [
        "# Agent Security Scanner Rules",
        "",
        "This document is generated from the built-in rule catalog. It is intended for release review, SARIF metadata, and users who want to understand what the scanner checks.",
        "",
        f"Total built-in rules: **{len(RULE_CATALOG)}**",
        "",
        "## Categories",
        "",
        "| Category | Rules |",
        "|---|---:|",
    ]
    grouped = _group_rules()
    for category in sorted(grouped):
        lines.append(f"| `{category}` | {len(grouped[category])} |")

    lines.extend(["", "## Rule Index", ""])
    for category in sorted(grouped):
        lines.extend([f"### {category}", "", "| Rule | Severity | Title | Description |", "|---|---|---|---|"])
        for rule in grouped[category]:
            lines.append(
                f"| [{rule.rule_id}](#{rule_anchor(rule.rule_id)}) | `{rule.severity.value}` | {rule.title} | {rule.description} |"
            )
        lines.append("")

    lines.extend(["## Rule Details", ""])
    for rule in RULE_CATALOG:
        lines.extend(
            [
                f"### {rule.rule_id} {rule.title}",
                "",
                f"- Category: `{rule.category.value}`",
                f"- Severity: `{rule.severity.value}`",
                f"- Description: {rule.description}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _render_rules_markdown_zh() -> str:
    lines = [
        "# Agent Security Scanner 规则索引",
        "",
        "本文档由内置规则目录生成，用于发布前复核、SARIF 元数据和用户理解扫描范围。",
        "",
        f"内置规则总数：**{len(RULE_CATALOG)}**",
        "",
        "## 规则分类",
        "",
        "| 分类 | 规则数 |",
        "|---|---:|",
    ]
    grouped = _group_rules()
    for category in sorted(grouped):
        lines.append(f"| `{category}` | {len(grouped[category])} |")

    lines.extend(["", "## 规则总览", ""])
    for category in sorted(grouped):
        lines.extend([f"### {category_label(category, Language.ZH)}", "", "| 规则 | 等级 | 标题 | 说明 |", "|---|---|---|---|"])
        for rule in grouped[category]:
            lines.append(
                f"| [{rule.rule_id}](#{rule_anchor(rule.rule_id)}) | `{severity_label(rule.severity.value, Language.ZH)}` | {rule_title(rule.rule_id, rule.title, Language.ZH)} | {rule_description(rule.rule_id, rule.description, Language.ZH)} |"
            )
        lines.append("")

    lines.extend(["## 规则详情", ""])
    for rule in RULE_CATALOG:
        lines.extend(
            [
                f'<a id="{rule_anchor(rule.rule_id)}"></a>',
                "",
                f"### {rule.rule_id} {rule_title(rule.rule_id, rule.title, Language.ZH)}",
                "",
                f"- 分类：`{category_label(rule.category.value, Language.ZH)}`",
                f"- 等级：`{severity_label(rule.severity.value, Language.ZH)}`",
                f"- 中文标题：{rule_title(rule.rule_id, rule.title, Language.ZH)}",
                f"- 说明：{rule_description(rule.rule_id, rule.description, Language.ZH)}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _group_rules() -> dict[str, list[RuleInfo]]:
    grouped: dict[str, list[RuleInfo]] = defaultdict(list)
    for rule in RULE_CATALOG:
        grouped[rule.category.value].append(rule)
    return dict(grouped)

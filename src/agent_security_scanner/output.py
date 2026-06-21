from __future__ import annotations

import json

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agent_security_scanner import __display_version__, __version__
from agent_security_scanner.i18n import (
    Language,
    category_label,
    effort_label,
    remediation_steps,
    remediation_summary,
    rule_description,
    rule_recommendation,
    rule_title,
    severity_label,
    t,
)
from agent_security_scanner.models import Finding, ScanResult
from agent_security_scanner.rules_catalog import RuleInfo, rule_by_id, rule_help_uri, rule_prefix
from agent_security_scanner.terminal import responsive_console, sync_console_width


def render_json(result: ScanResult) -> str:
    return json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2)


def render_sarif(result: ScanResult) -> str:
    rules = {_rule_id(finding): _sarif_rule(finding) for finding in result.findings}
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-security-scanner",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/LeeBush22/agent-security-scanner",
                        "rules": list(rules.values()),
                    }
                },
                "results": [_sarif_result(finding) for finding in result.findings],
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render_markdown(result: ScanResult) -> str:
    return render_markdown_en(result)


def render_markdown_en(result: ScanResult) -> str:
    lines = [
        "# Agent Security Scanner Report",
        "",
        f"Target: `{result.target}`",
        "",
        "## Summary",
        "",
        f"- Total findings: **{result.summary.total}**",
        "",
        "### By Severity",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for severity, count in result.summary.by_severity.items():
        lines.append(f"| {severity} | {count} |")

    lines.extend(["", "### By Category", "", "| Category | Count |", "|---|---:|"])
    for category, count in result.summary.by_category.items():
        lines.append(f"| {category} | {count} |")

    lines.extend(["", "## Findings", ""])
    if not result.findings:
        lines.append("No findings.")
    for finding in result.findings:
        location = finding.file_path
        if finding.line:
            location = f"{location}:{finding.line}"
        lines.extend(
            [
                f"### {finding.rule_id}: {finding.title}",
                "",
                f"- Severity: `{finding.severity.value}`",
                f"- Category: `{finding.category.value}`",
                f"- File: `{location}`",
                f"- Description: {finding.description}",
            ]
        )
        if finding.evidence:
            lines.append(f"- Evidence: `{finding.evidence}`")
        lines.append(f"- Recommendation: {finding.recommendation}")
        if finding.remediation:
            lines.extend(
                [
                    f"- Remediation effort: `{finding.remediation.effort}`",
                    f"- Automatable: `{str(finding.remediation.automatable).lower()}`",
                    "",
                    "Remediation steps:",
                ]
            )
            for step in finding.remediation.steps:
                lines.append(f"1. {step}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown_zh(result: ScanResult) -> str:
    lines = [
        "# Agent Security Scanner 扫描报告",
        "",
        f"扫描目标：`{result.target}`",
        "",
        "## 摘要",
        "",
        f"- 发现总数：**{result.summary.total}**",
        "",
        "### 按风险等级统计",
        "",
        "| 风险等级 | 数量 |",
        "|---|---:|",
    ]
    for severity, count in result.summary.by_severity.items():
        lines.append(f"| {severity_label(severity, Language.ZH)} | {count} |")

    lines.extend(["", "### 按类型统计", "", "| 类型 | 数量 |", "|---|---:|"])
    for category, count in result.summary.by_category.items():
        lines.append(f"| {category_label(category, Language.ZH)} | {count} |")

    lines.extend(["", "## 发现详情", ""])
    if not result.findings:
        lines.append("未发现风险。")
    for finding in result.findings:
        location = finding.file_path
        if finding.line:
            location = f"{location}:{finding.line}"
        lines.extend(
            [
                f"### {finding.rule_id}: {rule_title(finding.rule_id, finding.title, Language.ZH)}",
                "",
                f"- 风险等级：`{severity_label(finding.severity.value, Language.ZH)}`",
                f"- 类型：`{category_label(finding.category.value, Language.ZH)}`",
                f"- 文件：`{location}`",
                f"- 说明：{rule_description(finding.rule_id, finding.description, Language.ZH)}",
            ]
        )
        if finding.evidence:
            lines.append(f"- 证据：`{finding.evidence}`")
        lines.append(f"- 建议：{rule_recommendation(finding.rule_id, finding.recommendation, Language.ZH)}")
        if finding.remediation:
            steps = remediation_steps(finding.rule_id, finding.remediation.steps, Language.ZH)
            lines.extend(
                [
                    f"- 修复难度：`{effort_label(finding.remediation.effort, Language.ZH)}`",
                    f"- 可自动化：`{'是' if finding.remediation.automatable else '否'}`",
                    f"- 修复摘要：{remediation_summary(finding.rule_id, finding.remediation.summary, Language.ZH)}",
                    "",
                    "修复步骤：",
                ]
            )
            for step in steps:
                lines.append(f"1. {step}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_terminal(
    result: ScanResult,
    console: Console | None = None,
    language: Language = Language.EN,
) -> None:
    console = responsive_console(console)
    width = sync_console_width(console)
    console.print(f"[bold]{t('agent_name', language)}[/bold]")
    console.print(f"{t('target', language)}: [cyan]{result.target}[/cyan]")
    console.print(f"{t('findings', language)}: [bold]{result.summary.total}[/bold]")
    console.print()

    if not result.findings:
        console.print(f"[green]{t('no_findings', language)}[/green]")
        return

    if width < 84:
        for finding in result.findings:
            location = finding.file_path
            if finding.line:
                location = f"{location}:{finding.line}"
            console.print(
                Panel(
                    "\n".join(
                        [
                            f"[bold]{finding.rule_id}[/bold] | {severity_label(finding.severity.value, language)}",
                            rule_title(finding.rule_id, finding.title, language),
                            f"{t('file', language)}: {location}",
                            f"{t('effort', language)}: "
                            f"{effort_label(finding.remediation.effort, language) if finding.remediation else ''}",
                        ]
                    ),
                    border_style=_severity_style(finding.severity.value),
                    expand=True,
                )
            )
        return

    table = Table(show_lines=False, expand=True)
    table.add_column(t("severity", language), style="bold")
    table.add_column(t("rule", language))
    table.add_column(t("title", language), ratio=2)
    table.add_column(t("file", language), ratio=2)
    table.add_column(t("line", language), justify="right")
    table.add_column(t("effort", language))

    for finding in result.findings:
        table.add_row(
            severity_label(finding.severity.value, language),
            finding.rule_id,
            rule_title(finding.rule_id, finding.title, language),
            finding.file_path,
            str(finding.line or ""),
            effort_label(finding.remediation.effort, language) if finding.remediation else "",
        )
    console.print(table)


def _severity_style(severity: str) -> str:
    return {
        "critical": "red",
        "high": "orange1",
        "medium": "yellow",
        "low": "cyan",
        "info": "green",
    }.get(severity, "white")


def render_welcome(console: Console | None = None, language: Language = Language.EN) -> None:
    console = responsive_console(console)
    left = Table.grid(padding=(0, 1))
    left.add_row(Align.center(f"[bold]{t('welcome_back', language)}[/bold]"))
    left.add_row("")
    left.add_row(Align.center("[bold orange1]  ___   ___  ___ [/bold orange1]"))
    left.add_row(Align.center("[bold orange1] / _ | / _ \\/ _ |[/bold orange1]"))
    left.add_row(Align.center("[bold orange1]/ __ |/ , _/ __ |[/bold orange1]"))
    left.add_row(Align.center("[bold orange1]/_/ |_/_/|_/_/ |_|[/bold orange1]"))
    left.add_row("")
    left.add_row(f"[bold]{t('local_first', language)}[/bold]")
    left.add_row(f"{t('version', language)}: [cyan]{__display_version__}[/cyan]")

    right = Table.grid(padding=(0, 1))
    right.add_row(f"[bold orange1]{t('quick_start', language)}[/bold orange1]")
    right.add_row("  agent-scan .")
    right.add_row("  agent-scan . --format markdown")
    right.add_row("  agent-scan . --format all")
    right.add_row("  agent-scan . --fail-on high")
    right.add_row("")
    right.add_row(f"[bold orange1]{t('reports', language)}[/bold orange1]")
    right.add_row("  output/<project>/<time>/en/<project>_<time>_en.md")
    right.add_row("  output/<project>/<time>/zh/<project>_<time>_zh.md")
    right.add_row("  output/<project>/<time>/en/<project>_<time>_en.xlsx")
    right.add_row("  output/<project>/<time>/zh/<project>_<time>_zh.pdf")
    right.add_row("  output/machine/agent-scan.sarif")
    right.add_row("")
    right.add_row(f"[bold orange1]{t('checks', language)}[/bold orange1]")
    right.add_row("  Secrets | MCP | Shell | GitHub Actions | AI coding tools")

    layout = Table.grid(expand=True)
    layout.add_column(ratio=1)
    layout.add_column(ratio=2)
    layout.add_row(left, right)
    sync_console_width(console)
    console.print(Panel(layout, title=f"Agent Security Scanner {__display_version__}", border_style="orange1", expand=True))


def _sarif_rule(finding: Finding) -> dict[str, object]:
    info = rule_by_id(_rule_id(finding))
    title = _rule_title_for_sarif(finding, info)
    description = _rule_description_for_sarif(finding, info)
    category = _rule_category_for_sarif(finding, info)
    severity = _rule_severity_for_sarif(finding, info)
    return {
        "id": _rule_id(finding),
        "name": title,
        "shortDescription": {"text": title},
        "fullDescription": {"text": description},
        "helpUri": rule_help_uri(_rule_id(finding)),
        "help": {
            "text": finding.recommendation,
            "markdown": f"**Recommendation:** {finding.recommendation}",
        },
        "properties": {
            "category": category,
            "severity": severity,
            "security-severity": _security_severity(severity),
            "precision": _sarif_precision(severity),
            "tags": _sarif_tags(finding, info),
            "remediation": _remediation_properties(finding),
        },
    }


def _sarif_result(finding: Finding) -> dict[str, object]:
    region: dict[str, object] = {}
    if finding.line:
        region["startLine"] = finding.line
    if finding.column:
        region["startColumn"] = finding.column
    if finding.evidence:
        region["snippet"] = {"text": finding.evidence}

    physical_location: dict[str, object] = {
        "artifactLocation": {"uri": finding.file_path.replace("\\", "/")},
    }
    if region:
        physical_location["region"] = region

    return {
        "ruleId": _rule_id(finding),
        "level": _sarif_level(finding.severity.value),
        "message": {"text": f"{finding.title}: {finding.recommendation}"},
        "locations": [{"physicalLocation": physical_location}],
        "properties": {
            "severity": finding.severity.value,
            "category": finding.category.value,
            "remediation": _remediation_properties(finding),
        },
    }


def _remediation_properties(finding: Finding) -> dict[str, object] | None:
    if not finding.remediation:
        return None
    return finding.remediation.model_dump(mode="json")


def _rule_id(finding: Finding) -> str:
    return finding.rule_id


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _security_severity(severity: str) -> str:
    return {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.0",
        "low": "2.5",
        "info": "1.0",
    }.get(severity, "1.0")


def _sarif_precision(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "high"
    if severity == "medium":
        return "medium"
    return "low"


def _sarif_tags(finding: Finding, info: RuleInfo | None) -> list[str]:
    category = _rule_category_for_sarif(finding, info)
    return [
        "security",
        "agent-security-scanner",
        category,
        rule_prefix(_rule_id(finding)).lower(),
        _rule_severity_for_sarif(finding, info),
    ]


def _rule_title_for_sarif(finding: Finding, info: RuleInfo | None) -> str:
    return info.title if info else finding.title


def _rule_description_for_sarif(finding: Finding, info: RuleInfo | None) -> str:
    return info.description if info else finding.description


def _rule_category_for_sarif(finding: Finding, info: RuleInfo | None) -> str:
    return info.category.value if info else finding.category.value


def _rule_severity_for_sarif(finding: Finding, info: RuleInfo | None) -> str:
    return info.severity.value if info else finding.severity.value

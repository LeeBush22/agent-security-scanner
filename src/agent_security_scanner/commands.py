from __future__ import annotations

import importlib.util
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agent_security_scanner.baseline import BaselineLoadError, filter_baseline, load_baseline, write_baseline
from agent_security_scanner.config import load_project_config
from agent_security_scanner.i18n import (
    Language,
    category_label,
    report_label,
    resolve_language,
    rule_title,
    severity_label,
    t,
)
from agent_security_scanner.models import SEVERITY_ORDER, ScanResult, Severity
from agent_security_scanner.output import (
    render_json,
    render_markdown_en,
    render_markdown_zh,
    render_sarif,
    render_terminal,
)
from agent_security_scanner.quality import collect_quality_checks
from agent_security_scanner.reports import write_excel_report, write_pdf_report
from agent_security_scanner.rules_docs import render_rules_markdown
from agent_security_scanner.rules_catalog import list_rules
from agent_security_scanner.scanner import Scanner
from agent_security_scanner.terminal import sync_console_width


VALID_OUTPUT_FORMATS = {"terminal", "json", "markdown", "sarif", "excel", "pdf", "all"}
INVALID_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
ReportProgress = Callable[[str, Path], None]

DEFAULT_CONFIG_TEXT = """# Agent Security Scanner configuration
# See README.md for all available options.

min_severity: info
language: en

exclude:
  - output/
  - vendor/
  - generated/**

disabled_rules: []
enabled_rules: []

ignore:
  # - rule_id: SEC001
  #   path: examples/sample-project/app.py
  #   reason: Intentional fake key used as a scanner fixture.

max_file_size_bytes: 1000000
"""


@dataclass(frozen=True)
class DiagnosticCheck:
    name: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class ReportPaths:
    root: Path
    english_dir: Path
    chinese_dir: Path
    machine_dir: Path
    english_markdown: Path
    chinese_markdown: Path
    english_excel: Path
    chinese_excel: Path
    english_pdf: Path
    chinese_pdf: Path
    sarif: Path
    json: Path


def run_scan(
    target: Path,
    output_format: str,
    output: Optional[Path],
    severity: Severity,
    fail_on: Optional[Severity],
    config: Optional[Path],
    no_config: bool,
    baseline: Optional[Path],
    update_baseline: bool,
    baseline_output: Path,
    console: Console,
    language: Language | None = None,
) -> None:
    if not target.exists():
        raise typer.BadParameter(f"Path does not exist: {target}")

    fmt = output_format.lower()
    if fmt not in VALID_OUTPUT_FORMATS:
        raise typer.BadParameter("--format must be one of: terminal, json, markdown, sarif, excel, pdf, all")

    project_config = load_project_config(target, config_path=config, no_config=no_config)
    effective_language = resolve_language(language, project_config.language)
    result = Scanner(project_config=project_config).scan(target, min_severity=severity)

    if update_baseline:
        written = write_baseline(baseline_output, result)
        console.print(
            f"{t('wrote_baseline', effective_language)} [cyan]{baseline_output}[/cyan] "
            f"({len(written.entries)} {t('finding_count', effective_language)})."
        )
        return

    if baseline:
        try:
            result = filter_baseline(result, load_baseline(baseline))
        except BaselineLoadError as exc:
            raise typer.BadParameter(str(exc)) from exc

    if fmt == "json":
        rendered = render_json(result)
        if output is not None:
            output = machine_report_file(output, "report.json")
    elif fmt == "sarif":
        rendered = render_sarif(result)
        output = machine_report_file(output, "agent-scan.sarif")
    elif fmt == "excel":
        paths = report_paths(output, target=result.target)
        write_excel_report(result, paths.english_excel, language=Language.EN)
        write_excel_report(result, paths.chinese_excel, language=Language.ZH)
        console.print(f"{t('wrote_english', effective_language)} [cyan]{paths.english_excel}[/cyan]")
        console.print(f"{t('wrote_chinese', effective_language)} [cyan]{paths.chinese_excel}[/cyan]")
        exit_if_gate_failed(result, fail_on, console, effective_language)
        return
    elif fmt == "pdf":
        paths = report_paths(output, target=result.target)
        write_pdf_report(result, paths.english_pdf, language=Language.EN)
        write_pdf_report(result, paths.chinese_pdf, language=Language.ZH)
        console.print(f"{t('wrote_english', effective_language)} [cyan]{paths.english_pdf}[/cyan]")
        console.print(f"{t('wrote_chinese', effective_language)} [cyan]{paths.chinese_pdf}[/cyan]")
        exit_if_gate_failed(result, fail_on, console, effective_language)
        return
    elif fmt == "all":
        paths = write_all_reports(result, report_dir(output))
        console.print(f"{t('wrote_reports', effective_language)} [cyan]{paths.root}[/cyan]")
        exit_if_gate_failed(result, fail_on, console, effective_language)
        return
    elif fmt == "markdown":
        paths = report_paths(output, target=result.target)
        paths.english_dir.mkdir(parents=True, exist_ok=True)
        paths.chinese_dir.mkdir(parents=True, exist_ok=True)
        english_report = paths.english_markdown
        chinese_report = paths.chinese_markdown
        english_report.write_text(render_markdown_en(result), encoding="utf-8")
        chinese_report.write_text(render_markdown_zh(result), encoding="utf-8")
        console.print(f"{t('wrote_english', effective_language)} [cyan]{english_report}[/cyan]")
        console.print(f"{t('wrote_chinese', effective_language)} [cyan]{chinese_report}[/cyan]")
        exit_if_gate_failed(result, fail_on, console, effective_language)
        return
    else:
        if output:
            rendered = render_markdown_en(result)
        else:
            render_terminal(result, console, language=effective_language)
            exit_if_gate_failed(result, fail_on, console, effective_language)
            return

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        console.print(f"{t('wrote_report', effective_language)} [cyan]{output}[/cyan]")
    else:
        typer.echo(rendered)
    exit_if_gate_failed(result, fail_on, console, effective_language)


def write_all_reports(result: ScanResult, directory: Path, progress: ReportProgress | None = None) -> ReportPaths:
    paths = report_paths(directory, target=result.target)
    paths.english_dir.mkdir(parents=True, exist_ok=True)
    paths.chinese_dir.mkdir(parents=True, exist_ok=True)
    paths.machine_dir.mkdir(parents=True, exist_ok=True)
    if progress:
        progress("markdown_en", paths.english_markdown)
    paths.english_markdown.write_text(render_markdown_en(result), encoding="utf-8")
    if progress:
        progress("markdown_zh", paths.chinese_markdown)
    paths.chinese_markdown.write_text(render_markdown_zh(result), encoding="utf-8")
    if progress:
        progress("json", paths.json)
    paths.json.write_text(render_json(result), encoding="utf-8")
    if progress:
        progress("sarif", paths.sarif)
    paths.sarif.write_text(render_sarif(result), encoding="utf-8")
    if progress:
        progress("excel_en", paths.english_excel)
    write_excel_report(result, paths.english_excel, language=Language.EN)
    if progress:
        progress("excel_zh", paths.chinese_excel)
    write_excel_report(result, paths.chinese_excel, language=Language.ZH)
    if progress:
        progress("pdf_en", paths.english_pdf)
    write_pdf_report(result, paths.english_pdf, language=Language.EN)
    if progress:
        progress("pdf_zh", paths.chinese_pdf)
    write_pdf_report(result, paths.chinese_pdf, language=Language.ZH)
    return paths


def write_default_config(target: Path, force: bool = False) -> Path:
    directory = target if not target.suffix else target.parent
    directory.mkdir(parents=True, exist_ok=True)
    config_path = directory / ".agent-scan.yml"
    if config_path.exists() and not force:
        raise typer.BadParameter(f"Config already exists: {config_path}. Use --force to overwrite.")
    config_path.write_text(DEFAULT_CONFIG_TEXT, encoding="utf-8")
    return config_path


def collect_report_files(output_dir: Path) -> list[tuple[str, Path]]:
    if not output_dir.exists():
        return []
    files: list[tuple[str, Path]] = []
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file():
            continue
        label = _report_label_for_path(path)
        if label:
            files.append((label, path))
    return files


def render_reports_table(output_dir: Path, console: Console, language: Language = Language.EN) -> None:
    width = sync_console_width(console)
    files = collect_report_files(output_dir)
    if not files:
        console.print(f"[yellow]{t('no_reports_found', language)} {output_dir}.[/yellow]")
        return

    table = Table(title=f"{t('reports_in', language)} {output_dir}", expand=True)
    table.add_column(t("format", language))
    table.add_column(t("filename", language))
    if width >= 92:
        table.add_column(t("file", language), ratio=2)
    table.add_column(t("size", language), justify="right")
    for label, path in files:
        row = [report_label(label, language), path.name]
        if width >= 92:
            row.append(str(path))
        row.append(_format_size(path.stat().st_size))
        table.add_row(*row)
    console.print(table)


def render_rules_table(console: Console, category: str | None = None, language: Language = Language.EN) -> None:
    width = sync_console_width(console)
    rules = list_rules(category)
    if not rules:
        console.print(f"[yellow]{t('no_rules_found', language)}: {category}[/yellow]")
        return

    if width < 78:
        for rule in rules:
            console.print(
                Panel(
                    "\n".join(
                        [
                            f"[bold]{rule.rule_id}[/bold] | {severity_label(rule.severity.value, language)}",
                            category_label(rule.category.value, language),
                            rule_title(rule.rule_id, rule.title, language),
                        ]
                    ),
                    border_style=_severity_style(rule.severity.value),
                    expand=True,
                )
            )
        return

    table = Table(title=t("rules_title", language), expand=True)
    table.add_column(t("rule", language))
    table.add_column(t("category", language))
    table.add_column(t("severity", language))
    table.add_column(t("title", language), ratio=2)
    for rule in rules:
        table.add_row(
            rule.rule_id,
            category_label(rule.category.value, language),
            f"[{_severity_style(rule.severity.value)}]{severity_label(rule.severity.value, language)}[/{_severity_style(rule.severity.value)}]",
            rule_title(rule.rule_id, rule.title, language),
        )
    console.print(table)


def render_rules_markdown_output(language: Language = Language.EN) -> str:
    return render_rules_markdown(language)


def collect_diagnostics(project_dir: Path, output_dir: Path) -> list[DiagnosticCheck]:
    checks = [
        DiagnosticCheck(
            "python_version",
            sys.version_info >= (3, 10),
            ".".join(str(part) for part in sys.version_info[:3]),
        )
    ]
    for module_name, package_name in (
        ("typer", "Typer"),
        ("rich", "Rich"),
        ("pydantic", "Pydantic"),
        ("yaml", "PyYAML"),
        ("openpyxl", "openpyxl"),
        ("reportlab", "ReportLab"),
    ):
        checks.append(
            DiagnosticCheck(
                package_name,
                importlib.util.find_spec(module_name) is not None,
                "installed" if importlib.util.find_spec(module_name) is not None else "missing",
            )
        )

    checks.append(_path_check("project_directory", project_dir))
    checks.append(_output_writable_check(output_dir))
    for check in collect_quality_checks():
        checks.append(DiagnosticCheck(check.name, check.ok, check.detail))
    return checks


def render_doctor(
    console: Console,
    project_dir: Path,
    output_dir: Path,
    language: Language = Language.EN,
) -> bool:
    width = sync_console_width(console)
    checks = collect_diagnostics(project_dir, output_dir)
    table = Table(title=t("doctor_title", language), expand=True)
    table.add_column(t("check", language))
    table.add_column(t("status", language))
    if width >= 72:
        table.add_column(t("detail", language), ratio=2)
    for check in checks:
        row = [
            t(check.name, language),
            f"[green]{t('ok', language)}[/green]" if check.ok else f"[red]{t('fail', language)}[/red]",
        ]
        if width >= 72:
            row.append(_diagnostic_detail(check.detail, language))
        table.add_row(*row)
    console.print(table)
    return all(check.ok for check in checks)


def _severity_style(severity: str) -> str:
    return {
        "critical": "red",
        "high": "orange1",
        "medium": "yellow",
        "low": "cyan",
        "info": "green",
    }.get(severity, "white")


def report_dir(output: Path | None) -> Path:
    if output is None:
        return Path("output")
    if output.suffix:
        return output.parent
    return output


def report_paths(output: Path | None, target: str | Path | None = None) -> ReportPaths:
    root = report_dir(output)
    explicit_file = bool(output and output.suffix)
    if target is not None and not explicit_file:
        project_name = _safe_project_name(target)
        timestamped_root = _unique_path(root / project_name / _timestamp())
        root = timestamped_root
        base_name = f"{project_name}_{timestamped_root.name}"
        language_suffix = True
    elif explicit_file:
        base_name = _sanitize_filename(output.stem)
        language_suffix = False
    else:
        base_name = "report"
        language_suffix = False

    english_dir = root / "en"
    chinese_dir = root / "zh"
    machine_dir = root / "machine"
    english_name = f"{base_name}_en" if language_suffix else base_name
    chinese_name = f"{base_name}_zh" if language_suffix else base_name
    machine_name = f"{base_name}_machine" if language_suffix else base_name
    sarif_name = f"{machine_name}.sarif" if language_suffix else "agent-scan.sarif"
    return ReportPaths(
        root=root,
        english_dir=english_dir,
        chinese_dir=chinese_dir,
        machine_dir=machine_dir,
        english_markdown=english_dir / f"{english_name}.md",
        chinese_markdown=chinese_dir / f"{chinese_name}.md",
        english_excel=english_dir / f"{english_name}.xlsx",
        chinese_excel=chinese_dir / f"{chinese_name}.xlsx",
        english_pdf=english_dir / f"{english_name}.pdf",
        chinese_pdf=chinese_dir / f"{chinese_name}.pdf",
        sarif=machine_dir / sarif_name,
        json=machine_dir / f"{machine_name}.json",
    )


def machine_report_file(output: Path | None, default_name: str) -> Path:
    if output is None:
        return Path("output") / "machine" / default_name
    if output.suffix:
        return output
    return output / "machine" / default_name


def _report_label_for_path(path: Path) -> str | None:
    suffix = path.suffix.lower()
    language = path.parent.name.lower()
    if suffix == ".md":
        return "Markdown (Chinese)" if language == "zh" else "Markdown (English)"
    if suffix == ".xlsx":
        return "Excel (Chinese)" if language == "zh" else "Excel (English)"
    if suffix == ".pdf":
        return "PDF (Chinese)" if language == "zh" else "PDF (English)"
    if suffix == ".sarif":
        return "SARIF"
    if suffix == ".json":
        return "JSON"
    return None


def _safe_project_name(target: str | Path) -> str:
    path = Path(target)
    return _sanitize_filename(path.name or path.stem or "scan-target")


def _sanitize_filename(value: str) -> str:
    sanitized = INVALID_FILENAME_CHARS.sub("_", value).strip().strip(".")
    return sanitized or "scan-target"


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    for index in range(1, 1000):
        candidate = path.with_name(f"{path.name}_{index:02d}")
        if not candidate.exists():
            return candidate
    return path.with_name(f"{path.name}_{datetime.now().strftime('%f')}")


def exit_if_gate_failed(
    result: ScanResult,
    fail_on: Severity | None,
    console: Console,
    language: Language = Language.EN,
) -> None:
    if fail_on is None:
        return
    blocking = [
        finding
        for finding in result.findings
        if SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[fail_on]
    ]
    if not blocking:
        return
    console.print(
        f"[red]{t('fail_on_gate', language)}:[/red] {len(blocking)} "
        f"{t('finding_count', language)} {t('at_or_above', language)} {severity_label(fail_on.value, language)}."
    )
    raise typer.Exit(code=1)


def _path_check(name: str, path: Path) -> DiagnosticCheck:
    return DiagnosticCheck(name, path.exists(), str(path))


def _output_writable_check(output_dir: Path) -> DiagnosticCheck:
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        probe = output_dir / ".agent-scan-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return DiagnosticCheck("output_directory_writable", False, str(exc))
    return DiagnosticCheck("output_directory_writable", True, str(output_dir))


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def _diagnostic_detail(detail: str, language: Language) -> str:
    if detail == "installed":
        return t("installed", language)
    if detail == "missing":
        return t("missing", language)
    return detail

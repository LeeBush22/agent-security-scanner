from __future__ import annotations

from pathlib import Path

import typer
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agent_security_scanner import __display_version__
from agent_security_scanner.baseline import BaselineLoadError, filter_baseline, load_baseline, write_baseline
from agent_security_scanner.commands import (
    report_paths,
    render_doctor,
    render_reports_table,
    render_rules_table,
    write_all_reports,
    write_default_config,
)
from agent_security_scanner.config import load_project_config
from agent_security_scanner.i18n import Language, other_language, t
from agent_security_scanner.interactive_input import BackRequested, PromptSession
from agent_security_scanner.models import ScanResult, Severity
from agent_security_scanner.output import render_terminal
from agent_security_scanner.reports import write_excel_report, write_pdf_report
from agent_security_scanner.scanner import Scanner
from agent_security_scanner.terminal import responsive_console, sync_console_width


def run_interactive(console: Console | None = None, language: Language = Language.EN) -> None:
    console = responsive_console(console)
    show_header = True
    last_target = Path(".").resolve()
    last_result: ScanResult | None = None

    while True:
        prompts = PromptSession(language=language)
        _print_menu(console, language, show_header=show_header)
        show_header = False
        try:
            choice = prompts.ask(t("select_option", language)).strip()
        except BackRequested:
            console.print(t("goodbye", language))
            return

        if choice in {"r", "refresh", "刷新"}:
            show_header = True
            continue
        elif choice in {"1", "scan", "current"}:
            _print_section(console, t("scan_current", language), language)
            result = _scan(Path("."), console, language)
            if result is not None:
                last_result = result
                last_target = Path(result.target)
            _print_action_boundary(console, language)
        elif choice in {"2", "path"}:
            try:
                _print_section(console, t("scan_another", language), language)
                _print_project_path_hint(console, language)
                _print_back_hint(console, language)
                target = Path(prompts.ask(t("path_to_scan", language), default="."))
                result = _scan(target, console, language)
                if result is not None:
                    last_result = result
                    last_target = Path(result.target)
                _print_action_boundary(console, language)
            except BackRequested:
                _returned(console, language)
        elif choice in {"3", "all"}:
            try:
                _print_section(console, t("generate_all_reports", language), language)
                _print_last_target_hint(console, language)
                _print_back_hint(console, language)
                target = Path(prompts.ask(t("all_reports_project_directory", language), default=str(last_target)))
                output_dir = Path(prompts.ask(t("all_reports_output_directory", language), default="output"))
                last_result = _write_all_reports(target, output_dir, console, language, cached_result=last_result)
                last_target = Path(last_result.target)
                _print_action_boundary(console, language)
            except OSError as exc:
                _print_file_error(console, exc, language)
                _print_action_boundary(console, language)
            except BackRequested:
                _returned(console, language)
        elif choice in {"4", "reports"}:
            try:
                _print_section(console, t("generate_excel_pdf", language), language)
                _print_last_target_hint(console, language)
                _print_back_hint(console, language)
                target = Path(prompts.ask(t("excel_pdf_project_directory", language), default=str(last_target)))
                output_dir = Path(prompts.ask(t("excel_pdf_output_directory", language), default="output"))
                result = _result_for_reports(target, console, language, cached_result=last_result)
                paths = report_paths(output_dir, target=result.target)
                _print_report_phase(console, language, "excel_en", paths.english_excel)
                write_excel_report(result, paths.english_excel, language=Language.EN)
                _print_report_phase(console, language, "excel_zh", paths.chinese_excel)
                write_excel_report(result, paths.chinese_excel, language=Language.ZH)
                _print_report_phase(console, language, "pdf_en", paths.english_pdf)
                write_pdf_report(result, paths.english_pdf, language=Language.EN)
                _print_report_phase(console, language, "pdf_zh", paths.chinese_pdf)
                write_pdf_report(result, paths.chinese_pdf, language=Language.ZH)
                last_result = result
                last_target = Path(result.target)
                console.print(f"{t('report_scan_target', language)}: [cyan]{result.target}[/cyan]")
                console.print(f"{t('wrote_reports', language)} [cyan]{paths.root}[/cyan].")
                _print_action_boundary(console, language)
            except OSError as exc:
                _print_file_error(console, exc, language)
                _print_action_boundary(console, language)
            except BackRequested:
                _returned(console, language)
        elif choice in {"5", "init"}:
            try:
                _print_section(console, t("init_config", language), language)
                _print_back_hint(console, language)
                target = Path(prompts.ask(t("config_directory", language), default="."))
                force = prompts.confirm(t("overwrite_existing", language), default=False)
                try:
                    config_path = write_default_config(target, force=force)
                except typer.BadParameter as exc:
                    console.print(f"[yellow]{exc}[/yellow]")
                else:
                    console.print(f"{t('wrote_config', language)} [cyan]{config_path}[/cyan].")
                _print_action_boundary(console, language)
            except OSError as exc:
                _print_file_error(console, exc, language)
                _print_action_boundary(console, language)
            except BackRequested:
                _returned(console, language)
        elif choice in {"6", "doctor"}:
            try:
                _print_section(console, t("run_doctor", language), language)
                _print_path_hint(console, language)
                _print_back_hint(console, language)
                target = Path(prompts.ask(t("project_directory_prompt", language), default="."))
                output_dir = Path(prompts.ask(t("output_directory", language), default="output"))
                render_doctor(console, target, output_dir, language=language)
                _print_action_boundary(console, language)
            except BackRequested:
                _returned(console, language)
        elif choice in {"7", "rules"}:
            try:
                _print_section(console, t("list_rules", language), language, hint=t("category_filter_hint", language))
                _print_back_hint(console, language)
                category = prompts.ask(t("category_filter", language), default="").strip() or None
                render_rules_table(console, category=category, language=language)
                _print_action_boundary(console, language)
            except BackRequested:
                _returned(console, language)
        elif choice in {"8", "report"}:
            try:
                _print_section(console, t("list_reports", language), language)
                _print_back_hint(console, language)
                output_dir = Path(prompts.ask(t("output_directory", language), default="output"))
                render_reports_table(output_dir, console, language=language)
                _print_action_boundary(console, language)
            except BackRequested:
                _returned(console, language)
        elif choice in {"9", "baseline"}:
            try:
                _print_section(console, t("create_baseline", language), language)
                _print_back_hint(console, language)
                target = Path(prompts.ask(t("baseline_project_directory", language), default="."))
                baseline_path = Path(prompts.ask(t("baseline_file_path", language), default=".agent-scan-baseline.json"))
                baseline = write_baseline(baseline_path, _scan_result(target))
                console.print(
                    f"{t('wrote_baseline', language)} [cyan]{baseline_path}[/cyan] "
                    f"({len(baseline.entries)} {t('finding_count', language)})."
                )
                _print_action_boundary(console, language)
            except OSError as exc:
                _print_file_error(console, exc, language)
                _print_action_boundary(console, language)
            except BackRequested:
                _returned(console, language)
        elif choice in {"10", "gate"}:
            try:
                _print_section(console, t("baseline_gate_preview", language), language)
                _print_back_hint(console, language)
                target = Path(prompts.ask(t("path_to_scan", language), default="."))
                baseline_path = Path(prompts.ask(t("baseline_path", language), default=".agent-scan-baseline.json"))
                result = filter_baseline(_scan_result(target), load_baseline(baseline_path))
                render_terminal(result, console, language=language)
                blocking = [
                    finding for finding in result.findings if finding.severity in {Severity.HIGH, Severity.CRITICAL}
                ]
                if blocking:
                    console.print(f"[red]{t('gate_fail', language)}:[/red] {len(blocking)} {t('high_critical', language)}.")
                else:
                    console.print(f"[green]{t('gate_pass', language)}[/green]")
                _print_action_boundary(console, language)
            except BaselineLoadError as exc:
                _print_error(console, exc)
                console.print(f"[dim]{t('baseline_missing_hint', language)}[/dim]")
                _print_action_boundary(console, language)
            except BackRequested:
                _returned(console, language)
        elif choice in {"11", "help"}:
            _print_section(console, t("show_examples", language), language)
            _print_examples(console, language)
            _print_action_boundary(console, language)
        elif choice in {"12", "lang", "language"}:
            language = other_language(language)
            _print_section(console, t("switch_language", language), language)
            console.print(f"[green]{t('language_now', language)}[/green]")
            _print_action_boundary(console, language)
            show_header = True
        elif choice in {"13", "q", "quit", "exit"}:
            console.print(t("goodbye", language))
            return
        else:
            console.print(f"[yellow]{t('unknown_option', language)}[/yellow]")


def _scan(target: Path, console: Console, language: Language) -> ScanResult | None:
    if not target.exists():
        console.print(f"[red]{t('path_not_exist', language)}:[/red] {target}")
        return None
    result = _scan_result(target, console=console, language=language)
    render_terminal(result, console, language=language)
    return result


def _scan_result(target: Path, console: Console | None = None, language: Language = Language.EN) -> ScanResult:
    resolved_target = target.resolve()
    if console is not None:
        console.print(f"{_ui('Scan target', '扫描目标', language)}: [cyan]{resolved_target}[/cyan]")
        console.print(f"[dim]{_ui('Loading project configuration...', '正在加载项目配置...', language)}[/dim]")
    project_config = load_project_config(target)
    scanner = Scanner(project_config=project_config)
    if console is None:
        return scanner.scan(target)
    with console.status(
        f"[cyan]{_ui('Scanning files and applying security rules...', '正在扫描文件并执行安全规则...', language)}[/cyan]",
        spinner="dots",
    ):
        result = scanner.scan(target)
    console.print(
        f"[green]{_ui('Scan completed', '扫描完成', language)}[/green]: "
        f"{result.summary.total} {_ui('finding(s)', '个发现', language)}"
    )
    return result


def _write_all_reports(
    target: Path,
    output_dir: Path,
    console: Console,
    language: Language,
    cached_result: ScanResult | None = None,
) -> ScanResult:
    result = _result_for_reports(target, console, language, cached_result=cached_result)
    paths = write_all_reports(
        result,
        output_dir,
        progress=lambda phase, path: _print_report_phase(console, language, phase, path),
    )
    console.print(f"{t('report_scan_target', language)}: [cyan]{result.target}[/cyan]")
    console.print(f"{t('wrote_all_reports', language)} [cyan]{paths.root}[/cyan].")
    return result


def _result_for_reports(
    target: Path,
    console: Console,
    language: Language,
    cached_result: ScanResult | None = None,
) -> ScanResult:
    if not target.exists():
        raise FileNotFoundError(f"{t('path_not_exist', language)}: {target}")
    if cached_result is not None and _same_target(target, Path(cached_result.target)):
        console.print(
            f"[dim]{_ui('Using the last scan result for report generation.', '使用上一次扫描结果生成报告。', language)}[/dim]"
        )
        return cached_result
    console.print(
        f"[dim]{_ui('No matching cached scan result; rescanning before report generation.', '没有匹配的缓存扫描结果，生成报告前将重新扫描。', language)}[/dim]"
    )
    return _scan_result(target, console=console, language=language)


def _same_target(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return left == right


def _print_report_phase(console: Console, language: Language, phase: str, path: Path) -> None:
    labels = {
        "markdown_en": _ui("Generating English Markdown", "正在生成英文 Markdown", language),
        "markdown_zh": _ui("Generating Chinese Markdown", "正在生成中文 Markdown", language),
        "json": _ui("Generating JSON", "正在生成 JSON", language),
        "sarif": _ui("Generating SARIF", "正在生成 SARIF", language),
        "excel_en": _ui("Generating English Excel", "正在生成英文 Excel", language),
        "excel_zh": _ui("Generating Chinese Excel", "正在生成中文 Excel", language),
        "pdf_en": _ui("Generating English PDF", "正在生成英文 PDF", language),
        "pdf_zh": _ui("Generating Chinese PDF", "正在生成中文 PDF", language),
    }
    console.print(f"[dim]{labels.get(phase, phase)}:[/dim] [cyan]{path.name}[/cyan]")


def _returned(console: Console, language: Language) -> None:
    console.print(f"[dim]{t('back_to_menu', language)}[/dim]")


def _print_error(console: Console, error: Exception) -> None:
    console.print(f"[yellow]{error}[/yellow]")


def _print_file_error(console: Console, error: OSError, language: Language) -> None:
    console.print(f"[yellow]{t('file_operation_failed', language)}: {error}[/yellow]")
    console.print(f"[dim]{t('file_operation_hint', language)}[/dim]")


def _print_path_hint(console: Console, language: Language) -> None:
    _print_project_path_hint(console, language)
    console.print(f"[dim]{t('output_directory_hint', language)}[/dim]")


def _print_project_path_hint(console: Console, language: Language) -> None:
    console.print(f"[dim]{t('project_directory_hint', language)}[/dim]")


def _print_last_target_hint(console: Console, language: Language) -> None:
    console.print(f"[dim]{t('last_target_hint', language)}[/dim]")


def _print_back_hint(console: Console, language: Language) -> None:
    console.print(f"[dim]{t('back_hint', language)}[/dim]")


def _print_menu(console: Console, language: Language, show_header: bool = True) -> None:
    width = sync_console_width(console)
    if show_header:
        console.print(_header_panel(width, language))
    console.print(_menu_table(width, language))


def _header_panel(width: int, language: Language) -> Panel:
    logo = "\n".join(
        [
            "[bold orange1]  ___   ___  ___ [/bold orange1]",
            "[bold orange1] / _ | / _ \\/ _ |[/bold orange1]",
            "[bold orange1]/ __ |/ , _/ __ |[/bold orange1]",
            "[bold orange1]/_/ |_/_/|_/_/ |_|[/bold orange1]",
        ]
    )
    summary_lines = [
        f"[bold]{_ui('Welcome to Agent Security Scanner', '欢迎使用 Agent Security Scanner', language)}[/bold]",
        _ui(
            "Local-first scanner for AI Agent, MCP, AI coding tools, automation, and supply-chain risk.",
            "本地优先扫描 AI Agent、MCP、AI 编程工具、自动化和供应链风险。",
            language,
        ),
        f"{_ui('Privacy', '隐私', language)}: [green]{_ui('Local scan, no code upload', '本地扫描，不上传代码', language)}[/green]",
        f"{_ui('Version', '版本', language)}: [cyan]{__display_version__}[/cyan]",
    ]
    quick_lines = [
        f"[bold cyan]{_ui('Quick commands', '常用命令', language)}[/bold cyan]",
        "agent-scan .",
        "agent-scan . --format all",
        "agent-scan rules",
        "agent-scan",
    ]

    if width < 92:
        content = "\n".join([logo, "", *summary_lines, "", *quick_lines])
    else:
        layout = Table.grid(expand=True, padding=(0, 2))
        layout.add_column(ratio=1)
        layout.add_column(ratio=2)
        layout.add_column(ratio=1)
        layout.add_row(Align.center(logo), "\n".join(summary_lines), "\n".join(quick_lines))
        content = layout

    return Panel(
        content,
        title=f"Agent Security Scanner {__display_version__}",
        subtitle=_ui("Native Terminal CLI", "原生终端 CLI", language),
        border_style="orange1",
        expand=True,
    )


def _menu_table(width: int, language: Language) -> Table:
    items = [
        ("1", t("scan_current", language)),
        ("2", t("scan_another", language)),
        ("3", t("generate_all_reports", language)),
        ("4", t("generate_excel_pdf", language)),
        ("5", t("init_config", language)),
        ("6", t("run_doctor", language)),
        ("7", t("list_rules", language)),
        ("8", t("list_reports", language)),
        ("9", t("create_baseline", language)),
        ("10", t("baseline_gate_preview", language)),
        ("11", t("show_examples", language)),
        ("12", t("switch_language", language)),
        ("13", t("exit", language)),
    ]
    if width >= 104:
        table = Table(
            title=t("interactive_menu", language),
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold cyan",
            expand=True,
            show_lines=False,
        )
        table.add_column("#", justify="right", style="bold orange1", width=4)
        table.add_column(_ui("Action", "操作", language), ratio=1)
        table.add_column("#", justify="right", style="bold orange1", width=4)
        table.add_column(_ui("Action", "操作", language), ratio=1)
        midpoint = (len(items) + 1) // 2
        for left, right in zip(items[:midpoint], items[midpoint:] + [("", "")]):
            table.add_row(left[0], left[1], right[0], right[1])
    else:
        table = Table(
            title=t("interactive_menu", language),
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold cyan",
            expand=True,
            show_lines=False,
        )
        table.add_column("#", justify="right", style="bold orange1", width=4)
        table.add_column(_ui("Action", "操作", language), ratio=1)
        for number, label in items:
            table.add_row(number, label)
    table.caption = _ui(
        "Type 1-13 to choose; type r to refresh; type q to exit.",
        "输入 1-13 选择操作；输入 r 刷新布局；输入 q 退出。",
        language,
    )
    return table


def _print_section(console: Console, title: str, language: Language, hint: str | None = None) -> None:
    sync_console_width(console)
    console.print()
    console.rule(f"[bold cyan]{title}[/bold cyan]", style="cyan")
    if hint:
        console.print(f"[dim]{hint}[/dim]")


def _print_action_boundary(console: Console, language: Language) -> None:
    console.print(f"[dim]{_ui('End of output. Return to the menu below.', '本次输出结束，下方返回菜单。', language)}[/dim]")
    console.print()


def _ui(en: str, zh: str, language: Language) -> str:
    return zh if language == Language.ZH else en


def _print_examples(console: Console, language: Language) -> None:
    sync_console_width(console)
    console.print(
        Panel(
            "\n".join(
                [
                    "agent-scan .",
                    "agent-scan scan .",
                    "agent-scan init",
                    "agent-scan doctor",
                    "agent-scan rules",
                    "agent-scan report",
                    "agent-scan . --format all",
                    "agent-scan . --format excel",
                    "agent-scan . --format pdf",
                    "agent-scan . --update-baseline --baseline-output .agent-scan-baseline.json",
                    "agent-scan . --baseline .agent-scan-baseline.json --fail-on high",
                ]
            ),
            title=t("command_examples", language),
            border_style="orange1",
            expand=True,
        )
    )

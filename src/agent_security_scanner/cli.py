from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from agent_security_scanner import __display_version__
from agent_security_scanner.autofix import collect_fix_previews, render_fix_previews
from agent_security_scanner.commands import (
    collect_report_files,
    render_doctor,
    render_reports_table,
    render_rules_markdown_output,
    render_rules_table,
    run_scan,
    write_default_config,
)
from agent_security_scanner.config import load_project_config
from agent_security_scanner.i18n import Language, t
from agent_security_scanner.interactive import run_interactive
from agent_security_scanner.models import Severity
from agent_security_scanner.output import render_welcome
from agent_security_scanner.scanner import Scanner


app = typer.Typer(add_completion=False)
command_app = typer.Typer(
    add_completion=False,
    help="Local-first security scanner for AI Agent, MCP, and AI coding tool projects.",
)
COMMAND_NAMES = {"scan", "fix", "init", "doctor", "rules", "report"}


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"agent-security-scanner {__display_version__}")
        raise typer.Exit()


@app.command(
    help="Local-first security scanner for AI Agent, MCP, and AI coding tool projects.",
)
def main(
    path: Optional[Path] = typer.Argument(None, help="File or directory to scan. Omit to start interactive mode."),
    output_format: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json, markdown, sarif, excel, pdf, or all.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write output to a file. For markdown, this is a report directory and defaults to output/.",
    ),
    severity: Severity = typer.Option(Severity.INFO, "--severity", help="Minimum severity to include."),
    fail_on: Optional[Severity] = typer.Option(
        None,
        "--fail-on",
        help="Exit with code 1 when findings at or above this severity exist.",
    ),
    config: Optional[Path] = typer.Option(None, "--config", help="Path to .agent-scan.yml config file."),
    no_config: bool = typer.Option(False, "--no-config", help="Do not load project config files."),
    baseline: Optional[Path] = typer.Option(
        None,
        "--baseline",
        help="Only report findings not already present in this baseline file.",
    ),
    update_baseline: bool = typer.Option(
        False,
        "--update-baseline",
        help="Write the current full scan result as a baseline and exit.",
    ),
    baseline_output: Path = typer.Option(
        Path(".agent-scan-baseline.json"),
        "--baseline-output",
        help="Path used with --update-baseline.",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored terminal output."),
    language: Optional[Language] = typer.Option(None, "--lang", help="CLI language: en or zh."),
    welcome: bool = typer.Option(False, "--welcome", help="Show a welcome and quick-start screen, then exit."),
    version: Optional[bool] = typer.Option(None, "--version", callback=version_callback, help="Show version and exit."),
) -> None:
    console = Console(no_color=no_color)
    if welcome:
        render_welcome(console, language=language or Language.EN)
        return

    if path is None and _should_start_interactive(
        output_format=output_format,
        output=output,
        severity=severity,
        fail_on=fail_on,
        config=config,
        no_config=no_config,
        baseline=baseline,
        update_baseline=update_baseline,
    ):
        run_interactive(console, language=language or Language.EN)
        return

    run_scan(
        target=path or Path("."),
        output_format=output_format,
        output=output,
        severity=severity,
        fail_on=fail_on,
        config=config,
        no_config=no_config,
        baseline=baseline,
        update_baseline=update_baseline,
        baseline_output=baseline_output,
        console=console,
        language=language,
    )


@command_app.callback()
def root(
    version: Optional[bool] = typer.Option(None, "--version", callback=version_callback, help="Show version and exit."),
) -> None:
    return


@command_app.command("scan", help="Scan a file or directory.")
def scan_command(
    path: Path = typer.Argument(Path("."), help="File or directory to scan."),
    output_format: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json, markdown, sarif, excel, pdf, or all.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write output to a file or report directory.",
    ),
    severity: Severity = typer.Option(Severity.INFO, "--severity", help="Minimum severity to include."),
    fail_on: Optional[Severity] = typer.Option(
        None,
        "--fail-on",
        help="Exit with code 1 when findings at or above this severity exist.",
    ),
    config: Optional[Path] = typer.Option(None, "--config", help="Path to .agent-scan.yml config file."),
    no_config: bool = typer.Option(False, "--no-config", help="Do not load project config files."),
    baseline: Optional[Path] = typer.Option(
        None,
        "--baseline",
        help="Only report findings not already present in this baseline file.",
    ),
    update_baseline: bool = typer.Option(
        False,
        "--update-baseline",
        help="Write the current full scan result as a baseline and exit.",
    ),
    baseline_output: Path = typer.Option(
        Path(".agent-scan-baseline.json"),
        "--baseline-output",
        help="Path used with --update-baseline.",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored terminal output."),
    language: Optional[Language] = typer.Option(None, "--lang", help="CLI language: en or zh."),
) -> None:
    run_scan(
        target=path,
        output_format=output_format,
        output=output,
        severity=severity,
        fail_on=fail_on,
        config=config,
        no_config=no_config,
        baseline=baseline,
        update_baseline=update_baseline,
        baseline_output=baseline_output,
        console=Console(no_color=no_color),
        language=language,
    )


@command_app.command("init", help="Create a starter .agent-scan.yml configuration file.")
def init_command(
    path: Path = typer.Argument(Path("."), help="Directory where .agent-scan.yml should be created."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing config file."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored terminal output."),
    language: Language = typer.Option(Language.EN, "--lang", help="CLI language: en or zh."),
) -> None:
    console = Console(no_color=no_color)
    config_path = write_default_config(path, force=force)
    console.print(f"{t('wrote_config', language)} [cyan]{config_path}[/cyan]")


@command_app.command("fix", help="Preview safe autofix suggestions without modifying files.")
def fix_command(
    path: Path = typer.Argument(Path("."), help="File or directory to scan."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write the fix preview to a file."),
    severity: Severity = typer.Option(Severity.INFO, "--severity", help="Minimum severity to include."),
    config: Optional[Path] = typer.Option(None, "--config", help="Path to .agent-scan.yml config file."),
    no_config: bool = typer.Option(False, "--no-config", help="Do not load project config files."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored terminal output."),
) -> None:
    if not path.exists():
        raise typer.BadParameter(f"Path does not exist: {path}")
    project_config = load_project_config(path, config_path=config, no_config=no_config)
    result = Scanner(project_config=project_config).scan(path, min_severity=severity)
    root = path.resolve() if path.is_dir() else path.resolve().parent
    rendered = render_fix_previews(collect_fix_previews(result, root))
    console = Console(no_color=no_color)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        console.print(f"{t('wrote_report', Language.EN)} [cyan]{output}[/cyan]")
        return
    typer.echo(rendered)


@command_app.command("doctor", help="Check local runtime dependencies and report directory access.")
def doctor_command(
    path: Path = typer.Argument(Path("."), help="Project directory to check."),
    output_dir: Path = typer.Option(Path("output"), "--output-dir", help="Report output directory to test."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored terminal output."),
    language: Language = typer.Option(Language.EN, "--lang", help="CLI language: en or zh."),
) -> None:
    ok = render_doctor(Console(no_color=no_color), path, output_dir, language=language)
    if not ok:
        raise typer.Exit(code=1)


@command_app.command("rules", help="List built-in scanning rules.")
def rules_command(
    category: Optional[str] = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category: secrets, mcp, shell, github-actions, ai-tool, supply-chain, or filesystem.",
    ),
    output_format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table or markdown.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write markdown rules documentation to a file.",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored terminal output."),
    language: Language = typer.Option(Language.EN, "--lang", help="CLI language: en or zh."),
) -> None:
    fmt = output_format.lower()
    if fmt not in {"table", "markdown"}:
        raise typer.BadParameter("--format must be one of: table, markdown")

    console = Console(no_color=no_color)
    if fmt == "markdown":
        rendered = render_rules_markdown_output(language)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
            console.print(f"{t('wrote_report', language)} [cyan]{output}[/cyan]")
        else:
            typer.echo(rendered)
        return

    render_rules_table(console, category=category, language=language)


@command_app.command("report", help="List generated reports in an output directory.")
def report_command(
    output_dir: Path = typer.Argument(Path("output"), help="Directory containing generated reports."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored terminal output."),
    language: Language = typer.Option(Language.EN, "--lang", help="CLI language: en or zh."),
) -> None:
    render_reports_table(output_dir, Console(no_color=no_color), language=language)
    if not collect_report_files(output_dir):
        raise typer.Exit(code=1)


def entrypoint() -> None:
    args = sys.argv[1:]
    prog_name = Path(sys.argv[0]).name
    if args and args[0] in COMMAND_NAMES:
        command_app(args=args, prog_name=prog_name)
    else:
        app(args=args, prog_name=prog_name)


def _should_start_interactive(
    output_format: str,
    output: Optional[Path],
    severity: Severity,
    fail_on: Optional[Severity],
    config: Optional[Path],
    no_config: bool,
    baseline: Optional[Path],
    update_baseline: bool,
) -> bool:
    return (
        output_format == "terminal"
        and output is None
        and severity == Severity.INFO
        and fail_on is None
        and config is None
        and not no_config
        and baseline is None
        and not update_baseline
    )


if __name__ == "__main__":
    entrypoint()

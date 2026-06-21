import json
import sys
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from agent_security_scanner.cli import app, command_app, entrypoint
from agent_security_scanner.i18n import Language
from agent_security_scanner.interactive import _print_menu
from agent_security_scanner.interactive_input import BackRequested, _read_key_line


runner = CliRunner()


def _single_report(root: Path, pattern: str) -> Path:
    matches = sorted(root.rglob(pattern))
    assert len(matches) == 1, f"expected one report for {pattern}, found {matches}"
    return matches[0]


def _report_run_dirs(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_dir() and (path / "en").is_dir() and (path / "zh").is_dir()
    )


def test_cli_runs_terminal_scan(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    result = runner.invoke(app, [str(tmp_path)])

    assert result.exit_code == 0
    assert "Agent Security Scanner" in result.output
    assert "SEC001" in result.output


def test_cli_welcome_screen():
    result = runner.invoke(app, ["--welcome"])

    assert result.exit_code == 0
    assert "Tips for getting started" in result.output
    assert "V1.0.3" in result.output


def test_cli_version_uses_v1_display_label():
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert "agent-security-scanner V1.0.3" in result.output


def test_cli_no_args_starts_interactive_and_can_exit():
    result = runner.invoke(app, input="13\n")

    assert result.exit_code == 0
    assert "Agent Security Scanner V1.0.3" in result.output
    assert "Native Terminal CLI" in result.output
    assert "Interactive Menu" in result.output
    assert "Local scan, no code upload" in result.output
    assert "Select an option [1]" not in result.output
    assert "Goodbye" in result.output


def test_interactive_menu_resyncs_console_width(monkeypatch):
    console = Console(width=180, record=True)
    monkeypatch.setenv("AGENT_SCAN_TERMINAL_WIDTH", "72")

    _print_menu(console, language=Language.EN)

    assert console.width == 72
    rendered = console.export_text()
    assert "Native Terminal CLI" in rendered
    assert "Type 1-13 to choose" in rendered
    assert "type r to refresh" in rendered
    assert "type q to exit" in rendered


def test_interactive_menu_uses_two_columns_on_wide_terminal(monkeypatch):
    console = Console(width=120, record=True)
    monkeypatch.setenv("AGENT_SCAN_TERMINAL_WIDTH", "120")

    _print_menu(console, language=Language.EN)

    rendered = console.export_text()
    assert "Scan current directory" in rendered
    assert "List generated reports" in rendered
    assert "Quick commands" in rendered


def test_cli_interactive_refresh_redraws_menu():
    result = runner.invoke(app, input="r\n13\n")

    assert result.exit_code == 0
    assert result.output.count("Interactive Menu") >= 2
    assert result.output.count("Agent Security Scanner V1.0.3") >= 2
    assert "Goodbye" in result.output


def test_cli_unknown_option_does_not_repeat_header():
    result = runner.invoke(app, input="bad\n13\n")

    assert result.exit_code == 0
    assert result.output.count("Interactive Menu") >= 2
    assert result.output.count("Agent Security Scanner V1.0.3") == 1
    assert "Unknown option" in result.output


def test_cli_action_return_only_shows_compact_menu():
    result = runner.invoke(app, input="11\n13\n")

    assert result.exit_code == 0
    assert "Command Examples" in result.output
    assert result.output.count("Interactive Menu") >= 2
    assert result.output.count("Agent Security Scanner V1.0.3") == 1


def test_cli_language_switch_return_shows_full_header():
    result = runner.invoke(app, input="12\n13\n")

    assert result.exit_code == 0
    assert "Language switched to" in result.output or "Agent Security Scanner V1.0.3" in result.output
    assert result.output.count("Interactive Menu") + result.output.count("Agent Security Scanner V1.0.3") >= 2
    assert result.output.count("Agent Security Scanner V1.0.3") >= 2


def test_cli_interactive_main_menu_esc_word_exits():
    result = runner.invoke(app, input="esc\n")

    assert result.exit_code == 0
    assert "Interactive Menu" in result.output
    assert "Goodbye" in result.output


def test_interactive_real_escape_key_requests_back():
    keys = iter(["\x1b"])
    output: list[str] = []

    with pytest.raises(BackRequested):
        _read_key_line(lambda: next(keys), output.append)

    assert output == ["\n"]


def test_cli_interactive_subprompt_back_returns_to_menu():
    result = runner.invoke(app, input="2\nback\n13\n")

    assert result.exit_code == 0
    assert "Path to scan" in result.output
    assert "press Enter or type . for the current directory" in result.output
    assert "Type q, back, or esc to go back." in result.output
    assert "Returned to the previous menu" in result.output
    assert result.output.count("Interactive Menu") >= 2
    assert "Goodbye" in result.output


def test_cli_interactive_can_start_in_chinese():
    result = runner.invoke(app, ["--lang", "zh"], input="13\n")

    assert result.exit_code == 0
    assert "原生终端 CLI" in result.output
    assert "本地扫描，不上传代码" in result.output
    assert "Agent Security Scanner V1.0.3" in result.output
    assert "扫描当前目录" in result.output
    assert "输入 1-13 选择操作" in result.output
    assert result.output
    assert "再见" in result.output


def test_cli_interactive_doctor_shows_path_examples_in_chinese():
    result = runner.invoke(app, ["--lang", "zh"], input="6\n.\noutput\n13\n")

    assert result.exit_code == 0
    assert "示例：直接回车或输入 . 表示当前目录" in result.output
    assert "esc" in result.output
    assert "直接回车将报告写入 output 目录" in result.output


def test_cli_interactive_rules_shows_category_filter_hint_in_chinese():
    result = runner.invoke(app, ["--lang", "zh"], input="7\nsecrets\n13\n")

    assert result.exit_code == 0
    assert "secrets" in result.output
    assert "分类过滤（可选）" in result.output
    assert "native scrollback" not in result.output
    assert "SEC001" in result.output


def test_cli_interactive_path_prompt_shows_examples_in_chinese():
    result = runner.invoke(app, ["--lang", "zh"], input="2\nback\n13\n")

    assert result.exit_code == 0
    assert "示例：直接回车或输入 . 表示当前目录" in result.output


def test_cli_interactive_excel_pdf_writes_bilingual_reports(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    result = runner.invoke(app, input=f"4\n{tmp_path}\noutput\n13\n")

    assert result.exit_code == 0
    assert "Generating English Excel" in result.output
    assert "Generating Chinese PDF" in result.output
    assert _single_report(tmp_path / "output", f"{tmp_path.name}_*_en.xlsx").exists()
    assert _single_report(tmp_path / "output", f"{tmp_path.name}_*_en.pdf").exists()
    assert _single_report(tmp_path / "output", f"{tmp_path.name}_*_zh.xlsx").exists()
    assert _single_report(tmp_path / "output", f"{tmp_path.name}_*_zh.pdf").exists()


def test_cli_interactive_report_prompts_are_specific_in_chinese(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    all_result = runner.invoke(app, ["--lang", "zh"], input=f"3\n{tmp_path}\noutput\n13\n")
    excel_pdf_result = runner.invoke(app, ["--lang", "zh"], input=f"4\n{tmp_path}\noutput\n13\n")

    assert all_result.exit_code == 0
    assert "要生成全部报告的项目目录" in all_result.output
    assert "全部报告输出目录" in all_result.output
    assert excel_pdf_result.exit_code == 0
    assert "Excel/PDF" in excel_pdf_result.output
    assert "Excel/PDF 报告输出目录" in excel_pdf_result.output


def test_cli_interactive_all_reports_default_to_last_scanned_directory(tmp_path: Path, monkeypatch):
    current_project = tmp_path / "current"
    other_project = tmp_path / "Excel 鑷姩鍖栧伐鍏风"
    current_project.mkdir()
    other_project.mkdir()
    (current_project / "README.md").write_text("# current project\n", encoding="utf-8")
    (other_project / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")
    monkeypatch.chdir(current_project)

    result = runner.invoke(app, ["--lang", "zh"], input=f"2\n{other_project}\n3\n\noutput\n13\n")

    assert result.exit_code == 0
    assert "报告扫描目标" in result.output
    assert str(other_project) in result.output
    assert "SEC001" in result.output
    report = _single_report(current_project / "output", f"{other_project.name}_*_en.md")
    assert report.exists()
    assert report.parent.name == "en"
    assert report.parent.parent.parent.name == other_project.name
    report_text = report.read_text(encoding="utf-8")
    assert str(other_project) in report_text
    assert "SEC001" in report_text
    assert _single_report(current_project / "output", f"{other_project.name}_*_zh.md").exists()
    assert _single_report(current_project / "output", f"{other_project.name}_*_machine.json").exists()


def test_cli_interactive_excel_pdf_default_to_last_scanned_directory(tmp_path: Path, monkeypatch):
    current_project = tmp_path / "current"
    other_project = tmp_path / "Excel 鑷姩鍖栧伐鍏风"
    current_project.mkdir()
    other_project.mkdir()
    (current_project / "README.md").write_text("# current project\n", encoding="utf-8")
    (other_project / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")
    monkeypatch.chdir(current_project)

    result = runner.invoke(app, ["--lang", "zh"], input=f"2\n{other_project}\n4\n\noutput\n13\n")

    assert result.exit_code == 0
    assert "报告扫描目标" in result.output
    assert str(other_project) in result.output
    assert "正在生成英文 Excel" in result.output
    assert "正在生成中文 PDF" in result.output
    assert _single_report(current_project / "output", f"{other_project.name}_*_en.xlsx").exists()
    assert _single_report(current_project / "output", f"{other_project.name}_*_zh.xlsx").exists()
    assert _single_report(current_project / "output", f"{other_project.name}_*_en.pdf").exists()
    assert _single_report(current_project / "output", f"{other_project.name}_*_zh.pdf").exists()


def test_cli_interactive_baseline_prompt_is_specific_in_both_languages(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    english_result = runner.invoke(app, input=f"9\n{tmp_path}\n.agent-scan-baseline.json\n13\n")
    chinese_result = runner.invoke(app, ["--lang", "zh"], input=f"9\n{tmp_path}\n.agent-scan-baseline.json\n13\n")

    assert english_result.exit_code == 0
    assert "Project directory for baseline" in english_result.output
    assert "Baseline file path" in english_result.output
    assert chinese_result.exit_code == 0
    assert "baseline" in chinese_result.output.lower()
    assert "Baseline 文件保存路径" in chinese_result.output


def test_cli_interactive_all_reports_write_error_returns_to_menu(tmp_path: Path, monkeypatch):
    import agent_security_scanner.interactive as interactive

    monkeypatch.chdir(tmp_path)

    def fail_write_all_reports(*args, **kwargs):
        raise PermissionError(13, "Permission denied", "output/zh/report.pdf")

    monkeypatch.setattr(interactive, "write_all_reports", fail_write_all_reports)

    result = runner.invoke(app, ["--lang", "zh"], input="3\n.\noutput\n13\n")

    assert result.exit_code == 0
    assert "文件写入失败" in result.output
    assert "output/zh/report.pdf" in result.output
    assert result.output
    assert "Traceback" not in result.output
    assert "再见" in result.output


def test_cli_json_output_is_valid(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    result = runner.invoke(app, [str(tmp_path), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["summary"]["total"] >= 1
    assert payload["findings"][0]["remediation"]["steps"]
    assert payload["findings"][0]["fingerprint"]


def test_cli_fail_on_returns_non_zero_for_blocking_findings(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    result = runner.invoke(app, [str(tmp_path), "--fail-on", "high"])

    assert result.exit_code == 1
    assert "Fail-on gate triggered" in result.output


def test_cli_fail_on_passes_when_threshold_not_met(tmp_path: Path):
    (tmp_path / "app.py").write_text("print('ok')", encoding="utf-8")

    result = runner.invoke(app, [str(tmp_path), "--fail-on", "critical"])

    assert result.exit_code == 0


def test_cli_sarif_output_defaults_to_output_directory(tmp_path: Path, monkeypatch):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, [str(tmp_path), "--format", "sarif"])

    report = tmp_path / "output" / "machine" / "agent-scan.sarif"
    assert result.exit_code == 0
    assert report.exists()
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["runs"][0]["results"][0]["ruleId"] == "SEC001"


def test_cli_excel_output_file(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")
    report = tmp_path / "report.xlsx"

    result = runner.invoke(app, [str(tmp_path), "--format", "excel", "--output", str(report)])

    assert result.exit_code == 0
    assert (tmp_path / "en" / "report.xlsx").exists()
    assert (tmp_path / "zh" / "report.xlsx").exists()
    assert (tmp_path / "en" / "report.xlsx").stat().st_size > 0
    assert (tmp_path / "zh" / "report.xlsx").stat().st_size > 0


def test_cli_pdf_output_file(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")
    report = tmp_path / "report.pdf"

    result = runner.invoke(app, [str(tmp_path), "--format", "pdf", "--output", str(report)])

    assert result.exit_code == 0
    assert (tmp_path / "en" / "report.pdf").exists()
    assert (tmp_path / "zh" / "report.pdf").exists()
    assert (tmp_path / "en" / "report.pdf").stat().st_size > 0
    assert (tmp_path / "zh" / "report.pdf").stat().st_size > 0


def test_cli_all_output_directory(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")
    report_dir = tmp_path / "output"

    result = runner.invoke(app, [str(tmp_path), "--format", "all", "--output", str(report_dir)])

    assert result.exit_code == 0
    project_name = tmp_path.name
    assert _single_report(report_dir, f"{project_name}_*_en.md").exists()
    assert _single_report(report_dir, f"{project_name}_*_zh.md").exists()
    assert _single_report(report_dir, f"{project_name}_*_en.xlsx").exists()
    assert _single_report(report_dir, f"{project_name}_*_zh.xlsx").exists()
    assert _single_report(report_dir, f"{project_name}_*_en.pdf").exists()
    assert _single_report(report_dir, f"{project_name}_*_zh.pdf").exists()
    assert _single_report(report_dir, f"{project_name}_*_machine.sarif").exists()
    assert _single_report(report_dir, f"{project_name}_*_machine.json").exists()


def test_cli_markdown_output_directory(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")
    report_dir = tmp_path / "output"

    result = runner.invoke(app, [str(tmp_path), "--format", "markdown", "--output", str(report_dir)])

    assert result.exit_code == 0
    english_report = _single_report(report_dir, f"{tmp_path.name}_*_en.md")
    chinese_report = _single_report(report_dir, f"{tmp_path.name}_*_zh.md")
    assert english_report.exists()
    assert chinese_report.exists()
    assert english_report.parent.name == "en"
    assert chinese_report.parent.name == "zh"
    assert "Agent Security Scanner Report" in english_report.read_text(encoding="utf-8")
    chinese_text = chinese_report.read_text(encoding="utf-8")
    assert "Agent Security Scanner 扫描报告" in chinese_text
    assert "修复摘要" in chinese_text
    assert "修复步骤" in chinese_text
    assert "Move the credential" not in chinese_text
    assert "Remove plaintext credentials" not in chinese_text
    assert "Review the finding" not in chinese_text
    assert "Download scripts to a reviewed file" not in chinese_text


def test_cli_terminal_output_can_be_chinese(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    result = runner.invoke(app, [str(tmp_path), "--lang", "zh"])

    assert result.exit_code == 0
    assert "扫描目标" in result.output
    assert "发现数量" in result.output
    assert "严重" in result.output
    assert "发现 OpenAI API Key" in result.output


def test_cli_uses_language_from_config(tmp_path: Path):
    (tmp_path / ".agent-scan.yml").write_text("language: zh\n", encoding="utf-8")
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    result = runner.invoke(app, [str(tmp_path)])

    assert result.exit_code == 0
    assert "扫描目标" in result.output


def test_cli_markdown_defaults_to_output_directory(tmp_path: Path, monkeypatch):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, [str(tmp_path), "--format", "markdown"])

    assert result.exit_code == 0
    assert _single_report(tmp_path / "output", f"{tmp_path.name}_*_en.md").exists()
    assert _single_report(tmp_path / "output", f"{tmp_path.name}_*_zh.md").exists()


def test_cli_report_generation_creates_unique_runs(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")
    report_dir = tmp_path / "output"

    first = runner.invoke(app, [str(tmp_path), "--format", "markdown", "--output", str(report_dir)])
    second = runner.invoke(app, [str(tmp_path), "--format", "markdown", "--output", str(report_dir)])

    assert first.exit_code == 0
    assert second.exit_code == 0
    run_dirs = _report_run_dirs(report_dir)
    assert len(run_dirs) == 2
    assert len({path.name for path in run_dirs}) == 2
    assert len(list(report_dir.rglob(f"{tmp_path.name}_*_en.md"))) == 2


def test_cli_can_update_and_apply_baseline(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")
    baseline_path = tmp_path / ".agent-scan-baseline.json"

    update_result = runner.invoke(
        app,
        [str(tmp_path), "--update-baseline", "--baseline-output", str(baseline_path)],
    )
    scan_result = runner.invoke(app, [str(tmp_path), "--baseline", str(baseline_path), "--format", "json"])

    assert update_result.exit_code == 0
    assert baseline_path.exists()
    payload = json.loads(scan_result.output)
    assert payload["summary"]["total"] == 0


def test_cli_missing_baseline_shows_clean_error(tmp_path: Path):
    result = runner.invoke(app, [str(tmp_path), "--baseline", str(tmp_path / "missing.json")])

    assert result.exit_code != 0
    assert "Baseline file does not exist" in result.output
    assert "Traceback" not in result.output


def test_cli_interactive_missing_baseline_returns_to_menu(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    result = runner.invoke(app, ["--lang", "zh"], input=f"10\n{tmp_path}\nmissing.json\n13\n")

    assert result.exit_code == 0
    assert "Baseline file does not exist" in result.output
    assert "请先使用选项 9 创建 baseline" in result.output
    assert result.output
    assert "Traceback" not in result.output
    assert "再见" in result.output


def test_scan_subcommand_matches_legacy_scan(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    result = runner.invoke(command_app, ["scan", str(tmp_path), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["summary"]["total"] >= 1


def test_init_subcommand_writes_config(tmp_path: Path):
    result = runner.invoke(command_app, ["init", str(tmp_path)])

    config = tmp_path / ".agent-scan.yml"
    assert result.exit_code == 0
    assert config.exists()
    assert "min_severity" in config.read_text(encoding="utf-8")
    assert "language: en" in config.read_text(encoding="utf-8")


def test_init_subcommand_refuses_overwrite_without_force(tmp_path: Path):
    config = tmp_path / ".agent-scan.yml"
    config.write_text("min_severity: high\n", encoding="utf-8")

    result = runner.invoke(command_app, ["init", str(tmp_path)])

    assert result.exit_code != 0
    assert config.read_text(encoding="utf-8") == "min_severity: high\n"


def test_doctor_subcommand_runs(tmp_path: Path):
    result = runner.invoke(command_app, ["doctor", str(tmp_path), "--output-dir", str(tmp_path / "output")])

    assert result.exit_code == 0
    assert "Agent Security Scanner Doctor" in result.output
    assert "Python version" in result.output
    assert "Rule catalog unique IDs" in result.output
    assert "Scanner rules registered" in result.output


def test_doctor_subcommand_can_be_chinese(tmp_path: Path):
    result = runner.invoke(
        command_app,
        ["doctor", str(tmp_path), "--output-dir", str(tmp_path / "output"), "--lang", "zh"],
    )

    assert result.exit_code == 0
    assert "环境诊断" in result.output
    assert "Python 版本" in result.output
    assert "通过" in result.output


def test_rules_subcommand_lists_builtin_rules():
    result = runner.invoke(command_app, ["rules", "--no-color"])

    assert result.exit_code == 0
    assert "Built-in Rules" in result.output
    assert "SEC001" in result.output
    assert "GHA006" in result.output
    assert "SC014" in result.output


def test_rules_subcommand_filters_category():
    result = runner.invoke(command_app, ["rules", "--category", "mcp", "--no-color"])

    assert result.exit_code == 0
    assert "MCP001" in result.output
    assert "SEC001" not in result.output


def test_rules_subcommand_can_be_chinese():
    result = runner.invoke(command_app, ["rules", "--category", "secrets", "--lang", "zh", "--no-color"])

    assert result.exit_code == 0
    assert "内置规则" in result.output
    assert "敏感信息" in result.output
    assert "发现 OpenAI API Key" in result.output


def test_rules_subcommand_can_render_markdown(tmp_path: Path):
    output = tmp_path / "RULES.md"

    result = runner.invoke(command_app, ["rules", "--format", "markdown", "--output", str(output), "--no-color"])

    assert result.exit_code == 0
    assert output.exists()
    text = output.read_text(encoding="utf-8")
    assert "# Agent Security Scanner Rules" in text
    assert "SEC001" in text
    assert "SC014" in text


def test_report_subcommand_lists_generated_reports(tmp_path: Path):
    output = tmp_path / "output"
    (output / "en").mkdir(parents=True)
    (output / "en" / "report.md").write_text("# report\n", encoding="utf-8")

    result = runner.invoke(command_app, ["report", str(output), "--no-color"])

    assert result.exit_code == 0
    assert "Reports in" in result.output
    assert "report.md" in result.output
    assert "en" in result.output


def test_report_subcommand_can_be_chinese(tmp_path: Path):
    output = tmp_path / "output"
    (output / "zh").mkdir(parents=True)
    (output / "zh" / "report.md").write_text("# report\n", encoding="utf-8")

    result = runner.invoke(command_app, ["report", str(output), "--lang", "zh", "--no-color"])

    assert result.exit_code == 0
    assert "报告目录" in result.output
    assert "Markdown（中文）" in result.output


def test_report_subcommand_returns_non_zero_when_no_reports(tmp_path: Path):
    result = runner.invoke(command_app, ["report", str(tmp_path / "output"), "--no-color"])

    assert result.exit_code == 1
    assert "No reports found" in result.output


def test_entrypoint_preserves_legacy_scan(monkeypatch, capsys, tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["agent-scan", str(tmp_path), "--format", "json"])

    with pytest.raises(SystemExit) as exc_info:
        entrypoint()

    assert exc_info.value.code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["total"] >= 1


def test_entrypoint_dispatches_subcommands(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["agent-scan", "rules", "--category", "secrets", "--no-color"])

    with pytest.raises(SystemExit) as exc_info:
        entrypoint()

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "SEC001" in output
    assert "MCP001" not in output

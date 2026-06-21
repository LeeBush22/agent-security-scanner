from pathlib import Path

from typer.testing import CliRunner

from agent_security_scanner.cli import command_app


runner = CliRunner()


def test_fix_command_previews_mcp_dangerous_flag_without_modifying_file(tmp_path: Path):
    config = tmp_path / "mcp.json"
    original = """
{
  "mcpServers": {
    "shell": {
      "command": "bash",
      "args": ["--dangerously-skip-permissions", "--safe"]
    }
  }
}
""".strip()
    config.write_text(original, encoding="utf-8")

    result = runner.invoke(command_app, ["fix", str(tmp_path)])

    assert result.exit_code == 0
    assert "Agent Security Scanner Fix Preview" in result.output
    assert "MCP005" in result.output
    assert '-      "args": ["--dangerously-skip-permissions", "--safe"]' in result.output
    assert '+        "--safe"' in result.output
    assert config.read_text(encoding="utf-8") == original


def test_fix_command_can_write_preview_file(tmp_path: Path):
    config = tmp_path / "mcp.json"
    output = tmp_path / "fix.patch.md"
    config.write_text(
        '{"mcpServers":{"shell":{"command":"bash","args":["--no-sandbox"]}}}',
        encoding="utf-8",
    )

    result = runner.invoke(command_app, ["fix", str(tmp_path), "--output", str(output)])

    assert result.exit_code == 0
    assert output.exists()
    assert "MCP005" in output.read_text(encoding="utf-8")

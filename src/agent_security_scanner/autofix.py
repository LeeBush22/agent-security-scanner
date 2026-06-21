from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from agent_security_scanner.models import Finding, ScanResult


DANGEROUS_MCP_FLAGS = {
    "--allow-all",
    "--dangerously-skip-permissions",
    "--disable-sandbox",
    "--disable-security",
    "--no-sandbox",
    "--unsafe",
    "--yes-i-know-what-i-am-doing",
}


@dataclass(frozen=True)
class FixPreview:
    finding: Finding
    description: str
    patch: str
    apply_supported: bool = False


def collect_fix_previews(result: ScanResult, project_root: Path) -> list[FixPreview]:
    previews: list[FixPreview] = []
    for finding in result.findings:
        if finding.rule_id == "MCP005":
            preview = _preview_mcp005(finding, project_root)
            if preview:
                previews.append(preview)
    return previews


def render_fix_previews(previews: list[FixPreview]) -> str:
    if not previews:
        return "No safe autofix previews are available for the current findings.\n"

    lines = [
        "# Agent Security Scanner Fix Preview",
        "",
        "No files were modified. Review each suggested change before applying it manually.",
        "",
    ]
    for index, preview in enumerate(previews, start=1):
        lines.extend(
            [
                f"## {index}. {preview.finding.rule_id}: {preview.finding.title}",
                "",
                f"- File: `{preview.finding.file_path}`",
                f"- Description: {preview.description}",
                f"- Apply supported: `{str(preview.apply_supported).lower()}`",
                "",
                "```diff",
                preview.patch.rstrip(),
                "```",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _preview_mcp005(finding: Finding, project_root: Path) -> FixPreview | None:
    path = project_root / finding.file_path
    if not path.exists() or not path.is_file():
        return None

    try:
        original = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None

    data = _load_structured(path, original)
    if data is None:
        return None

    changed = _remove_dangerous_args(data)
    if not changed:
        return None

    rendered = _dump_structured(path, data)
    if rendered == original:
        return None

    return FixPreview(
        finding=finding,
        description="Remove dangerous MCP server flags while preserving the surrounding configuration.",
        patch=_simple_diff(finding.file_path, original, rendered),
        apply_supported=False,
    )


def _load_structured(path: Path, text: str) -> Any | None:
    try:
        if path.suffix.lower() == ".json":
            return json.loads(text)
        return yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError):
        return None


def _dump_structured(path: Path, data: Any) -> str:
    if path.suffix.lower() == ".json":
        return json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=False)


def _remove_dangerous_args(value: Any) -> bool:
    changed = False
    if isinstance(value, dict):
        args = value.get("args")
        if isinstance(args, list):
            filtered = [
                arg
                for arg in args
                if not (isinstance(arg, str) and (arg in DANGEROUS_MCP_FLAGS or arg.startswith("--allow-")))
            ]
            if filtered != args:
                value["args"] = filtered
                changed = True
        for child in value.values():
            changed = _remove_dangerous_args(child) or changed
    elif isinstance(value, list):
        for child in value:
            changed = _remove_dangerous_args(child) or changed
    return changed


def _simple_diff(path: str, old: str, new: str) -> str:
    import difflib

    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )

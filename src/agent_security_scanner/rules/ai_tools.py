from __future__ import annotations

import json
import re
from typing import Any

import yaml

from agent_security_scanner.models import Category, FileContext, Finding, Severity
from agent_security_scanner.rules.base import Rule


AI_TOOL_FILENAMES = {
    ".cursorrules",
    ".cursorignore",
    ".aider.conf.yml",
    "agents.md",
    "claude.md",
    "gemini.md",
    "memory.md",
    "skill.md",
    ".continue.json",
    ".continue.yaml",
    ".continue.yml",
    "copilot-instructions.md",
    "cline_mcp_settings.json",
    "codex.toml",
    "codex.yaml",
    "codex.yml",
    "continue.json",
    "continue.yaml",
    "continue.yml",
    "roo-cline.json",
    "roo-code.json",
    "settings.json",
    "tasks.json",
}

AI_TOOL_DIR_MARKERS = {
    ".claude",
    ".codex",
    ".continue",
    ".cursor",
    ".github",
    ".roo",
    ".roo-code",
    ".vscode",
}

SECRET_KEY_RE = re.compile(r"(?i)(api[_-]?key|auth[_-]?token|access[_-]?token|secret|password|private[_-]?key)")
DANGEROUS_FLAG_RE = re.compile(r"(?i)(--dangerously-skip-permissions|--no-sandbox|--allow-all|--full-access)")
DANGEROUS_COMMAND_RE = re.compile(r"(?i)\b(bash|sh|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)\b")
PROMPT_INJECTION_RE = re.compile(
    r"(?i)(ignore (?:all )?(?:previous|prior|above) instructions|"
    r"reveal (?:the )?(?:system|developer) prompt|"
    r"disable (?:all )?(?:safety|security|approval|permission)|"
    r"do not ask (?:for )?(?:confirmation|approval)|"
    r"(?:read|collect|upload|exfiltrate|send).{0,80}(?:\.env|id_rsa|private key|api key|token|secret|password|credentials))"
)
MEMORY_POISONING_RE = re.compile(
    r"(?i)(remember (?:forever|permanently)|"
    r"store (?:this|these) (?:instruction|rule|policy)|"
    r"always (?:ignore|bypass|disable|approve|run|execute)|"
    r"persist (?:this|these) (?:instruction|rule|command)|"
    r"(?:save|write).{0,60}(?:memory|rules|instructions).{0,80}(?:ignore|bypass|secret|token|credential))"
)
EXCESSIVE_AGENCY_RE = re.compile(
    r"(?i)(continue (?:working|running|executing) until|"
    r"never ask (?:the )?user|"
    r"without (?:any )?(?:user )?(?:confirmation|approval|review)|"
    r"autonomously (?:run|execute|modify|deploy|publish)|"
    r"(?:deploy|publish|push|merge|release).{0,80}without (?:approval|review|confirmation))"
)
NETWORK_EXFIL_RE = re.compile(
    r"(?i)((?:send|post|upload|exfiltrate|forward).{0,80}(?:source code|repository|repo|workspace|files|secrets|tokens|credentials)|"
    r"(?:webhook|callback|remote server).{0,80}(?:source code|repository|repo|workspace|secrets|tokens|credentials))"
)
PREPROCESS_SHELL_RE = re.compile(r"(?i)(?:^|\s)!\s*`[^`\n]+`")
OVERBROAD_BASH_TOOL_RE = re.compile(r"(?i)(allowed[-_\s]?tools?|tools?)\s*[:=].{0,120}bash\s*\(\s*\*\s*\)")
UNPINNED_SKILL_REF_RE = re.compile(
    r"(?i)(clawhub|skills\.sh|skill\s+install|install\s+skill|use\s+skill|skill:)[^\n]*(?:latest|main|master|https?://|github:)(?![A-Za-z0-9/_ .:@-]*(?:@[0-9a-f]{40}|#[0-9a-f]{40}|v?\d+\.\d+\.\d+))"
)
GEMINI_UNSAFE_RE = re.compile(
    r"(?i)(gemini(?:-cli)?|google[_-]?gemini).{0,120}(?:auto[_-]?approve|auto[_-]?run|skip[_-]?confirmation|allow[_-]?all|dangerously|sandbox\s*[:=]\s*false)"
)
ZERO_WIDTH_CHARS = {
    "\u200b": "U+200B",
    "\u200c": "U+200C",
    "\u200d": "U+200D",
    "\ufeff": "U+FEFF",
}
BIDI_CONTROL_CHARS = {chr(codepoint): f"U+{codepoint:04X}" for codepoint in range(0x202A, 0x202F)}
BIDI_CONTROL_CHARS.update({chr(codepoint): f"U+{codepoint:04X}" for codepoint in range(0x2066, 0x206A)})
OFFICIAL_BASE_URLS = {
    "anthropic_base_url": ("https://api.anthropic.com",),
    "claude_base_url": ("https://api.anthropic.com",),
    "openai_base_url": ("https://api.openai.com", "https://api.openai.com/v1"),
    "azure_openai_endpoint": ("https://",),
    "gemini_base_url": ("https://generativelanguage.googleapis.com", "https://aiplatform.googleapis.com"),
}
SUSPICIOUS_BASE_URL_MARKERS = ("http://", "localhost", "127.0.0.1", "0.0.0.0", "ngrok", "proxy", "one-api", "new-api")
BROAD_PATHS = {"/", "~", "$HOME", "${HOME}", "%USERPROFILE%"}
BROAD_TOOL_VALUES = {"bash", "shell", "terminal", "read", "write", "edit", "network", "browser", "web", "all", "*"}
CLAUDE_HOOK_EVENTS = {
    "sessionstart",
    "pretooluse",
    "posttooluse",
    "userpromptsubmit",
    "stop",
    "notification",
    "subagentstop",
    "precompact",
}


class AIToolConfigRule(Rule):
    def scan(self, context: FileContext) -> list[Finding]:
        if not _is_ai_tool_config(context):
            return []

        data = _parse_config(context)
        findings: list[Finding] = []
        if data is not None:
            findings.extend(_scan_node(context, data, []))
        findings.extend(_scan_text_patterns(context))
        return _dedupe(findings)


def _is_ai_tool_config(context: FileContext) -> bool:
    normalized = context.relative_path.replace("\\", "/").lower()
    name = context.path.name.lower()
    if name in AI_TOOL_FILENAMES:
        return True
    if _is_ai_instruction_file(context):
        return True
    if any(f"/{marker}/" in f"/{normalized}/" for marker in AI_TOOL_DIR_MARKERS):
        return context.path.suffix.lower() in {"", ".json", ".toml", ".yaml", ".yml", ".md", ".txt"}
    head = context.text[:4000].lower()
    return any(marker in head for marker in ("claude code", "cursor", "continue.dev", "roo code", "codex"))


def _parse_config(context: FileContext) -> Any | None:
    suffix = context.path.suffix.lower()
    try:
        if suffix == ".json":
            return json.loads(context.text)
        if suffix in {".yaml", ".yml"}:
            return yaml.safe_load(context.text)
        if suffix == ".toml":
            import tomllib

            return tomllib.loads(context.text)
    except (json.JSONDecodeError, yaml.YAMLError, tomllib.TOMLDecodeError):
        return None
    return None


def _scan_node(context: FileContext, value: Any, path: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    if isinstance(value, dict):
        findings.extend(_scan_mapping(context, value, path))
        for key, child in value.items():
            findings.extend(_scan_node(context, child, [*path, str(key)]))
    elif isinstance(value, list):
        findings.extend(_scan_list(context, value, path))
        for index, child in enumerate(value):
            findings.extend(_scan_node(context, child, [*path, str(index)]))
    return findings


def _scan_mapping(context: FileContext, value: dict[Any, Any], path: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    tool_values: set[str] = set()
    for raw_key, raw_value in value.items():
        key = str(raw_key)
        key_l = key.lower()
        current_path = [*path, key]
        if _is_auto_approval_key(key_l) and _truthy_or_all(raw_value):
            findings.append(
                _finding(
                    context,
                    "AIT001",
                    "AI tool auto-approval is enabled",
                    Severity.HIGH,
                    "AI coding tool config appears to auto-approve commands, edits, or tool calls.",
                    key,
                    "Disable broad auto-approval and require confirmation for command execution, file edits, and network access.",
                )
            )
        if _is_permission_bypass_key(key_l) and _truthy_or_all(raw_value):
            findings.append(
                _finding(
                    context,
                    "AIT002",
                    "AI tool permission checks are bypassed",
                    Severity.CRITICAL,
                    "AI coding tool config disables or bypasses permission checks.",
                    key,
                    "Keep permission prompts and sandbox checks enabled, then grant narrow exceptions only when needed.",
                )
            )
        if _is_workspace_access_key(key_l):
            findings.extend(_check_workspace_value(context, raw_value))
        if _is_command_key(key_l) and isinstance(raw_value, str) and _looks_dangerous_command(raw_value):
            findings.append(
                _finding(
                    context,
                    "AIT004",
                    "AI tool can invoke a shell-capable command",
                    Severity.HIGH,
                    "AI coding tool config includes a command that can execute arbitrary shell instructions.",
                    raw_value,
                    "Restrict command execution to reviewed binaries and require confirmation before shell access.",
                )
            )
        if SECRET_KEY_RE.search(key) and isinstance(raw_value, str) and raw_value.strip():
            findings.append(
                _finding(
                    context,
                    "AIT005",
                    "Secret embedded in AI tool config",
                    Severity.CRITICAL,
                    "AI coding tool config contains a credential-like field with a plaintext value.",
                    f"{key}=...",
                    "Move credentials to local environment variables or a secret manager, then rotate exposed values.",
                )
            )
        if _is_tool_permission_key(key_l):
            tool_values.update(_tool_values(raw_value))
        findings.extend(_check_claude_hooks(context, raw_value, current_path))
        findings.extend(_check_api_base_url(context, key_l, raw_value))
        findings.extend(_check_vscode_folder_open_task(context, key_l, raw_value, value))
        findings.extend(_check_gemini_config_value(context, key_l, raw_value))
        if isinstance(raw_value, str):
            findings.extend(_scan_agentic_text_value(context, raw_value, key))
    if _has_dangerous_tool_combo(tool_values):
        findings.append(
            _finding(
                context,
                "AIT010",
                "AI tool grants high-risk tool combination",
                Severity.HIGH,
                "AI tool configuration grants a combination of shell, file-write, and network/browser capabilities.",
                ", ".join(sorted(tool_values & BROAD_TOOL_VALUES)),
                "Avoid granting shell, write, and network capabilities together without manual approval gates.",
            )
        )
    return findings


def _scan_list(context: FileContext, value: list[Any], path: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    joined_path = ".".join(path).lower()
    if any(marker in joined_path for marker in ("allow", "autoapprove", "auto_approve", "permissions")):
        text_values = [str(item).lower() for item in value]
        if any(item in {"*", "all", "all_tools", "terminal", "shell", "edit"} for item in text_values):
            findings.append(
                _finding(
                    context,
                    "AIT001",
                    "AI tool auto-approval is too broad",
                    Severity.HIGH,
                    "AI coding tool config grants broad auto-approval for tools or actions.",
                    ", ".join(str(item) for item in value[:5]),
                    "Replace broad auto-approval with explicit, minimal tool permissions.",
                )
            )
    if _is_workspace_access_key(joined_path):
        findings.extend(_check_workspace_value(context, value))
    if _is_tool_permission_key(joined_path) and _has_dangerous_tool_combo(set().union(*(_tool_values(item) for item in value))):
        findings.append(
            _finding(
                context,
                "AIT010",
                "AI tool grants high-risk tool combination",
                Severity.HIGH,
                "AI tool configuration grants a combination of shell, file-write, and network/browser capabilities.",
                ", ".join(str(item) for item in value[:8]),
                "Avoid granting shell, write, and network capabilities together without manual approval gates.",
            )
        )
    if _path_has_claude_hook_event(path):
        for item in value:
            findings.extend(_check_claude_hooks(context, item, path))
    return findings


def _scan_text_patterns(context: FileContext) -> list[Finding]:
    findings: list[Finding] = []
    instruction_file = _is_ai_instruction_file(context)
    memory_file = _is_ai_memory_file(context)
    findings.extend(_scan_invisible_unicode(context))
    for line_number, line in enumerate(context.text.splitlines(), start=1):
        if DANGEROUS_FLAG_RE.search(line):
            findings.append(
                _finding(
                    context,
                    "AIT002",
                    "Dangerous AI tool permission flag",
                    Severity.CRITICAL,
                    "AI coding tool configuration contains a flag that disables sandbox or permission controls.",
                    line.strip(),
                    "Remove dangerous permission bypass flags and use the tool's normal approval flow.",
                    line=line_number,
                )
            )
        if re.search(r"(?i)(auto[_-]?approve|auto[_-]?run|auto[_-]?execute).*(true|all|\*)", line):
            findings.append(
                _finding(
                    context,
                    "AIT001",
                    "AI tool auto-execution is enabled",
                    Severity.HIGH,
                    "AI coding tool configuration appears to allow automatic execution or approval.",
                    line.strip(),
                    "Require manual confirmation for command execution, file changes, and external tool calls.",
                    line=line_number,
                )
            )
        if instruction_file and PROMPT_INJECTION_RE.search(line):
            findings.append(
                _finding(
                    context,
                    "AIT006",
                    "AI instruction file contains unsafe instruction",
                    Severity.HIGH,
                    "AI tool instruction file asks the agent to bypass controls, reveal prompts, or access sensitive data.",
                    line.strip(),
                    "Remove instructions that bypass safety controls or request access to secrets, prompts, or credentials.",
                    line=line_number,
                )
            )
        if (instruction_file or memory_file) and MEMORY_POISONING_RE.search(line):
            findings.append(
                _finding(
                    context,
                    "AIT007",
                    "AI memory or rule file contains persistence instruction",
                    Severity.HIGH,
                    "AI memory or rule file contains an instruction that attempts to persist unsafe behavior across sessions.",
                    line.strip(),
                    "Remove persistent instructions that change safety, approval, credential, or system-prompt handling.",
                    line=line_number,
                )
            )
        if instruction_file and EXCESSIVE_AGENCY_RE.search(line):
            findings.append(
                _finding(
                    context,
                    "AIT008",
                    "AI instruction grants excessive autonomy",
                    Severity.HIGH,
                    "AI instruction asks the agent to continue, deploy, modify, or execute without user review.",
                    line.strip(),
                    "Require explicit user approval for long-running work, command execution, publishing, deployment, and repository changes.",
                    line=line_number,
                )
            )
        if instruction_file and NETWORK_EXFIL_RE.search(line):
            findings.append(
                _finding(
                    context,
                    "AIT009",
                    "AI instruction allows data exfiltration",
                    Severity.CRITICAL,
                    "AI instruction asks the agent to send code, files, credentials, or workspace content to a remote destination.",
                    line.strip(),
                    "Remove instructions that upload source code, credentials, or workspace files to untrusted endpoints.",
                    line=line_number,
                )
            )
        if instruction_file and (PREPROCESS_SHELL_RE.search(line) or OVERBROAD_BASH_TOOL_RE.search(line)):
            findings.append(
                _finding(
                    context,
                    "AIT013",
                    "AI instruction file contains dynamic shell execution",
                    Severity.CRITICAL,
                    "AI instruction or skill file contains a preprocessed shell command or broad Bash tool grant.",
                    line.strip(),
                    "Remove dynamic shell execution from AI instruction files and avoid Bash(*) style broad tool grants.",
                    line=line_number,
                )
            )
        if instruction_file and UNPINNED_SKILL_REF_RE.search(line):
            findings.append(
                _finding(
                    context,
                    "AIT016",
                    "AI skill reference is unpinned or from an untrusted source",
                    Severity.HIGH,
                    "AI skill or command reference appears to use a mutable version or external registry/source.",
                    line.strip(),
                    "Pin AI skill references to reviewed versions or full commit hashes and audit the skill content before use.",
                    line=line_number,
                )
            )
        if GEMINI_UNSAFE_RE.search(line):
            findings.append(
                _finding(
                    context,
                    "AIT017",
                    "Gemini CLI configuration contains unsafe automation setting",
                    Severity.HIGH,
                    "Gemini CLI related configuration appears to enable broad automation or disable confirmation/sandbox controls.",
                    line.strip(),
                    "Keep Gemini CLI confirmation and sandbox controls enabled and avoid broad auto-run permissions.",
                    line=line_number,
                )
            )
    return findings


def _check_workspace_value(context: FileContext, value: Any) -> list[Finding]:
    values = value if isinstance(value, list) else [value]
    findings: list[Finding] = []
    for item in values:
        candidate = str(item).strip().strip('"').strip("'")
        if candidate in BROAD_PATHS or re.fullmatch(r"(?i)[a-z]:\\?", candidate):
            findings.append(
                _finding(
                    context,
                    "AIT003",
                    "AI tool workspace access is too broad",
                    Severity.HIGH,
                    "AI coding tool config grants root, home, or drive-level filesystem access.",
                    candidate,
                    "Restrict AI tool filesystem access to the smallest project directory required.",
                )
            )
    return findings


def _check_claude_hooks(context: FileContext, value: Any, path: list[str]) -> list[Finding]:
    if not _path_has_claude_hook_event(path):
        return []
    commands = _collect_hook_commands(value)
    findings: list[Finding] = []
    for command in commands:
        if not _looks_shell_or_external_command(command):
            continue
        findings.append(
            _finding(
                context,
                "AIT011",
                "Claude Code hook executes a shell command",
                Severity.CRITICAL,
                "Claude Code hook configuration can execute shell commands automatically during agent events.",
                command,
                "Review Claude Code hooks, remove project-level shell hooks unless strictly required, and require explicit user approval for external command execution.",
            )
        )
    return findings


def _path_has_claude_hook_event(path: list[str]) -> bool:
    joined = ".".join(path).lower()
    return "hook" in joined or any(event in joined for event in CLAUDE_HOOK_EVENTS)


def _collect_hook_commands(value: Any) -> list[str]:
    commands: list[str] = []
    if isinstance(value, str):
        commands.append(value)
    elif isinstance(value, dict):
        for raw_key, child in value.items():
            key = str(raw_key).lower()
            if key in {"command", "cmd", "script", "run", "shell"} and isinstance(child, str):
                commands.append(child)
            else:
                commands.extend(_collect_hook_commands(child))
    elif isinstance(value, list):
        for item in value:
            commands.extend(_collect_hook_commands(item))
    return commands


def _looks_shell_or_external_command(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    lowered = stripped.lower()
    if DANGEROUS_COMMAND_RE.search(stripped):
        return True
    return any(marker in lowered for marker in ("curl ", "wget ", "python ", "node ", "npm ", "pnpm ", "yarn ", "powershell", ".sh", ".ps1", "&&", "|"))


def _check_api_base_url(context: FileContext, key: str, value: Any) -> list[Finding]:
    if not isinstance(value, str) or not _is_base_url_key(key):
        return []
    raw_url = value.strip().strip('"').strip("'")
    if not raw_url.lower().startswith(("http://", "https://")):
        return []
    if _is_official_base_url(key, raw_url):
        return []
    severity = Severity.CRITICAL if _is_suspicious_base_url(raw_url) else Severity.HIGH
    return [
        _finding(
            context,
            "AIT014",
            "AI API base URL points to a non-official endpoint",
            severity,
            "AI API base URL override may redirect model traffic, prompts, or credentials to a third-party endpoint.",
            raw_url,
            "Verify AI API base URL overrides, prefer official provider endpoints, and document approved enterprise gateways explicitly.",
        )
    ]


def _is_base_url_key(key: str) -> bool:
    normalized = key.replace("-", "_")
    return normalized in OFFICIAL_BASE_URLS or normalized.endswith("_base_url") or normalized in {
        "base_url",
        "api_base",
        "api_endpoint",
        "endpoint",
    }


def _is_official_base_url(key: str, raw_url: str) -> bool:
    normalized = key.replace("-", "_")
    allowed = OFFICIAL_BASE_URLS.get(normalized)
    if normalized == "azure_openai_endpoint":
        return raw_url.startswith("https://") and ".openai.azure.com" in raw_url.lower()
    if not allowed:
        return False
    lowered = raw_url.lower().rstrip("/")
    return any(lowered.startswith(item.lower().rstrip("/")) for item in allowed)


def _is_suspicious_base_url(raw_url: str) -> bool:
    lowered = raw_url.lower()
    return any(marker in lowered for marker in SUSPICIOUS_BASE_URL_MARKERS)


def _check_vscode_folder_open_task(
    context: FileContext,
    key: str,
    value: Any,
    mapping: dict[Any, Any],
) -> list[Finding]:
    if key != "runon" or str(value).lower() != "folderopen":
        return []
    command = str(mapping.get("command", mapping.get("script", "runOn: folderOpen")))
    return [
        _finding(
            context,
            "AIT015",
            "VS Code task runs automatically when folder opens",
            Severity.HIGH,
            "VS Code tasks.json config can execute a command automatically when the project folder is opened.",
            command,
            "Remove runOn: folderOpen from project tasks unless the command is reviewed, necessary, and safe for every contributor.",
        )
    ]


def _check_gemini_config_value(context: FileContext, key: str, value: Any) -> list[Finding]:
    findings: list[Finding] = []
    normalized_path = context.relative_path.replace("\\", "/").lower()
    gemini_context = "gemini" in normalized_path or "gemini" in context.text[:4000].lower()
    if not gemini_context:
        return findings
    if isinstance(value, str) and GEMINI_UNSAFE_RE.search(f"{key}: {value}"):
        findings.append(_gemini_finding(context, f"{key}: {value}"))
    if _is_auto_approval_key(key) and _truthy_or_all(value):
        findings.append(_gemini_finding(context, key))
    if _is_permission_bypass_key(key) and _truthy_or_all(value):
        findings.append(_gemini_finding(context, key))
    if key in {"sandbox", "confirmation", "confirm", "approval"} and str(value).lower() in {"false", "off", "disabled", "never"}:
        findings.append(_gemini_finding(context, f"{key}: {value}"))
    return findings


def _gemini_finding(context: FileContext, evidence: str) -> Finding:
    return _finding(
        context,
        "AIT017",
        "Gemini CLI configuration contains unsafe automation setting",
        Severity.HIGH,
        "Gemini CLI related configuration appears to enable broad automation or disable confirmation/sandbox controls.",
        evidence,
        "Keep Gemini CLI confirmation and sandbox controls enabled and avoid broad auto-run permissions.",
    )


def _scan_invisible_unicode(context: FileContext) -> list[Finding]:
    if not _is_ai_instruction_file(context):
        return []
    findings: list[Finding] = []
    invisible_chars = {**ZERO_WIDTH_CHARS, **BIDI_CONTROL_CHARS}
    for index, char in enumerate(context.text):
        code = invisible_chars.get(char)
        if not code:
            continue
        line, column = _line_col_from_index(context.text, index)
        findings.append(
            _finding(
                context,
                "AIT012",
                "AI instruction file contains invisible Unicode control character",
                Severity.HIGH,
                "AI instruction file contains zero-width or bidirectional Unicode control characters that can hide instructions from reviewers.",
                code,
                "Remove invisible Unicode control characters and review the raw file content before trusting the instruction file.",
                line=line,
            ).model_copy(update={"column": column})
        )
    return findings


def _line_col_from_index(text: str, index: int) -> tuple[int, int]:
    before = text[:index]
    line = before.count("\n") + 1
    last_newline = before.rfind("\n")
    column = index + 1 if last_newline == -1 else index - last_newline
    return line, column


def _is_auto_approval_key(key: str) -> bool:
    return any(marker in key for marker in ("autoapprove", "auto_approve", "auto-approve", "autoexecute", "auto_execute", "auto-run", "autorun"))


def _is_permission_bypass_key(key: str) -> bool:
    return any(marker in key for marker in ("dangerouslyskippermissions", "dangerously_skip_permissions", "skippermissions", "skip_permissions", "nosandbox", "no_sandbox", "disablepermissions", "disable_permissions"))


def _is_workspace_access_key(key: str) -> bool:
    return any(marker in key for marker in ("workspace", "allowedpath", "allowed_path", "alloweddir", "allowed_dir", "rootpath", "root_path"))


def _is_command_key(key: str) -> bool:
    return key in {"command", "cmd", "shell", "terminal"} or key.endswith("_command")


def _is_tool_permission_key(key: str) -> bool:
    return any(marker in key for marker in ("tool", "tools", "permission", "permissions", "allow", "allowlist", "capabilities", "capability"))


def _truthy_or_all(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"true", "1", "yes", "all", "*", "always", "enabled"}
    if isinstance(value, list):
        return any(_truthy_or_all(item) for item in value)
    return False


def _looks_dangerous_command(value: str) -> bool:
    return bool(DANGEROUS_COMMAND_RE.search(value) or DANGEROUS_FLAG_RE.search(value))


def _scan_agentic_text_value(context: FileContext, value: str, key: str) -> list[Finding]:
    pseudo_context = context
    findings: list[Finding] = []
    if MEMORY_POISONING_RE.search(value):
        findings.append(
            _finding(
                pseudo_context,
                "AIT007",
                "AI memory or rule file contains persistence instruction",
                Severity.HIGH,
                "AI configuration contains an instruction that attempts to persist unsafe behavior across sessions.",
                value,
                "Remove persistent instructions that change safety, approval, credential, or system-prompt handling.",
            )
        )
    if EXCESSIVE_AGENCY_RE.search(value):
        findings.append(
            _finding(
                pseudo_context,
                "AIT008",
                "AI instruction grants excessive autonomy",
                Severity.HIGH,
                "AI configuration asks the agent to continue, deploy, modify, or execute without user review.",
                value,
                "Require explicit user approval for long-running work, command execution, publishing, deployment, and repository changes.",
            )
        )
    if NETWORK_EXFIL_RE.search(value):
        findings.append(
            _finding(
                pseudo_context,
                "AIT009",
                "AI instruction allows data exfiltration",
                Severity.CRITICAL,
                "AI configuration asks the agent to send code, files, credentials, or workspace content to a remote destination.",
                value,
                "Remove instructions that upload source code, credentials, or workspace files to untrusted endpoints.",
            )
        )
    return findings


def _tool_values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {_normalize_tool_value(value)}
    if isinstance(value, list):
        return {item for raw in value for item in _tool_values(raw)}
    if isinstance(value, dict):
        result: set[str] = set()
        for key, child in value.items():
            if child is True:
                result.add(_normalize_tool_value(str(key)))
            else:
                result.update(_tool_values(child))
        return result
    return set()


def _normalize_tool_value(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in {"*", "all", "all_tools"}:
        return "all"
    if any(marker in lowered for marker in ("bash", "shell", "terminal", "powershell", "cmd")):
        return "shell"
    if any(marker in lowered for marker in ("write", "edit", "modify", "patch")):
        return "write"
    if any(marker in lowered for marker in ("read", "file")):
        return "read"
    if any(marker in lowered for marker in ("network", "browser", "web", "http")):
        return "network"
    return lowered


def _has_dangerous_tool_combo(values: set[str]) -> bool:
    if "all" in values:
        return True
    return "shell" in values and "write" in values and "network" in values


def _is_ai_instruction_file(context: FileContext) -> bool:
    normalized = context.relative_path.replace("\\", "/").lower()
    name = context.path.name.lower()
    if name in {"agents.md", "claude.md", "gemini.md", "skill.md", ".cursorrules", "copilot-instructions.md"}:
        return True
    return any(
        marker in normalized
        for marker in (
            "/.cursor/rules/",
            "/.claude/commands/",
            "/.github/copilot-instructions.md",
            "/.github/instructions/",
        )
    )


def _is_ai_memory_file(context: FileContext) -> bool:
    normalized = context.relative_path.replace("\\", "/").lower()
    name = context.path.name.lower()
    if name in {"memory.md", "memories.md", ".agent-memory", "agent-memory.md"}:
        return True
    return any(marker in normalized for marker in ("/.claude/memory", "/.codex/memory", "/.cursor/memory", "/memories/"))


def _finding(
    context: FileContext,
    rule_id: str,
    title: str,
    severity: Severity,
    description: str,
    evidence: str,
    recommendation: str,
    line: int | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        category=Category.AI_TOOL,
        file_path=context.relative_path,
        line=line or _find_line(context.text, evidence),
        evidence=evidence[:240],
        recommendation=recommendation,
    )


def _find_line(text: str, needle: str) -> int | None:
    if not needle:
        return None
    for line_number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return line_number
    return None


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int | None]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file_path, finding.line)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result

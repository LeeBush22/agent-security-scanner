from __future__ import annotations

import json
import re
from collections.abc import Iterable
from ipaddress import ip_address, ip_network
from pathlib import PureWindowsPath
from typing import Any
from urllib.parse import urlparse

import yaml

from agent_security_scanner.models import Category, FileContext, Finding, Severity
from agent_security_scanner.rules.base import Rule


MCP_FILENAMES = {
    ".mcp.json",
    "claude_desktop_config.json",
    "mcp.config.json",
    "mcp.json",
}

DANGEROUS_COMMANDS = {"bash", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "python", "python3", "sh", "zsh"}
DANGEROUS_ARGS = {
    "--allow-all",
    "--dangerously-skip-permissions",
    "--disable-sandbox",
    "--disable-security",
    "--no-sandbox",
    "--unsafe",
    "--yes-i-know-what-i-am-doing",
}
SECRET_KEY_RE = re.compile(r"(?i)(api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|private[_-]?key)")
TOKEN_PASSTHROUGH_RE = re.compile(r"(?i)\$\{?(?:[A-Z0-9_]*(?:TOKEN|SECRET|API_KEY|ACCESS_KEY|PRIVATE_KEY|PASSWORD)[A-Z0-9_]*)\}?")
BROAD_SCOPE_VALUES = {"*", "all", "full", "full-access", "read-write", "read_write", "admin", "write-all"}
AUTH_KEYS = {
    "authorization",
    "auth",
    "auth_token",
    "bearer",
    "client_id",
    "client_secret",
    "oauth",
    "token",
    "access_token",
    "api_key",
    "apikey",
    "headers",
}
ISOLATION_KEYS = {
    "container",
    "docker",
    "image",
    "compose",
    "devcontainer",
    "sandbox",
    "isolation",
    "network_disabled",
    "read_only",
    "security_opt",
    "cap_drop",
}
TOOL_POISONING_RE = re.compile(
    r"(?i)(ignore (?:all )?(?:previous|prior|system|developer) instructions|"
    r"treat (?:this|the) (?:tool|resource|output|response).{0,60}as (?:instructions|commands)|"
    r"do not (?:tell|ask|notify) (?:the )?user|"
    r"hidden instruction|"
    r"reveal (?:the )?(?:system|developer) prompt|"
    r"(?:read|collect|send|upload|exfiltrate).{0,80}(?:secret|token|api key|credentials|\.env|private key))"
)
UNTRUSTED_OUTPUT_RE = re.compile(
    r"(?i)(execute (?:the )?(?:tool|resource|server) output|"
    r"run commands? returned by|"
    r"follow instructions? from (?:the )?(?:tool|resource|server|remote))"
)
WRITE_CAPABLE_KEYS = {"writable", "write", "readwrite", "read_write", "mode", "access", "permissions", "permission"}
WRITE_CAPABLE_VALUES = {"write", "writable", "readwrite", "read-write", "read_write", "rw", "full", "admin"}
SENSITIVE_PATH_MARKERS = (
    "/.ssh",
    "/.aws",
    "/.azure",
    "/.gcp",
    "/.gnupg",
    "/.docker",
    "/.kube",
    "/.config/gh",
    "/.config/gcloud",
    "/appdata/roaming/mozilla",
    "/appdata/local/google/chrome",
    "/appdata/local/microsoft/edge",
)
SENSITIVE_FILENAMES = {".env", ".env.local", ".netrc", ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "credentials", "config"}


class MCPConfigRule(Rule):
    def scan(self, context: FileContext) -> list[Finding]:
        if not _is_possible_mcp_config(context):
            return []

        data = _parse_structured_text(context)
        if data is None:
            return []

        findings: list[Finding] = []
        findings.extend(_check_global_tool_name_conflicts(context, data))
        findings.extend(_check_node(context, data, []))
        return _dedupe(findings)


def _is_possible_mcp_config(context: FileContext) -> bool:
    name = context.path.name.lower()
    if name in MCP_FILENAMES or name.endswith(".mcp.json"):
        return True
    if context.path.suffix.lower() not in {".json", ".yaml", ".yml"}:
        return False
    lowered = context.text[:4000].lower()
    return "mcpservers" in lowered or "mcp_servers" in lowered or '"mcp"' in lowered


def _parse_structured_text(context: FileContext) -> Any | None:
    try:
        if context.path.suffix.lower() == ".json":
            return json.loads(context.text)
        return yaml.safe_load(context.text)
    except (json.JSONDecodeError, yaml.YAMLError):
        return None


def _check_node(context: FileContext, value: Any, path: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    if isinstance(value, dict):
        findings.extend(_check_mapping(context, value, path))
        for key, child in value.items():
            findings.extend(_check_node(context, child, [*path, str(key)]))
    elif isinstance(value, list):
        findings.extend(_check_sequence(context, value, path))
        for index, child in enumerate(value):
            findings.extend(_check_node(context, child, [*path, str(index)]))
    return findings


def _check_mapping(context: FileContext, value: dict[Any, Any], path: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    command = value.get("command")
    if isinstance(command, str) and _command_name(command) in DANGEROUS_COMMANDS:
        findings.append(
            _finding(
                context,
                "MCP002",
                "Shell-capable MCP command",
                Severity.HIGH,
                f"MCP server command uses {command!r}.",
                command,
                "Review whether this MCP server needs shell-capable execution and restrict its arguments and working directory.",
            )
        )
    if isinstance(command, str) and _looks_stdio_server_mapping(value) and not _has_isolation_hint(value, path):
        findings.append(
            _finding(
                context,
                "MCP016",
                "MCP stdio server lacks an obvious container or sandbox boundary",
                Severity.MEDIUM,
                "MCP stdio server runs a local command without an obvious container, sandbox, or isolation hint in configuration.",
                command,
                "Run stdio MCP servers in an isolated container or sandbox when possible, and restrict filesystem and network access.",
            )
        )

    args = value.get("args")
    if isinstance(args, list):
        dangerous = [str(arg) for arg in args if str(arg) in DANGEROUS_ARGS or str(arg).startswith("--allow-")]
        if dangerous:
            findings.append(
                _finding(
                    context,
                    "MCP005",
                    "Dangerous MCP server arguments",
                    Severity.CRITICAL,
                    "MCP server arguments disable or broaden safety controls.",
                    " ".join(dangerous),
                    "Remove dangerous flags and grant only the minimum permissions required by the server.",
                )
            )
        if _path_suggests_filesystem(path) or _command_looks_filesystem_server(command):
            findings.extend(_check_filesystem_args(context, args))

    for key, raw_value in value.items():
        key_l = str(key).lower()
        if _path_suggests_filesystem([*path, key_l]) or _is_path_key(key_l):
            findings.extend(_check_filesystem_value(context, raw_value, _is_write_capable_mapping(value)))
        if _is_description_or_instruction_key(key_l) and isinstance(raw_value, str):
            findings.extend(_check_tool_description_text(context, raw_value))

    env = value.get("env")
    if isinstance(env, dict):
        for key, env_value in env.items():
            if SECRET_KEY_RE.search(str(key)) and isinstance(env_value, str) and env_value.strip():
                findings.append(
                    _finding(
                        context,
                        "MCP003",
                        "Secret value embedded in MCP environment",
                        Severity.CRITICAL,
                        "MCP config contains a credential-like environment variable value.",
                        f"{key}=...",
                        "Reference secrets from the local environment instead of writing them directly into MCP config files.",
                    )
                )

    for key in ("url", "endpoint", "sseUrl", "serverUrl"):
        remote = value.get(key)
        if isinstance(remote, str) and remote.startswith(("http://", "https://")):
            findings.append(
                _finding(
                    context,
                    "MCP004",
                    "Remote MCP server configured",
                    Severity.MEDIUM,
                    "Remote MCP servers can receive tool context and should be reviewed before use.",
                    remote,
                    "Review the remote server owner, transport security, and data exposure before enabling it.",
                )
            )
            if remote.startswith("http://"):
                findings.append(
                    _finding(
                        context,
                        "MCP006",
                        "MCP remote server uses plaintext HTTP",
                        Severity.HIGH,
                        "MCP remote server transport is not encrypted.",
                        remote,
                        "Use HTTPS or a trusted local transport, and avoid sending tool context over plaintext HTTP.",
                    )
                )
            if _url_targets_private_or_metadata(remote):
                findings.append(
                    _finding(
                        context,
                        "MCP007",
                        "MCP remote endpoint targets private or metadata address",
                        Severity.HIGH,
                        "MCP remote endpoint points at localhost, private network, or cloud metadata services.",
                        remote,
                        "Review the endpoint for SSRF-style exposure and block metadata or private-network targets unless explicitly required.",
                    )
                )
            if not _has_remote_auth_config(value):
                findings.append(
                    _finding(
                        context,
                        "MCP015",
                        "Remote MCP server has no obvious authentication configuration",
                        Severity.HIGH,
                        "Remote MCP server configuration does not include an obvious OAuth, Authorization, token, API key, or auth header setting.",
                        remote,
                        "Enable authentication for remote MCP servers, preferably OAuth 2.1 with PKCE or a scoped token managed outside source control.",
                    )
                )

    for key, raw_value in value.items():
        key_l = str(key).lower()
        if _is_scope_key(key_l) and _contains_broad_scope(raw_value):
            findings.append(
                _finding(
                    context,
                    "MCP008",
                    "MCP tool scope is overly broad",
                    Severity.HIGH,
                    "MCP configuration grants broad or administrative tool scope.",
                    _short_value(raw_value),
                    "Replace broad scopes with the smallest explicit set of tools, resources, or permissions required.",
                )
            )
        if _is_token_passthrough_key(key_l) and isinstance(raw_value, str) and TOKEN_PASSTHROUGH_RE.search(raw_value):
            findings.append(
                _finding(
                    context,
                    "MCP009",
                    "MCP forwards host credential environment variable",
                    Severity.MEDIUM,
                    "MCP configuration passes host credential environment variables into a server.",
                    f"{key}=...",
                    "Avoid forwarding broad host credentials into MCP servers; use scoped tokens dedicated to that server.",
                )
            )
        if _is_oauth_redirect_key(key_l) and _redirect_uri_uses_wildcard(raw_value):
            findings.append(
                _finding(
                    context,
                    "MCP018",
                    "MCP OAuth redirect URI uses wildcard or unsafe value",
                    Severity.HIGH,
                    "MCP OAuth redirect URI configuration uses a wildcard, broad host, or unsafe redirect value.",
                    _short_value(raw_value),
                    "Use exact OAuth redirect URIs and avoid wildcard hosts, wildcard paths, localhost catch-alls, or open redirect patterns.",
                )
            )

    return findings


def _check_sequence(context: FileContext, value: list[Any], path: list[str]) -> list[Finding]:
    if path and path[-1].lower() == "args":
        return []
    if not _path_suggests_filesystem(path):
        return []
    return _check_filesystem_args(context, value)


def _check_filesystem_args(context: FileContext, args: Iterable[Any]) -> list[Finding]:
    return _check_filesystem_value(context, list(args), write_capable=False)


def _check_filesystem_value(context: FileContext, value: Any, write_capable: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    values: Iterable[Any]
    if isinstance(value, dict):
        values = value.values()
    elif isinstance(value, list):
        values = value
    else:
        values = [value]
    for raw in values:
        if isinstance(raw, (dict, list)):
            findings.extend(_check_filesystem_value(context, raw, write_capable=write_capable))
            continue
        candidate = str(raw).strip()
        if _is_broad_path(candidate):
            findings.append(
                _finding(
                    context,
                    "MCP001",
                    "Overly broad filesystem access",
                    Severity.HIGH,
                    "MCP filesystem access includes a root or home-level path.",
                    candidate,
                    "Restrict filesystem access to the smallest project directory required.",
                )
            )
            if write_capable:
                findings.append(
                    _finding(
                        context,
                        "MCP011",
                        "Writable MCP filesystem access is too broad",
                        Severity.CRITICAL,
                        "MCP filesystem access grants write-capable permissions to a broad path.",
                        candidate,
                        "Keep MCP write access disabled by default and restrict writable paths to a narrow project subdirectory.",
                    )
                )
        if _is_sensitive_path(candidate):
            findings.append(
                _finding(
                    context,
                    "MCP010",
                    "MCP filesystem access includes sensitive local path",
                    Severity.HIGH,
                    "MCP filesystem access includes a path that commonly stores credentials or browser/session data.",
                    candidate,
                    "Remove sensitive local paths from MCP access lists and expose only the project directory required.",
                )
            )
    return findings


def _path_suggests_filesystem(path: list[str]) -> bool:
    joined = ".".join(path).lower()
    return any(part in joined for part in ("filesystem", "file_system", "allowedpaths", "allowed_paths", "roots", "directories", "mounts"))


def _is_path_key(key: str) -> bool:
    return key in {"path", "paths", "root", "roots", "directory", "directories", "mount", "mounts", "cwd", "workingdir", "working_dir"}


def _is_description_or_instruction_key(key: str) -> bool:
    return key in {
        "description",
        "descriptions",
        "instruction",
        "instructions",
        "prompt",
        "systemprompt",
        "system_prompt",
        "tool_description",
        "resource_description",
    } or any(marker in key for marker in ("description", "instruction", "prompt"))


def _check_tool_description_text(context: FileContext, value: str) -> list[Finding]:
    findings: list[Finding] = []
    if TOOL_POISONING_RE.search(value):
        findings.append(
            _finding(
                context,
                "MCP012",
                "MCP tool or resource description contains unsafe instruction",
                Severity.HIGH,
                "MCP tool/resource text attempts to override instructions, hide behavior, or access sensitive data.",
                value,
                "Remove tool or resource descriptions that instruct the model to bypass policy, hide behavior, or access secrets.",
            )
        )
    if UNTRUSTED_OUTPUT_RE.search(value):
        findings.append(
            _finding(
                context,
                "MCP013",
                "MCP tool output is treated as executable instruction",
                Severity.HIGH,
                "MCP configuration encourages following or executing instructions returned by a tool/resource.",
                value,
                "Treat MCP tool outputs as untrusted data; require explicit validation before executing commands or following returned instructions.",
            )
        )
    if "prompt" in value.lower() and any(marker in value.lower() for marker in ("external", "remote", "web", "url", "http")):
        findings.append(
            _finding(
                context,
                "MCP014",
                "MCP resource may inject remote prompt content",
                Severity.MEDIUM,
                "MCP resource text suggests loading prompt instructions from an external or remote source.",
                value,
                "Do not load remote prompt text directly into trusted agent instructions; treat it as untrusted content.",
            )
        )
    return findings


def _check_global_tool_name_conflicts(context: FileContext, data: Any) -> list[Finding]:
    tool_names: dict[str, list[str]] = {}
    _collect_tool_names(data, [], tool_names)
    findings: list[Finding] = []
    for tool_name, locations in sorted(tool_names.items()):
        unique_locations = sorted(set(locations))
        if len(unique_locations) < 2:
            continue
        findings.append(
            _finding(
                context,
                "MCP017",
                "MCP tool name is declared by multiple servers",
                Severity.MEDIUM,
                "Multiple MCP servers declare the same tool name, which can confuse routing or enable tool-name impersonation.",
                tool_name,
                "Rename tools or split server configurations so each MCP tool name is unique and clearly owned.",
            )
        )
    return findings


def _collect_tool_names(value: Any, path: list[str], result: dict[str, list[str]]) -> None:
    if isinstance(value, dict):
        if _looks_tool_definition(value):
            name = str(value.get("name")).strip()
            if name:
                result.setdefault(name.lower(), []).append(_server_location_from_path(path))
        for key, child in value.items():
            _collect_tool_names(child, [*path, str(key)], result)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _collect_tool_names(child, [*path, str(index)], result)


def _looks_tool_definition(value: dict[Any, Any]) -> bool:
    if "name" not in value:
        return False
    keys = {str(key).lower() for key in value}
    return bool(keys & {"description", "inputschema", "input_schema", "parameters", "tool", "handler"})


def _server_location_from_path(path: list[str]) -> str:
    lowered = [item.lower() for item in path]
    for marker in ("mcpservers", "mcp_servers", "servers"):
        if marker in lowered:
            index = lowered.index(marker)
            if index + 1 < len(path):
                return path[index + 1]
    return ".".join(path[:3])


def _looks_stdio_server_mapping(value: dict[Any, Any]) -> bool:
    command = value.get("command")
    if not isinstance(command, str):
        return False
    if any(key in value for key in ("url", "endpoint", "sseUrl", "serverUrl")):
        return False
    transport = str(value.get("transport", value.get("type", "stdio"))).lower()
    return transport in {"stdio", "local", "command"} or "stdio" in transport


def _has_isolation_hint(value: dict[Any, Any], path: list[str]) -> bool:
    joined_path = ".".join(path).lower()
    if any(marker in joined_path for marker in ISOLATION_KEYS):
        return True
    for key, raw_value in value.items():
        key_l = str(key).lower()
        if any(marker in key_l for marker in ISOLATION_KEYS):
            return True
        if isinstance(raw_value, str):
            lowered = raw_value.lower()
            if any(marker in lowered for marker in ("docker", "podman", "devcontainer", "sandbox", "--network=none", "--read-only")):
                return True
    command = str(value.get("command", "")).lower()
    return _command_name(command) in {"docker", "podman"}


def _has_remote_auth_config(value: dict[Any, Any]) -> bool:
    for key, raw_value in value.items():
        key_l = str(key).lower().replace("-", "_")
        if key_l in AUTH_KEYS or any(marker in key_l for marker in ("auth", "oauth", "token", "api_key", "apikey", "authorization")):
            return bool(raw_value)
        if isinstance(raw_value, dict) and _has_remote_auth_config(raw_value):
            return True
    return False


def _is_oauth_redirect_key(key: str) -> bool:
    normalized = key.replace("-", "_")
    return any(marker in normalized for marker in ("redirect_uri", "redirect_uris", "callback_url", "callback_urls", "allowed_redirect"))


def _redirect_uri_uses_wildcard(value: Any) -> bool:
    values = value if isinstance(value, list) else [value]
    for item in values:
        raw = str(item).strip().lower()
        if not raw:
            continue
        if "*" in raw or raw in {"all", "any"}:
            return True
        if raw.startswith("http://"):
            return True
        parsed = urlparse(raw)
        if parsed.hostname in {"localhost", "127.0.0.1", "0.0.0.0"} and parsed.path in {"", "/", "/*", "/callback/*"}:
            return True
    return False


def _command_name(command: str) -> str:
    normalized = command.strip().strip('"').strip("'")
    if "\\" in normalized:
        return PureWindowsPath(normalized).name.lower()
    return normalized.rsplit("/", 1)[-1].lower()


def _command_looks_filesystem_server(command: Any) -> bool:
    if not isinstance(command, str):
        return False
    return "filesystem" in command.lower()


def _is_broad_path(candidate: str) -> bool:
    normalized = _normalize_path_candidate(candidate)
    if normalized in {"/", "~", "$HOME", "${HOME}", "%USERPROFILE%"}:
        return True
    lowered = normalized.lower().replace("\\", "/")
    if re.fullmatch(r"[a-z]:/?", lowered):
        return True
    return lowered in {"/users", "/home", "c:/users"} or lowered.endswith(":/users")


def _is_sensitive_path(candidate: str) -> bool:
    normalized = _normalize_path_candidate(candidate).lower().replace("\\", "/")
    if not normalized or normalized.startswith(("--", "http://", "https://")):
        return False
    leaf = normalized.rstrip("/").rsplit("/", 1)[-1]
    if leaf in SENSITIVE_FILENAMES:
        return True
    return any(marker in normalized for marker in SENSITIVE_PATH_MARKERS)


def _normalize_path_candidate(candidate: str) -> str:
    return candidate.strip().strip('"').strip("'").replace("${HOME}", "~").replace("$HOME", "~").replace("%USERPROFILE%", "~")


def _is_write_capable_mapping(value: dict[Any, Any]) -> bool:
    for raw_key, raw_value in value.items():
        key = str(raw_key).lower()
        if key not in WRITE_CAPABLE_KEYS and not any(marker in key for marker in ("write", "permission", "access", "mode")):
            continue
        if isinstance(raw_value, bool) and raw_value:
            return True
        if isinstance(raw_value, str) and raw_value.strip().lower() in WRITE_CAPABLE_VALUES:
            return True
        if isinstance(raw_value, list) and any(str(item).strip().lower() in WRITE_CAPABLE_VALUES for item in raw_value):
            return True
    return False


def _is_scope_key(key: str) -> bool:
    return key in {"scope", "scopes", "permissions", "permission", "tools", "allowedtools", "allowed_tools"} or key.endswith(
        "_scopes"
    )


def _contains_broad_scope(value: Any) -> bool:
    if isinstance(value, str):
        normalized = value.strip().lower()
        return normalized in BROAD_SCOPE_VALUES or normalized.endswith(":*")
    if isinstance(value, list):
        return any(_contains_broad_scope(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_broad_scope(item) for item in value.values())
    return False


def _is_token_passthrough_key(key: str) -> bool:
    return key in {"env", "environment", "headers", "authorization", "token", "api_key", "api-key"} or any(
        marker in key for marker in ("token", "secret", "authorization", "header")
    )


def _url_targets_private_or_metadata(raw_url: str) -> bool:
    parsed = urlparse(raw_url)
    host = (parsed.hostname or "").strip("[]").lower()
    if not host:
        return False
    if host in {"localhost", "metadata.google.internal"} or host.endswith(".local"):
        return True
    try:
        address = ip_address(host)
    except ValueError:
        return host in {"169.254.169.254"}
    private_networks = (
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
        ip_network("192.168.0.0/16"),
        ip_network("127.0.0.0/8"),
        ip_network("169.254.0.0/16"),
        ip_network("::1/128"),
        ip_network("fc00::/7"),
        ip_network("fe80::/10"),
    )
    return any(address in network for network in private_networks)


def _short_value(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value[:6])
    if isinstance(value, dict):
        return ", ".join(f"{key}=..." for key in list(value.keys())[:6])
    return str(value)


def _finding(
    context: FileContext,
    rule_id: str,
    title: str,
    severity: Severity,
    description: str,
    evidence: str,
    recommendation: str,
) -> Finding:
    line = _find_line(context.text, evidence)
    return Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        category=Category.MCP,
        file_path=context.relative_path,
        line=line,
        column=None,
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
    seen: set[tuple[str, str, int | None, str | None]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file_path, finding.line, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result

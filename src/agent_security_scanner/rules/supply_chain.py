from __future__ import annotations

import json
import re
from typing import Any

import yaml

from agent_security_scanner.models import Category, FileContext, Finding, Severity
from agent_security_scanner.rules.base import Rule


INSTALL_SCRIPT_NAMES = {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishonly"}
RISKY_SCRIPT_RE = re.compile(
    r"(?i)(curl|wget|Invoke-WebRequest|iwr).{0,120}\|\s*(sh|bash|zsh|iex|Invoke-Expression)|"
    r"\b(npm|pnpm|yarn)\s+(?:install|add)\s+[^&|;]*(?:https?:|git\+|github:)|"
    r"\b(?:python|node|ruby|perl)\s+-[ce]\s+"
)
UNTRUSTED_DEP_RE = re.compile(r"(?i)^(?:https?:|git\+https?:|git\+ssh:|github:|gitlab:|bitbucket:)")
TOKEN_CONFIG_RE = re.compile(r"(?i)(?:_authToken|password|token|api[_-]?key)\s*=\s*(?!\$\{)[^\s#;]{8,}")
LATEST_TAG_RE = re.compile(r"(?i):latest(?:\s|$)")
ADD_REMOTE_RE = re.compile(r"(?i)^\s*ADD\s+https?://")
RUN_DOWNLOAD_EXEC_RE = re.compile(r"(?i)^\s*RUN\s+.*(?:curl|wget).{0,160}\|\s*(?:sh|bash|zsh)")
GYP_COMMAND_SUBSTITUTION_RE = re.compile(r"<!@?\s*\([^)]{1,240}\)")
SETUP_PY_RISKY_RE = re.compile(
    r"(?i)(os\.system\s*\(|subprocess\.(?:run|call|check_call|check_output|Popen)\s*\(|"
    r"(?:urllib\.request|requests)\.[a-z_]+\s*\(.{0,120}(?:exec|eval|os\.system|subprocess)|"
    r"(?:curl|wget).{0,120}\|\s*(?:sh|bash|zsh)|"
    r"base64\.b64decode\s*\(.{0,160}(?:exec|eval|subprocess|os\.system))"
)
PRIVILEGED_CONTAINER_KEYS = {"privileged", "pid", "network_mode"}
HOST_MOUNT_MARKERS = (
    "/var/run/docker.sock",
    "/:/",
    "c:\\",
    "~/.ssh",
    "~/.aws",
    "${home}/.ssh",
    "$home/.ssh",
    "${localenv:home}/.ssh",
    "${localworkspacefolder}/..",
)


class SupplyChainRule(Rule):
    def scan(self, context: FileContext) -> list[Finding]:
        name = context.path.name.lower()
        normalized = context.relative_path.replace("\\", "/").lower()

        if name == "package.json":
            return _scan_package_json(context)
        if name in {".npmrc", ".pypirc", ".netrc"}:
            return _scan_credential_config(context)
        if name == "dockerfile" or normalized.endswith("/dockerfile"):
            return _scan_dockerfile(context)
        if name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
            return _scan_compose(context)
        if name == "devcontainer.json" or normalized.endswith("/.devcontainer/devcontainer.json"):
            return _scan_devcontainer(context)
        if name.startswith("requirements") and name.endswith(".txt"):
            return _scan_requirements(context)
        if name == "binding.gyp":
            return _scan_binding_gyp(context)
        if name == "setup.py":
            return _scan_setup_py(context)
        return []


def _scan_package_json(context: FileContext) -> list[Finding]:
    try:
        data = json.loads(context.text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []

    findings: list[Finding] = []
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for name, command in scripts.items():
            if not isinstance(command, str):
                continue
            if str(name).lower() in INSTALL_SCRIPT_NAMES:
                findings.append(
                    _finding(
                        context,
                        "SC001",
                        "Package lifecycle script executes during install",
                        Severity.HIGH,
                        "package.json contains a lifecycle script that runs automatically during package install or publish.",
                        str(name),
                        "Review lifecycle scripts carefully and avoid running network, shell, or code-generation commands during install.",
                    )
                )
            if RISKY_SCRIPT_RE.search(command):
                findings.append(
                    _finding(
                        context,
                        "SC002",
                        "Package script contains risky install or execution command",
                        Severity.HIGH,
                        "package.json script downloads or executes code in a way that can compromise the development environment.",
                        command,
                        "Replace dynamic install/download execution with pinned, reviewed, and integrity-checked dependencies.",
                    )
                )

    for section_name in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        dependencies = data.get(section_name)
        if not isinstance(dependencies, dict):
            continue
        for package, version in dependencies.items():
            if isinstance(version, str) and UNTRUSTED_DEP_RE.search(version):
                findings.append(
                    _finding(
                        context,
                        "SC003",
                        "Package dependency uses remote Git or URL source",
                        Severity.MEDIUM,
                        "Dependency is installed from a remote URL or Git source instead of a registry version.",
                        f"{package}: {version}",
                        "Prefer pinned registry versions or commit-pinned sources from trusted owners.",
                    )
                )
            if isinstance(version, str) and version.strip() in {"*", "latest"}:
                findings.append(
                    _finding(
                        context,
                        "SC004",
                        "Package dependency version is unpinned",
                        Severity.MEDIUM,
                        "Dependency uses a wildcard or latest version.",
                        f"{package}: {version}",
                        "Pin dependency versions and update them deliberately.",
                    )
                )
    return _dedupe(findings)


def _scan_credential_config(context: FileContext) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(context.text.splitlines(), start=1):
        if TOKEN_CONFIG_RE.search(line):
            findings.append(
                _finding(
                    context,
                    "SC005",
                    "Package manager credential stored in config file",
                    Severity.CRITICAL,
                    "Package manager configuration contains a plaintext credential value.",
                    line.strip(),
                    "Move package manager credentials to environment variables or a secret manager and rotate exposed values.",
                    line=line_number,
                )
            )
    return findings


def _scan_dockerfile(context: FileContext) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(context.text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.upper().startswith("FROM ") and LATEST_TAG_RE.search(stripped):
            findings.append(
                _finding(
                    context,
                    "SC006",
                    "Docker base image uses latest tag",
                    Severity.MEDIUM,
                    "Dockerfile uses a mutable latest tag for the base image.",
                    stripped,
                    "Pin base images to a specific version or digest.",
                    line=line_number,
                )
            )
        if ADD_REMOTE_RE.search(stripped):
            findings.append(
                _finding(
                    context,
                    "SC007",
                    "Dockerfile ADD downloads remote content",
                    Severity.MEDIUM,
                    "Dockerfile ADD pulls remote content during build.",
                    stripped,
                    "Download remote content explicitly with integrity checks or vendor reviewed artifacts.",
                    line=line_number,
                )
            )
        if RUN_DOWNLOAD_EXEC_RE.search(stripped):
            findings.append(
                _finding(
                    context,
                    "SC008",
                    "Docker build executes downloaded script",
                    Severity.HIGH,
                    "Dockerfile downloads a script and executes it during image build.",
                    stripped,
                    "Download, verify, and review scripts before executing them in Docker builds.",
                    line=line_number,
                )
            )
    return findings


def _scan_compose(context: FileContext) -> list[Finding]:
    data = _parse_yaml(context)
    if not isinstance(data, dict):
        return []
    findings: list[Finding] = []
    services = data.get("services", {})
    if not isinstance(services, dict):
        return findings
    for service_name, service in services.items():
        if not isinstance(service, dict):
            continue
        for key in PRIVILEGED_CONTAINER_KEYS:
            value = service.get(key)
            if value is True or value in {"host", "service:host"}:
                findings.append(
                    _finding(
                        context,
                        "SC009",
                        "Container service uses privileged or host-level settings",
                        Severity.HIGH,
                        "Compose service uses privileged mode or host-level namespace/network settings.",
                        f"{service_name}.{key}: {value}",
                        "Avoid privileged containers and host namespaces unless they are isolated and explicitly required.",
                    )
                )
        for volume in _as_list(service.get("volumes")):
            if _is_sensitive_mount(str(volume)):
                findings.append(
                    _finding(
                        context,
                        "SC010",
                        "Container mounts sensitive host path",
                        Severity.HIGH,
                        "Compose service mounts a sensitive host path into a container.",
                        str(volume),
                        "Avoid mounting Docker socket, host root, SSH keys, cloud credentials, or broad home directories into containers.",
                    )
                )
    return _dedupe(findings)


def _scan_devcontainer(context: FileContext) -> list[Finding]:
    try:
        data = json.loads(context.text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    findings: list[Finding] = []
    for key in ("postCreateCommand", "postStartCommand", "initializeCommand", "onCreateCommand"):
        command = data.get(key)
        if isinstance(command, str) and RISKY_SCRIPT_RE.search(command):
            findings.append(
                _finding(
                    context,
                    "SC011",
                    "Devcontainer lifecycle command executes risky shell content",
                    Severity.HIGH,
                    "devcontainer lifecycle command downloads or executes dynamic code.",
                    command,
                    "Use pinned setup scripts committed to the repository and avoid dynamic download-to-shell patterns.",
                )
            )
    for mount in _as_list(data.get("mounts")):
        if _is_sensitive_mount(str(mount)):
            findings.append(
                _finding(
                    context,
                    "SC012",
                    "Devcontainer mounts sensitive host path",
                    Severity.HIGH,
                    "devcontainer configuration mounts a sensitive host path.",
                    str(mount),
                    "Avoid mounting Docker socket, SSH keys, cloud credentials, or broad host paths into devcontainers.",
                )
            )
    return _dedupe(findings)


def _scan_requirements(context: FileContext) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, raw_line in enumerate(context.text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if re.search(r"(?i)(?:^|\s)(?:-e\s+)?(?:git\+|https?://)", line):
            findings.append(
                _finding(
                    context,
                    "SC013",
                    "Python requirement uses remote URL or VCS source",
                    Severity.MEDIUM,
                    "requirements file installs a dependency from a remote URL or VCS source.",
                    line,
                    "Prefer pinned package index versions or commit-pinned trusted sources with hash checking.",
                    line=line_number,
                )
            )
        if "==" not in line and not line.startswith(("-", "--")) and not re.search(r"\s+@\s+", line):
            findings.append(
                _finding(
                    context,
                    "SC014",
                    "Python requirement is not version pinned",
                    Severity.LOW,
                    "requirements file contains an unpinned package requirement.",
                    line,
                    "Pin Python dependencies and update them deliberately.",
                    line=line_number,
                )
            )
    return findings


def _scan_binding_gyp(context: FileContext) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(context.text.splitlines(), start=1):
        match = GYP_COMMAND_SUBSTITUTION_RE.search(line)
        if not match:
            continue
        findings.append(
            _finding(
                context,
                "SC015",
                "binding.gyp contains command substitution",
                Severity.CRITICAL,
                "binding.gyp can execute command substitutions during native package build or install.",
                match.group(0),
                "Remove command substitutions from binding.gyp and use reviewed, committed build configuration instead.",
                line=line_number,
            )
        )
    return findings


def _scan_setup_py(context: FileContext) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(context.text.splitlines(), start=1):
        stripped = line.strip()
        if not SETUP_PY_RISKY_RE.search(stripped):
            continue
        findings.append(
            _finding(
                context,
                "SC016",
                "setup.py contains suspicious install-time command execution",
                Severity.HIGH,
                "setup.py appears to execute shell commands, subprocesses, downloaded code, or decoded payloads during package installation.",
                stripped,
                "Avoid arbitrary command execution in setup.py; move build logic to reviewed scripts and keep package installation deterministic.",
                line=line_number,
            )
        )
    return findings


def _parse_yaml(context: FileContext) -> Any | None:
    try:
        return yaml.safe_load(context.text)
    except yaml.YAMLError:
        return None


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _is_sensitive_mount(value: str) -> bool:
    lowered = value.lower().replace("\\", "/")
    return any(marker in lowered for marker in HOST_MOUNT_MARKERS)


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
        category=Category.SUPPLY_CHAIN,
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
    seen: set[tuple[str, str, int | None, str | None]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file_path, finding.line, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result

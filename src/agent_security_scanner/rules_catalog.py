from __future__ import annotations

from dataclasses import dataclass
import re

from agent_security_scanner.models import Category, Severity


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    title: str
    category: Category
    severity: Severity
    description: str


RULE_ID_RE = re.compile(r"^(AIT|SEC|MCP|SH|GHA|SC|FS)\d{3}$")
RULE_PREFIX_CATEGORY = {
    "AIT": Category.AI_TOOL,
    "SEC": Category.SECRETS,
    "MCP": Category.MCP,
    "SH": Category.SHELL,
    "GHA": Category.GITHUB_ACTIONS,
    "SC": Category.SUPPLY_CHAIN,
    "FS": Category.FILESYSTEM,
}


RULE_CATALOG: tuple[RuleInfo, ...] = (
    RuleInfo(
        "AIT001",
        "AI tool auto-approval is enabled or too broad",
        Category.AI_TOOL,
        Severity.HIGH,
        "AI coding tool configuration auto-approves commands, edits, or tool calls.",
    ),
    RuleInfo(
        "AIT002",
        "AI tool permission checks are bypassed",
        Category.AI_TOOL,
        Severity.CRITICAL,
        "AI coding tool configuration disables sandbox or permission checks.",
    ),
    RuleInfo(
        "AIT003",
        "AI tool workspace access is too broad",
        Category.AI_TOOL,
        Severity.HIGH,
        "AI coding tool configuration grants root, home, or drive-level filesystem access.",
    ),
    RuleInfo(
        "AIT004",
        "AI tool can invoke a shell-capable command",
        Category.AI_TOOL,
        Severity.HIGH,
        "AI coding tool configuration includes shell-capable command execution.",
    ),
    RuleInfo(
        "AIT005",
        "Secret embedded in AI coding tool config",
        Category.AI_TOOL,
        Severity.CRITICAL,
        "AI coding tool configuration contains plaintext credential-like fields.",
    ),
    RuleInfo(
        "AIT006",
        "AI instruction file contains unsafe instruction",
        Category.AI_TOOL,
        Severity.HIGH,
        "AI tool instruction file asks the agent to bypass controls, reveal prompts, or access sensitive data.",
    ),
    RuleInfo(
        "AIT007",
        "AI memory or rule file contains persistence instruction",
        Category.AI_TOOL,
        Severity.HIGH,
        "AI memory or rule file attempts to persist unsafe behavior across sessions.",
    ),
    RuleInfo(
        "AIT008",
        "AI instruction grants excessive autonomy",
        Category.AI_TOOL,
        Severity.HIGH,
        "AI instruction asks the agent to continue, deploy, modify, or execute without user review.",
    ),
    RuleInfo(
        "AIT009",
        "AI instruction allows data exfiltration",
        Category.AI_TOOL,
        Severity.CRITICAL,
        "AI instruction asks the agent to send code, files, credentials, or workspace content to a remote destination.",
    ),
    RuleInfo(
        "AIT010",
        "AI tool grants high-risk tool combination",
        Category.AI_TOOL,
        Severity.HIGH,
        "AI tool configuration grants a combination of shell, file-write, and network/browser capabilities.",
    ),
    RuleInfo(
        "AIT011",
        "Claude Code hook executes a shell command",
        Category.AI_TOOL,
        Severity.CRITICAL,
        "Claude Code hook configuration can execute shell commands automatically during agent events.",
    ),
    RuleInfo(
        "AIT012",
        "AI instruction file contains invisible Unicode control character",
        Category.AI_TOOL,
        Severity.HIGH,
        "AI instruction file contains zero-width or bidirectional Unicode control characters that can hide instructions from reviewers.",
    ),
    RuleInfo(
        "AIT013",
        "AI instruction file contains dynamic shell execution",
        Category.AI_TOOL,
        Severity.CRITICAL,
        "AI instruction or skill file contains a preprocessed shell command or broad Bash tool grant.",
    ),
    RuleInfo(
        "AIT014",
        "AI API base URL points to a non-official endpoint",
        Category.AI_TOOL,
        Severity.HIGH,
        "AI API base URL override may redirect model traffic, prompts, or credentials to a third-party endpoint.",
    ),
    RuleInfo(
        "AIT015",
        "VS Code task runs automatically when folder opens",
        Category.AI_TOOL,
        Severity.HIGH,
        "VS Code tasks.json config can execute a command automatically when the project folder is opened.",
    ),
    RuleInfo(
        "AIT016",
        "AI skill reference is unpinned or from an untrusted source",
        Category.AI_TOOL,
        Severity.HIGH,
        "AI skill or command reference appears to use a mutable version or external registry/source.",
    ),
    RuleInfo(
        "AIT017",
        "Gemini CLI configuration contains unsafe automation setting",
        Category.AI_TOOL,
        Severity.HIGH,
        "Gemini CLI related configuration appears to enable broad automation or disable confirmation/sandbox controls.",
    ),
    RuleInfo("SEC001", "OpenAI API key detected", Category.SECRETS, Severity.CRITICAL, "OpenAI-style API key pattern."),
    RuleInfo("SEC002", "GitHub token detected", Category.SECRETS, Severity.CRITICAL, "GitHub token pattern."),
    RuleInfo("SEC003", "Anthropic API key detected", Category.SECRETS, Severity.CRITICAL, "Anthropic API key pattern."),
    RuleInfo("SEC004", "Bearer token detected", Category.SECRETS, Severity.HIGH, "Authorization bearer token pattern."),
    RuleInfo("SEC005", "Private key block detected", Category.SECRETS, Severity.CRITICAL, "Private key PEM block."),
    RuleInfo("SEC006", "AWS access key detected", Category.SECRETS, Severity.CRITICAL, "AWS access key ID pattern."),
    RuleInfo("SEC007", "Slack token detected", Category.SECRETS, Severity.CRITICAL, "Slack token pattern."),
    RuleInfo("SEC008", "Discord token or webhook detected", Category.SECRETS, Severity.CRITICAL, "Discord token or webhook pattern."),
    RuleInfo("SEC009", "Hugging Face token detected", Category.SECRETS, Severity.CRITICAL, "Hugging Face token pattern."),
    RuleInfo("SEC010", "npm access token detected", Category.SECRETS, Severity.CRITICAL, "npm access token pattern."),
    RuleInfo("SEC011", "PyPI API token detected", Category.SECRETS, Severity.CRITICAL, "PyPI API token pattern."),
    RuleInfo("SEC012", "Stripe API key detected", Category.SECRETS, Severity.CRITICAL, "Stripe secret or restricted key pattern."),
    RuleInfo("SEC013", "Google API key detected", Category.SECRETS, Severity.CRITICAL, "Google API key pattern."),
    RuleInfo("SEC014", "Azure Storage connection string detected", Category.SECRETS, Severity.CRITICAL, "Azure Storage AccountKey in a connection string."),
    RuleInfo("SEC015", "JWT detected", Category.SECRETS, Severity.HIGH, "JWT-like token pattern in credential context."),
    RuleInfo("SEC016", "Database URL with embedded password detected", Category.SECRETS, Severity.HIGH, "Database connection URL embeds a password."),
    RuleInfo("SEC017", "Generic high-entropy credential detected", Category.SECRETS, Severity.HIGH, "Credential-like assignment contains a high-entropy value."),
    RuleInfo("SEC018", "DeepSeek API key detected", Category.SECRETS, Severity.CRITICAL, "DeepSeek API key pattern or provider-specific assignment."),
    RuleInfo("SEC019", "Groq API key detected", Category.SECRETS, Severity.CRITICAL, "Groq API key pattern or provider-specific assignment."),
    RuleInfo("SEC020", "xAI / Grok API key detected", Category.SECRETS, Severity.CRITICAL, "xAI or Grok API key pattern or provider-specific assignment."),
    RuleInfo("SEC021", "Perplexity API key detected", Category.SECRETS, Severity.HIGH, "Perplexity API key pattern or provider-specific assignment."),
    RuleInfo("SEC022", "OpenRouter API key detected", Category.SECRETS, Severity.HIGH, "OpenRouter API key pattern or provider-specific assignment."),
    RuleInfo("SEC023", "Together AI API key detected", Category.SECRETS, Severity.HIGH, "Together AI API key provider-specific assignment."),
    RuleInfo("SEC024", "Fireworks AI API key detected", Category.SECRETS, Severity.HIGH, "Fireworks AI API key provider-specific assignment."),
    RuleInfo("SEC025", "Mistral AI API key detected", Category.SECRETS, Severity.HIGH, "Mistral AI API key provider-specific assignment."),
    RuleInfo("SEC026", "Cohere API key detected", Category.SECRETS, Severity.HIGH, "Cohere API key provider-specific assignment."),
    RuleInfo("SEC027", "Replicate API token detected", Category.SECRETS, Severity.HIGH, "Replicate API token pattern or provider-specific assignment."),
    RuleInfo("SEC028", "Azure OpenAI API key detected", Category.SECRETS, Severity.HIGH, "Azure OpenAI API key provider-specific assignment."),
    RuleInfo("SEC029", "NVIDIA NIM / NGC API key detected", Category.SECRETS, Severity.HIGH, "NVIDIA AI API key provider-specific assignment."),
    RuleInfo("SEC030", "Stability AI API key detected", Category.SECRETS, Severity.HIGH, "Stability AI API key pattern or provider-specific assignment."),
    RuleInfo("SEC031", "ElevenLabs API key detected", Category.SECRETS, Severity.HIGH, "ElevenLabs API key provider-specific assignment."),
    RuleInfo("SEC032", "Voyage AI API key detected", Category.SECRETS, Severity.HIGH, "Voyage AI API key provider-specific assignment."),
    RuleInfo("SEC033", "Tavily API key detected", Category.SECRETS, Severity.HIGH, "Tavily API key pattern or provider-specific assignment."),
    RuleInfo("SEC034", "Zhipu GLM / Z.ai API key detected", Category.SECRETS, Severity.CRITICAL, "Zhipu GLM or Z.ai API key provider-specific assignment."),
    RuleInfo("SEC035", "Kimi / Moonshot API key detected", Category.SECRETS, Severity.CRITICAL, "Kimi or Moonshot API key provider-specific assignment."),
    RuleInfo("SEC036", "Volcengine Ark / Doubao / Seedance API key detected", Category.SECRETS, Severity.CRITICAL, "Volcengine Ark, Doubao, Seedance, or Seedream API key provider-specific assignment."),
    RuleInfo("SEC037", "Alibaba Bailian / Qwen / DashScope API key detected", Category.SECRETS, Severity.CRITICAL, "Alibaba Bailian, Qwen, or DashScope API key provider-specific assignment."),
    RuleInfo("SEC038", "Baidu Qianfan / ERNIE API key detected", Category.SECRETS, Severity.HIGH, "Baidu Qianfan or ERNIE API key provider-specific assignment."),
    RuleInfo("SEC039", "Tencent Hunyuan secret detected", Category.SECRETS, Severity.HIGH, "Tencent Hunyuan or Tencent Cloud AI credential pattern."),
    RuleInfo("SEC040", "iFlytek Spark API key detected", Category.SECRETS, Severity.HIGH, "iFlytek Spark API key or secret provider-specific assignment."),
    RuleInfo("SEC041", "MiniMax / Hailuo / Minmo API key detected", Category.SECRETS, Severity.HIGH, "MiniMax, Hailuo, or Minmo API key provider-specific assignment."),
    RuleInfo("SEC042", "Baichuan AI API key detected", Category.SECRETS, Severity.HIGH, "Baichuan AI API key provider-specific assignment."),
    RuleInfo("SEC043", "01.AI / Yi API key detected", Category.SECRETS, Severity.HIGH, "01.AI or Yi API key provider-specific assignment."),
    RuleInfo("SEC044", "StepFun API key detected", Category.SECRETS, Severity.HIGH, "StepFun API key provider-specific assignment."),
    RuleInfo("SEC045", "SiliconFlow API key detected", Category.SECRETS, Severity.HIGH, "SiliconFlow API key pattern or provider-specific assignment."),
    RuleInfo("SEC046", "SenseNova API key detected", Category.SECRETS, Severity.HIGH, "SenseNova API key or access key provider-specific assignment."),
    RuleInfo("SEC047", "360 Zhinao API key detected", Category.SECRETS, Severity.HIGH, "360 Zhinao API key provider-specific assignment."),
    RuleInfo("SEC048", "ModelScope API token detected", Category.SECRETS, Severity.HIGH, "ModelScope API token provider-specific assignment."),
    RuleInfo("SEC049", "Infini-AI API key detected", Category.SECRETS, Severity.HIGH, "Infini-AI API key provider-specific assignment."),
    RuleInfo("SEC050", "Vidu / Shengshu API key detected", Category.SECRETS, Severity.HIGH, "Vidu or Shengshu API key provider-specific assignment."),
    RuleInfo("SEC051", "Kling AI secret detected", Category.SECRETS, Severity.HIGH, "Kling AI access key, secret key, or API key provider-specific assignment."),
    RuleInfo("SEC052", "OpenAI-compatible proxy key detected", Category.SECRETS, Severity.HIGH, "OpenAI-compatible API key combined with a non-OpenAI provider base URL or proxy context."),
    RuleInfo("SEC053", "AI service access key pair detected", Category.SECRETS, Severity.HIGH, "Paired access key and secret key for an AI or cloud AI service."),
    RuleInfo(
        "MCP001",
        "Overly broad filesystem access",
        Category.MCP,
        Severity.HIGH,
        "MCP filesystem server grants root, home, or drive-level paths.",
    ),
    RuleInfo(
        "MCP002",
        "Shell-capable MCP command",
        Category.MCP,
        Severity.HIGH,
        "MCP server command can execute arbitrary shell instructions.",
    ),
    RuleInfo(
        "MCP003",
        "Secret value embedded in MCP environment",
        Category.MCP,
        Severity.CRITICAL,
        "MCP environment variable contains a plaintext credential-like value.",
    ),
    RuleInfo(
        "MCP004",
        "Remote MCP server configured",
        Category.MCP,
        Severity.MEDIUM,
        "Remote MCP server can receive tool context and should be reviewed.",
    ),
    RuleInfo(
        "MCP005",
        "Dangerous MCP server arguments",
        Category.MCP,
        Severity.CRITICAL,
        "MCP server arguments disable or broaden safety controls.",
    ),
    RuleInfo(
        "MCP006",
        "MCP remote server uses plaintext HTTP",
        Category.MCP,
        Severity.HIGH,
        "MCP remote server transport is not encrypted.",
    ),
    RuleInfo(
        "MCP007",
        "MCP remote endpoint targets private or metadata address",
        Category.MCP,
        Severity.HIGH,
        "MCP remote endpoint points at localhost, private network, or cloud metadata services.",
    ),
    RuleInfo(
        "MCP008",
        "MCP tool scope is overly broad",
        Category.MCP,
        Severity.HIGH,
        "MCP configuration grants broad or administrative tool scope.",
    ),
    RuleInfo(
        "MCP009",
        "MCP forwards host credential environment variable",
        Category.MCP,
        Severity.MEDIUM,
        "MCP configuration passes host credential environment variables into a server.",
    ),
    RuleInfo(
        "MCP010",
        "MCP filesystem access includes sensitive local path",
        Category.MCP,
        Severity.HIGH,
        "MCP filesystem access includes paths that commonly store credentials or browser/session data.",
    ),
    RuleInfo(
        "MCP011",
        "Writable MCP filesystem access is too broad",
        Category.MCP,
        Severity.CRITICAL,
        "MCP filesystem access grants write-capable permissions to a broad path.",
    ),
    RuleInfo(
        "MCP012",
        "MCP tool or resource description contains unsafe instruction",
        Category.MCP,
        Severity.HIGH,
        "MCP tool/resource text attempts to override instructions, hide behavior, or access sensitive data.",
    ),
    RuleInfo(
        "MCP013",
        "MCP tool output is treated as executable instruction",
        Category.MCP,
        Severity.HIGH,
        "MCP configuration encourages following or executing instructions returned by a tool/resource.",
    ),
    RuleInfo(
        "MCP014",
        "MCP resource may inject remote prompt content",
        Category.MCP,
        Severity.MEDIUM,
        "MCP resource text suggests loading prompt instructions from an external or remote source.",
    ),
    RuleInfo(
        "MCP015",
        "Remote MCP server has no obvious authentication configuration",
        Category.MCP,
        Severity.HIGH,
        "Remote MCP server configuration does not include an obvious OAuth, Authorization, token, API key, or auth header setting.",
    ),
    RuleInfo(
        "MCP016",
        "MCP stdio server lacks an obvious container or sandbox boundary",
        Category.MCP,
        Severity.MEDIUM,
        "MCP stdio server runs a local command without an obvious container, sandbox, or isolation hint in configuration.",
    ),
    RuleInfo(
        "MCP017",
        "MCP tool name is declared by multiple servers",
        Category.MCP,
        Severity.MEDIUM,
        "Multiple MCP servers declare the same tool name, which can confuse routing or enable tool-name impersonation.",
    ),
    RuleInfo(
        "MCP018",
        "MCP OAuth redirect URI uses wildcard or unsafe value",
        Category.MCP,
        Severity.HIGH,
        "MCP OAuth redirect URI configuration uses a wildcard, broad host, or unsafe redirect value.",
    ),
    RuleInfo("SH001", "Recursive force delete command", Category.SHELL, Severity.CRITICAL, "Broad destructive delete command."),
    RuleInfo("SH002", "Downloaded script piped to shell", Category.SHELL, Severity.CRITICAL, "Downloaded script executed directly by a shell."),
    RuleInfo("SH003", "Disabled execution safety controls", Category.SHELL, Severity.HIGH, "Sandbox bypass or world-writable permission pattern."),
    RuleInfo("SH004", "Potential secret exfiltration command", Category.SHELL, Severity.HIGH, "Shell command may send local secrets to a remote endpoint."),
    RuleInfo("SH005", "Encoded command execution", Category.SHELL, Severity.HIGH, "Opaque encoded command execution pattern."),
    RuleInfo("SH006", "PowerShell expression execution", Category.SHELL, Severity.HIGH, "Dynamic PowerShell expression execution pattern."),
    RuleInfo("SH007", "Reverse shell pattern", Category.SHELL, Severity.CRITICAL, "Reverse shell command pattern."),
    RuleInfo("SH008", "Destructive disk or filesystem command", Category.SHELL, Severity.CRITICAL, "Disk formatting or raw device overwrite pattern."),
    RuleInfo("SH009", "Inline dynamic code execution", Category.SHELL, Severity.MEDIUM, "Inline interpreter execution pattern."),
    RuleInfo("SH010", "Package manager immediate execution command", Category.SHELL, Severity.MEDIUM, "npx, npm create, pnpm dlx, or similar package manager immediate execution pattern."),
    RuleInfo(
        "SC001",
        "Package lifecycle script executes during install",
        Category.SUPPLY_CHAIN,
        Severity.HIGH,
        "package.json contains a lifecycle script that runs automatically during install or publish.",
    ),
    RuleInfo(
        "SC002",
        "Package script contains risky install or execution command",
        Category.SUPPLY_CHAIN,
        Severity.HIGH,
        "package.json script downloads or executes code dynamically.",
    ),
    RuleInfo(
        "SC003",
        "Package dependency uses remote Git or URL source",
        Category.SUPPLY_CHAIN,
        Severity.MEDIUM,
        "Package dependency is installed from a remote URL or Git source.",
    ),
    RuleInfo(
        "SC004",
        "Package dependency version is unpinned",
        Category.SUPPLY_CHAIN,
        Severity.MEDIUM,
        "Package dependency uses a wildcard or latest version.",
    ),
    RuleInfo(
        "SC005",
        "Package manager credential stored in config file",
        Category.SUPPLY_CHAIN,
        Severity.CRITICAL,
        "Package manager configuration contains a plaintext credential value.",
    ),
    RuleInfo(
        "SC006",
        "Docker base image uses latest tag",
        Category.SUPPLY_CHAIN,
        Severity.MEDIUM,
        "Dockerfile uses a mutable latest tag for the base image.",
    ),
    RuleInfo(
        "SC007",
        "Dockerfile ADD downloads remote content",
        Category.SUPPLY_CHAIN,
        Severity.MEDIUM,
        "Dockerfile ADD pulls remote content during build.",
    ),
    RuleInfo(
        "SC008",
        "Docker build executes downloaded script",
        Category.SUPPLY_CHAIN,
        Severity.HIGH,
        "Dockerfile downloads and executes a script during image build.",
    ),
    RuleInfo(
        "SC009",
        "Container service uses privileged or host-level settings",
        Category.SUPPLY_CHAIN,
        Severity.HIGH,
        "Compose service uses privileged mode or host-level namespace/network settings.",
    ),
    RuleInfo(
        "SC010",
        "Container mounts sensitive host path",
        Category.SUPPLY_CHAIN,
        Severity.HIGH,
        "Compose service mounts a sensitive host path into a container.",
    ),
    RuleInfo(
        "SC011",
        "Devcontainer lifecycle command executes risky shell content",
        Category.SUPPLY_CHAIN,
        Severity.HIGH,
        "devcontainer lifecycle command downloads or executes dynamic code.",
    ),
    RuleInfo(
        "SC012",
        "Devcontainer mounts sensitive host path",
        Category.SUPPLY_CHAIN,
        Severity.HIGH,
        "devcontainer configuration mounts a sensitive host path.",
    ),
    RuleInfo(
        "SC013",
        "Python requirement uses remote URL or VCS source",
        Category.SUPPLY_CHAIN,
        Severity.MEDIUM,
        "requirements file installs a dependency from a remote URL or VCS source.",
    ),
    RuleInfo(
        "SC014",
        "Python requirement is not version pinned",
        Category.SUPPLY_CHAIN,
        Severity.LOW,
        "requirements file contains an unpinned package requirement.",
    ),
    RuleInfo(
        "SC015",
        "binding.gyp contains command substitution",
        Category.SUPPLY_CHAIN,
        Severity.CRITICAL,
        "binding.gyp can execute command substitutions during native package build or install.",
    ),
    RuleInfo(
        "SC016",
        "setup.py contains suspicious install-time command execution",
        Category.SUPPLY_CHAIN,
        Severity.HIGH,
        "setup.py appears to execute shell commands, subprocesses, downloaded code, or decoded payloads during package installation.",
    ),
    RuleInfo(
        "GHA001",
        "pull_request_target workflow checks out code",
        Category.GITHUB_ACTIONS,
        Severity.HIGH,
        "Workflow combines elevated pull_request_target context with repository checkout.",
    ),
    RuleInfo(
        "GHA002",
        "Unpinned GitHub Action reference",
        Category.GITHUB_ACTIONS,
        Severity.MEDIUM,
        "Third-party action is referenced by a mutable branch or tag.",
    ),
    RuleInfo(
        "GHA003",
        "Secret echoed in GitHub Actions shell",
        Category.GITHUB_ACTIONS,
        Severity.CRITICAL,
        "Workflow shell step echoes a GitHub secret expression.",
    ),
    RuleInfo(
        "GHA004",
        "Dangerous script download in GitHub Actions",
        Category.GITHUB_ACTIONS,
        Severity.CRITICAL,
        "Workflow downloads a script and executes it directly.",
    ),
    RuleInfo(
        "GHA005",
        "Overly broad GitHub Actions permissions",
        Category.GITHUB_ACTIONS,
        Severity.HIGH,
        "Workflow grants write-all or broad write permissions.",
    ),
    RuleInfo(
        "GHA006",
        "Self-hosted GitHub Actions runner",
        Category.GITHUB_ACTIONS,
        Severity.MEDIUM,
        "Workflow runs on a self-hosted runner.",
    ),
    RuleInfo(
        "GHA007",
        "Untrusted GitHub context used directly in shell",
        Category.GITHUB_ACTIONS,
        Severity.HIGH,
        "Workflow shell step interpolates untrusted event data directly into a run command.",
    ),
    RuleInfo(
        "GHA008",
        "OIDC token permission granted",
        Category.GITHUB_ACTIONS,
        Severity.MEDIUM,
        "Workflow job can mint GitHub OIDC tokens.",
    ),
    RuleInfo(
        "GHA009",
        "Cache or artifact action used in untrusted workflow context",
        Category.GITHUB_ACTIONS,
        Severity.MEDIUM,
        "Workflow uses cache or artifact transfer on an event that may be influenced by untrusted contributors.",
    ),
    RuleInfo(
        "GHA010",
        "Downloaded artifact or cache content is executed",
        Category.GITHUB_ACTIONS,
        Severity.HIGH,
        "Workflow appears to execute content from an artifact or cache path.",
    ),
    RuleInfo(
        "GHA011",
        "workflow_run workflow may process untrusted artifacts with elevated permissions",
        Category.GITHUB_ACTIONS,
        Severity.HIGH,
        "workflow_run can run with privileged context and may consume attacker-controlled artifacts.",
    ),
    RuleInfo(
        "GHA012",
        "OIDC cloud trust policy constraints require verification",
        Category.GITHUB_ACTIONS,
        Severity.MEDIUM,
        "Workflow grants id-token: write for cloud authentication, but repository-side YAML cannot prove strict cloud subject and audience constraints.",
    ),
    RuleInfo(
        "FS001",
        "Sensitive local file is included in the scanned project",
        Category.FILESYSTEM,
        Severity.HIGH,
        "Project contains a file path commonly used for local credentials or security-sensitive configuration.",
    ),
    RuleInfo(
        "FS002",
        "Sensitive host directory path is present",
        Category.FILESYSTEM,
        Severity.HIGH,
        "Project contains a path under a sensitive host credential or configuration directory.",
    ),
    RuleInfo(
        "FS003",
        "Broad filesystem permission command detected",
        Category.FILESYSTEM,
        Severity.MEDIUM,
        "A command grants broad read/write/execute permissions to users or groups.",
    ),
)


def list_rules(category: str | None = None) -> tuple[RuleInfo, ...]:
    if not category:
        return RULE_CATALOG
    normalized = category.lower()
    return tuple(rule for rule in RULE_CATALOG if rule.category.value == normalized)


def rule_by_id(rule_id: str) -> RuleInfo | None:
    return _RULES_BY_ID.get(rule_id)


def rule_help_uri(rule_id: str) -> str:
    return f"https://github.com/LeeBush22/agent-security-scanner/blob/main/docs/RULES.md#{rule_anchor(rule_id)}"


def rule_anchor(rule_id: str) -> str:
    info = rule_by_id(rule_id)
    if not info:
        return rule_id.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", info.title.lower()).strip("-")
    return f"{rule_id.lower()}-{slug}"


def rule_prefix(rule_id: str) -> str:
    match = RULE_ID_RE.match(rule_id)
    return match.group(1) if match else rule_id[:3]


_RULES_BY_ID = {rule.rule_id: rule for rule in RULE_CATALOG}

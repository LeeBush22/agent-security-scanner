# Agent Security Scanner Rules

This document is generated from the built-in rule catalog. It is intended for release review, SARIF metadata, and users who want to understand what the scanner checks.

Total built-in rules: **126**

## Categories

| Category | Rules |
|---|---:|
| `ai-tool` | 17 |
| `github-actions` | 12 |
| `mcp` | 18 |
| `secrets` | 53 |
| `shell` | 10 |
| `supply-chain` | 16 |

## Rule Index

### ai-tool

| Rule | Severity | Title | Description |
|---|---|---|---|
| [AIT001](#ait001-ai-tool-auto-approval-is-enabled-or-too-broad) | `high` | AI tool auto-approval is enabled or too broad | AI coding tool configuration auto-approves commands, edits, or tool calls. |
| [AIT002](#ait002-ai-tool-permission-checks-are-bypassed) | `critical` | AI tool permission checks are bypassed | AI coding tool configuration disables sandbox or permission checks. |
| [AIT003](#ait003-ai-tool-workspace-access-is-too-broad) | `high` | AI tool workspace access is too broad | AI coding tool configuration grants root, home, or drive-level filesystem access. |
| [AIT004](#ait004-ai-tool-can-invoke-a-shell-capable-command) | `high` | AI tool can invoke a shell-capable command | AI coding tool configuration includes shell-capable command execution. |
| [AIT005](#ait005-secret-embedded-in-ai-coding-tool-config) | `critical` | Secret embedded in AI coding tool config | AI coding tool configuration contains plaintext credential-like fields. |
| [AIT006](#ait006-ai-instruction-file-contains-unsafe-instruction) | `high` | AI instruction file contains unsafe instruction | AI tool instruction file asks the agent to bypass controls, reveal prompts, or access sensitive data. |
| [AIT007](#ait007-ai-memory-or-rule-file-contains-persistence-instruction) | `high` | AI memory or rule file contains persistence instruction | AI memory or rule file attempts to persist unsafe behavior across sessions. |
| [AIT008](#ait008-ai-instruction-grants-excessive-autonomy) | `high` | AI instruction grants excessive autonomy | AI instruction asks the agent to continue, deploy, modify, or execute without user review. |
| [AIT009](#ait009-ai-instruction-allows-data-exfiltration) | `critical` | AI instruction allows data exfiltration | AI instruction asks the agent to send code, files, credentials, or workspace content to a remote destination. |
| [AIT010](#ait010-ai-tool-grants-high-risk-tool-combination) | `high` | AI tool grants high-risk tool combination | AI tool configuration grants a combination of shell, file-write, and network/browser capabilities. |
| [AIT011](#ait011-claude-code-hook-executes-a-shell-command) | `critical` | Claude Code hook executes a shell command | Claude Code hook configuration can execute shell commands automatically during agent events. |
| [AIT012](#ait012-ai-instruction-file-contains-invisible-unicode-control-character) | `high` | AI instruction file contains invisible Unicode control character | AI instruction file contains zero-width or bidirectional Unicode control characters that can hide instructions from reviewers. |
| [AIT013](#ait013-ai-instruction-file-contains-dynamic-shell-execution) | `critical` | AI instruction file contains dynamic shell execution | AI instruction or skill file contains a preprocessed shell command or broad Bash tool grant. |
| [AIT014](#ait014-ai-api-base-url-points-to-a-non-official-endpoint) | `high` | AI API base URL points to a non-official endpoint | AI API base URL override may redirect model traffic, prompts, or credentials to a third-party endpoint. |
| [AIT015](#ait015-vs-code-task-runs-automatically-when-folder-opens) | `high` | VS Code task runs automatically when folder opens | VS Code tasks.json config can execute a command automatically when the project folder is opened. |
| [AIT016](#ait016-ai-skill-reference-is-unpinned-or-from-an-untrusted-source) | `high` | AI skill reference is unpinned or from an untrusted source | AI skill or command reference appears to use a mutable version or external registry/source. |
| [AIT017](#ait017-gemini-cli-configuration-contains-unsafe-automation-setting) | `high` | Gemini CLI configuration contains unsafe automation setting | Gemini CLI related configuration appears to enable broad automation or disable confirmation/sandbox controls. |

### github-actions

| Rule | Severity | Title | Description |
|---|---|---|---|
| [GHA001](#gha001-pull-request-target-workflow-checks-out-code) | `high` | pull_request_target workflow checks out code | Workflow combines elevated pull_request_target context with repository checkout. |
| [GHA002](#gha002-unpinned-github-action-reference) | `medium` | Unpinned GitHub Action reference | Third-party action is referenced by a mutable branch or tag. |
| [GHA003](#gha003-secret-echoed-in-github-actions-shell) | `critical` | Secret echoed in GitHub Actions shell | Workflow shell step echoes a GitHub secret expression. |
| [GHA004](#gha004-dangerous-script-download-in-github-actions) | `critical` | Dangerous script download in GitHub Actions | Workflow downloads a script and executes it directly. |
| [GHA005](#gha005-overly-broad-github-actions-permissions) | `high` | Overly broad GitHub Actions permissions | Workflow grants write-all or broad write permissions. |
| [GHA006](#gha006-self-hosted-github-actions-runner) | `medium` | Self-hosted GitHub Actions runner | Workflow runs on a self-hosted runner. |
| [GHA007](#gha007-untrusted-github-context-used-directly-in-shell) | `high` | Untrusted GitHub context used directly in shell | Workflow shell step interpolates untrusted event data directly into a run command. |
| [GHA008](#gha008-oidc-token-permission-granted) | `medium` | OIDC token permission granted | Workflow job can mint GitHub OIDC tokens. |
| [GHA009](#gha009-cache-or-artifact-action-used-in-untrusted-workflow-context) | `medium` | Cache or artifact action used in untrusted workflow context | Workflow uses cache or artifact transfer on an event that may be influenced by untrusted contributors. |
| [GHA010](#gha010-downloaded-artifact-or-cache-content-is-executed) | `high` | Downloaded artifact or cache content is executed | Workflow appears to execute content from an artifact or cache path. |
| [GHA011](#gha011-workflow-run-workflow-may-process-untrusted-artifacts-with-elevated-permissions) | `high` | workflow_run workflow may process untrusted artifacts with elevated permissions | workflow_run can run with privileged context and may consume attacker-controlled artifacts. |
| [GHA012](#gha012-oidc-cloud-trust-policy-constraints-require-verification) | `medium` | OIDC cloud trust policy constraints require verification | Workflow grants id-token: write for cloud authentication, but repository-side YAML cannot prove strict cloud subject and audience constraints. |

### mcp

| Rule | Severity | Title | Description |
|---|---|---|---|
| [MCP001](#mcp001-overly-broad-filesystem-access) | `high` | Overly broad filesystem access | MCP filesystem server grants root, home, or drive-level paths. |
| [MCP002](#mcp002-shell-capable-mcp-command) | `high` | Shell-capable MCP command | MCP server command can execute arbitrary shell instructions. |
| [MCP003](#mcp003-secret-value-embedded-in-mcp-environment) | `critical` | Secret value embedded in MCP environment | MCP environment variable contains a plaintext credential-like value. |
| [MCP004](#mcp004-remote-mcp-server-configured) | `medium` | Remote MCP server configured | Remote MCP server can receive tool context and should be reviewed. |
| [MCP005](#mcp005-dangerous-mcp-server-arguments) | `critical` | Dangerous MCP server arguments | MCP server arguments disable or broaden safety controls. |
| [MCP006](#mcp006-mcp-remote-server-uses-plaintext-http) | `high` | MCP remote server uses plaintext HTTP | MCP remote server transport is not encrypted. |
| [MCP007](#mcp007-mcp-remote-endpoint-targets-private-or-metadata-address) | `high` | MCP remote endpoint targets private or metadata address | MCP remote endpoint points at localhost, private network, or cloud metadata services. |
| [MCP008](#mcp008-mcp-tool-scope-is-overly-broad) | `high` | MCP tool scope is overly broad | MCP configuration grants broad or administrative tool scope. |
| [MCP009](#mcp009-mcp-forwards-host-credential-environment-variable) | `medium` | MCP forwards host credential environment variable | MCP configuration passes host credential environment variables into a server. |
| [MCP010](#mcp010-mcp-filesystem-access-includes-sensitive-local-path) | `high` | MCP filesystem access includes sensitive local path | MCP filesystem access includes paths that commonly store credentials or browser/session data. |
| [MCP011](#mcp011-writable-mcp-filesystem-access-is-too-broad) | `critical` | Writable MCP filesystem access is too broad | MCP filesystem access grants write-capable permissions to a broad path. |
| [MCP012](#mcp012-mcp-tool-or-resource-description-contains-unsafe-instruction) | `high` | MCP tool or resource description contains unsafe instruction | MCP tool/resource text attempts to override instructions, hide behavior, or access sensitive data. |
| [MCP013](#mcp013-mcp-tool-output-is-treated-as-executable-instruction) | `high` | MCP tool output is treated as executable instruction | MCP configuration encourages following or executing instructions returned by a tool/resource. |
| [MCP014](#mcp014-mcp-resource-may-inject-remote-prompt-content) | `medium` | MCP resource may inject remote prompt content | MCP resource text suggests loading prompt instructions from an external or remote source. |
| [MCP015](#mcp015-remote-mcp-server-has-no-obvious-authentication-configuration) | `high` | Remote MCP server has no obvious authentication configuration | Remote MCP server configuration does not include an obvious OAuth, Authorization, token, API key, or auth header setting. |
| [MCP016](#mcp016-mcp-stdio-server-lacks-an-obvious-container-or-sandbox-boundary) | `medium` | MCP stdio server lacks an obvious container or sandbox boundary | MCP stdio server runs a local command without an obvious container, sandbox, or isolation hint in configuration. |
| [MCP017](#mcp017-mcp-tool-name-is-declared-by-multiple-servers) | `medium` | MCP tool name is declared by multiple servers | Multiple MCP servers declare the same tool name, which can confuse routing or enable tool-name impersonation. |
| [MCP018](#mcp018-mcp-oauth-redirect-uri-uses-wildcard-or-unsafe-value) | `high` | MCP OAuth redirect URI uses wildcard or unsafe value | MCP OAuth redirect URI configuration uses a wildcard, broad host, or unsafe redirect value. |

### secrets

| Rule | Severity | Title | Description |
|---|---|---|---|
| [SEC001](#sec001-openai-api-key-detected) | `critical` | OpenAI API key detected | OpenAI-style API key pattern. |
| [SEC002](#sec002-github-token-detected) | `critical` | GitHub token detected | GitHub token pattern. |
| [SEC003](#sec003-anthropic-api-key-detected) | `critical` | Anthropic API key detected | Anthropic API key pattern. |
| [SEC004](#sec004-bearer-token-detected) | `high` | Bearer token detected | Authorization bearer token pattern. |
| [SEC005](#sec005-private-key-block-detected) | `critical` | Private key block detected | Private key PEM block. |
| [SEC006](#sec006-aws-access-key-detected) | `critical` | AWS access key detected | AWS access key ID pattern. |
| [SEC007](#sec007-slack-token-detected) | `critical` | Slack token detected | Slack token pattern. |
| [SEC008](#sec008-discord-token-or-webhook-detected) | `critical` | Discord token or webhook detected | Discord token or webhook pattern. |
| [SEC009](#sec009-hugging-face-token-detected) | `critical` | Hugging Face token detected | Hugging Face token pattern. |
| [SEC010](#sec010-npm-access-token-detected) | `critical` | npm access token detected | npm access token pattern. |
| [SEC011](#sec011-pypi-api-token-detected) | `critical` | PyPI API token detected | PyPI API token pattern. |
| [SEC012](#sec012-stripe-api-key-detected) | `critical` | Stripe API key detected | Stripe secret or restricted key pattern. |
| [SEC013](#sec013-google-api-key-detected) | `critical` | Google API key detected | Google API key pattern. |
| [SEC014](#sec014-azure-storage-connection-string-detected) | `critical` | Azure Storage connection string detected | Azure Storage AccountKey in a connection string. |
| [SEC015](#sec015-jwt-detected) | `high` | JWT detected | JWT-like token pattern in credential context. |
| [SEC016](#sec016-database-url-with-embedded-password-detected) | `high` | Database URL with embedded password detected | Database connection URL embeds a password. |
| [SEC017](#sec017-generic-high-entropy-credential-detected) | `high` | Generic high-entropy credential detected | Credential-like assignment contains a high-entropy value. |
| [SEC018](#sec018-deepseek-api-key-detected) | `critical` | DeepSeek API key detected | DeepSeek API key pattern or provider-specific assignment. |
| [SEC019](#sec019-groq-api-key-detected) | `critical` | Groq API key detected | Groq API key pattern or provider-specific assignment. |
| [SEC020](#sec020-xai-grok-api-key-detected) | `critical` | xAI / Grok API key detected | xAI or Grok API key pattern or provider-specific assignment. |
| [SEC021](#sec021-perplexity-api-key-detected) | `high` | Perplexity API key detected | Perplexity API key pattern or provider-specific assignment. |
| [SEC022](#sec022-openrouter-api-key-detected) | `high` | OpenRouter API key detected | OpenRouter API key pattern or provider-specific assignment. |
| [SEC023](#sec023-together-ai-api-key-detected) | `high` | Together AI API key detected | Together AI API key provider-specific assignment. |
| [SEC024](#sec024-fireworks-ai-api-key-detected) | `high` | Fireworks AI API key detected | Fireworks AI API key provider-specific assignment. |
| [SEC025](#sec025-mistral-ai-api-key-detected) | `high` | Mistral AI API key detected | Mistral AI API key provider-specific assignment. |
| [SEC026](#sec026-cohere-api-key-detected) | `high` | Cohere API key detected | Cohere API key provider-specific assignment. |
| [SEC027](#sec027-replicate-api-token-detected) | `high` | Replicate API token detected | Replicate API token pattern or provider-specific assignment. |
| [SEC028](#sec028-azure-openai-api-key-detected) | `high` | Azure OpenAI API key detected | Azure OpenAI API key provider-specific assignment. |
| [SEC029](#sec029-nvidia-nim-ngc-api-key-detected) | `high` | NVIDIA NIM / NGC API key detected | NVIDIA AI API key provider-specific assignment. |
| [SEC030](#sec030-stability-ai-api-key-detected) | `high` | Stability AI API key detected | Stability AI API key pattern or provider-specific assignment. |
| [SEC031](#sec031-elevenlabs-api-key-detected) | `high` | ElevenLabs API key detected | ElevenLabs API key provider-specific assignment. |
| [SEC032](#sec032-voyage-ai-api-key-detected) | `high` | Voyage AI API key detected | Voyage AI API key provider-specific assignment. |
| [SEC033](#sec033-tavily-api-key-detected) | `high` | Tavily API key detected | Tavily API key pattern or provider-specific assignment. |
| [SEC034](#sec034-zhipu-glm-z-ai-api-key-detected) | `critical` | Zhipu GLM / Z.ai API key detected | Zhipu GLM or Z.ai API key provider-specific assignment. |
| [SEC035](#sec035-kimi-moonshot-api-key-detected) | `critical` | Kimi / Moonshot API key detected | Kimi or Moonshot API key provider-specific assignment. |
| [SEC036](#sec036-volcengine-ark-doubao-seedance-api-key-detected) | `critical` | Volcengine Ark / Doubao / Seedance API key detected | Volcengine Ark, Doubao, Seedance, or Seedream API key provider-specific assignment. |
| [SEC037](#sec037-alibaba-bailian-qwen-dashscope-api-key-detected) | `critical` | Alibaba Bailian / Qwen / DashScope API key detected | Alibaba Bailian, Qwen, or DashScope API key provider-specific assignment. |
| [SEC038](#sec038-baidu-qianfan-ernie-api-key-detected) | `high` | Baidu Qianfan / ERNIE API key detected | Baidu Qianfan or ERNIE API key provider-specific assignment. |
| [SEC039](#sec039-tencent-hunyuan-secret-detected) | `high` | Tencent Hunyuan secret detected | Tencent Hunyuan or Tencent Cloud AI credential pattern. |
| [SEC040](#sec040-iflytek-spark-api-key-detected) | `high` | iFlytek Spark API key detected | iFlytek Spark API key or secret provider-specific assignment. |
| [SEC041](#sec041-minimax-hailuo-minmo-api-key-detected) | `high` | MiniMax / Hailuo / Minmo API key detected | MiniMax, Hailuo, or Minmo API key provider-specific assignment. |
| [SEC042](#sec042-baichuan-ai-api-key-detected) | `high` | Baichuan AI API key detected | Baichuan AI API key provider-specific assignment. |
| [SEC043](#sec043-01-ai-yi-api-key-detected) | `high` | 01.AI / Yi API key detected | 01.AI or Yi API key provider-specific assignment. |
| [SEC044](#sec044-stepfun-api-key-detected) | `high` | StepFun API key detected | StepFun API key provider-specific assignment. |
| [SEC045](#sec045-siliconflow-api-key-detected) | `high` | SiliconFlow API key detected | SiliconFlow API key pattern or provider-specific assignment. |
| [SEC046](#sec046-sensenova-api-key-detected) | `high` | SenseNova API key detected | SenseNova API key or access key provider-specific assignment. |
| [SEC047](#sec047-360-zhinao-api-key-detected) | `high` | 360 Zhinao API key detected | 360 Zhinao API key provider-specific assignment. |
| [SEC048](#sec048-modelscope-api-token-detected) | `high` | ModelScope API token detected | ModelScope API token provider-specific assignment. |
| [SEC049](#sec049-infini-ai-api-key-detected) | `high` | Infini-AI API key detected | Infini-AI API key provider-specific assignment. |
| [SEC050](#sec050-vidu-shengshu-api-key-detected) | `high` | Vidu / Shengshu API key detected | Vidu or Shengshu API key provider-specific assignment. |
| [SEC051](#sec051-kling-ai-secret-detected) | `high` | Kling AI secret detected | Kling AI access key, secret key, or API key provider-specific assignment. |
| [SEC052](#sec052-openai-compatible-proxy-key-detected) | `high` | OpenAI-compatible proxy key detected | OpenAI-compatible API key combined with a non-OpenAI provider base URL or proxy context. |
| [SEC053](#sec053-ai-service-access-key-pair-detected) | `high` | AI service access key pair detected | Paired access key and secret key for an AI or cloud AI service. |

### shell

| Rule | Severity | Title | Description |
|---|---|---|---|
| [SH001](#sh001-recursive-force-delete-command) | `critical` | Recursive force delete command | Broad destructive delete command. |
| [SH002](#sh002-downloaded-script-piped-to-shell) | `critical` | Downloaded script piped to shell | Downloaded script executed directly by a shell. |
| [SH003](#sh003-disabled-execution-safety-controls) | `high` | Disabled execution safety controls | Sandbox bypass or world-writable permission pattern. |
| [SH004](#sh004-potential-secret-exfiltration-command) | `high` | Potential secret exfiltration command | Shell command may send local secrets to a remote endpoint. |
| [SH005](#sh005-encoded-command-execution) | `high` | Encoded command execution | Opaque encoded command execution pattern. |
| [SH006](#sh006-powershell-expression-execution) | `high` | PowerShell expression execution | Dynamic PowerShell expression execution pattern. |
| [SH007](#sh007-reverse-shell-pattern) | `critical` | Reverse shell pattern | Reverse shell command pattern. |
| [SH008](#sh008-destructive-disk-or-filesystem-command) | `critical` | Destructive disk or filesystem command | Disk formatting or raw device overwrite pattern. |
| [SH009](#sh009-inline-dynamic-code-execution) | `medium` | Inline dynamic code execution | Inline interpreter execution pattern. |
| [SH010](#sh010-package-manager-immediate-execution-command) | `medium` | Package manager immediate execution command | npx, npm create, pnpm dlx, or similar package manager immediate execution pattern. |

### supply-chain

| Rule | Severity | Title | Description |
|---|---|---|---|
| [SC001](#sc001-package-lifecycle-script-executes-during-install) | `high` | Package lifecycle script executes during install | package.json contains a lifecycle script that runs automatically during install or publish. |
| [SC002](#sc002-package-script-contains-risky-install-or-execution-command) | `high` | Package script contains risky install or execution command | package.json script downloads or executes code dynamically. |
| [SC003](#sc003-package-dependency-uses-remote-git-or-url-source) | `medium` | Package dependency uses remote Git or URL source | Package dependency is installed from a remote URL or Git source. |
| [SC004](#sc004-package-dependency-version-is-unpinned) | `medium` | Package dependency version is unpinned | Package dependency uses a wildcard or latest version. |
| [SC005](#sc005-package-manager-credential-stored-in-config-file) | `critical` | Package manager credential stored in config file | Package manager configuration contains a plaintext credential value. |
| [SC006](#sc006-docker-base-image-uses-latest-tag) | `medium` | Docker base image uses latest tag | Dockerfile uses a mutable latest tag for the base image. |
| [SC007](#sc007-dockerfile-add-downloads-remote-content) | `medium` | Dockerfile ADD downloads remote content | Dockerfile ADD pulls remote content during build. |
| [SC008](#sc008-docker-build-executes-downloaded-script) | `high` | Docker build executes downloaded script | Dockerfile downloads and executes a script during image build. |
| [SC009](#sc009-container-service-uses-privileged-or-host-level-settings) | `high` | Container service uses privileged or host-level settings | Compose service uses privileged mode or host-level namespace/network settings. |
| [SC010](#sc010-container-mounts-sensitive-host-path) | `high` | Container mounts sensitive host path | Compose service mounts a sensitive host path into a container. |
| [SC011](#sc011-devcontainer-lifecycle-command-executes-risky-shell-content) | `high` | Devcontainer lifecycle command executes risky shell content | devcontainer lifecycle command downloads or executes dynamic code. |
| [SC012](#sc012-devcontainer-mounts-sensitive-host-path) | `high` | Devcontainer mounts sensitive host path | devcontainer configuration mounts a sensitive host path. |
| [SC013](#sc013-python-requirement-uses-remote-url-or-vcs-source) | `medium` | Python requirement uses remote URL or VCS source | requirements file installs a dependency from a remote URL or VCS source. |
| [SC014](#sc014-python-requirement-is-not-version-pinned) | `low` | Python requirement is not version pinned | requirements file contains an unpinned package requirement. |
| [SC015](#sc015-binding-gyp-contains-command-substitution) | `critical` | binding.gyp contains command substitution | binding.gyp can execute command substitutions during native package build or install. |
| [SC016](#sc016-setup-py-contains-suspicious-install-time-command-execution) | `high` | setup.py contains suspicious install-time command execution | setup.py appears to execute shell commands, subprocesses, downloaded code, or decoded payloads during package installation. |

## Rule Details

### AIT001 AI tool auto-approval is enabled or too broad

- Category: `ai-tool`
- Severity: `high`
- Description: AI coding tool configuration auto-approves commands, edits, or tool calls.

### AIT002 AI tool permission checks are bypassed

- Category: `ai-tool`
- Severity: `critical`
- Description: AI coding tool configuration disables sandbox or permission checks.

### AIT003 AI tool workspace access is too broad

- Category: `ai-tool`
- Severity: `high`
- Description: AI coding tool configuration grants root, home, or drive-level filesystem access.

### AIT004 AI tool can invoke a shell-capable command

- Category: `ai-tool`
- Severity: `high`
- Description: AI coding tool configuration includes shell-capable command execution.

### AIT005 Secret embedded in AI coding tool config

- Category: `ai-tool`
- Severity: `critical`
- Description: AI coding tool configuration contains plaintext credential-like fields.

### AIT006 AI instruction file contains unsafe instruction

- Category: `ai-tool`
- Severity: `high`
- Description: AI tool instruction file asks the agent to bypass controls, reveal prompts, or access sensitive data.

### AIT007 AI memory or rule file contains persistence instruction

- Category: `ai-tool`
- Severity: `high`
- Description: AI memory or rule file attempts to persist unsafe behavior across sessions.

### AIT008 AI instruction grants excessive autonomy

- Category: `ai-tool`
- Severity: `high`
- Description: AI instruction asks the agent to continue, deploy, modify, or execute without user review.

### AIT009 AI instruction allows data exfiltration

- Category: `ai-tool`
- Severity: `critical`
- Description: AI instruction asks the agent to send code, files, credentials, or workspace content to a remote destination.

### AIT010 AI tool grants high-risk tool combination

- Category: `ai-tool`
- Severity: `high`
- Description: AI tool configuration grants a combination of shell, file-write, and network/browser capabilities.

### AIT011 Claude Code hook executes a shell command

- Category: `ai-tool`
- Severity: `critical`
- Description: Claude Code hook configuration can execute shell commands automatically during agent events.

### AIT012 AI instruction file contains invisible Unicode control character

- Category: `ai-tool`
- Severity: `high`
- Description: AI instruction file contains zero-width or bidirectional Unicode control characters that can hide instructions from reviewers.

### AIT013 AI instruction file contains dynamic shell execution

- Category: `ai-tool`
- Severity: `critical`
- Description: AI instruction or skill file contains a preprocessed shell command or broad Bash tool grant.

### AIT014 AI API base URL points to a non-official endpoint

- Category: `ai-tool`
- Severity: `high`
- Description: AI API base URL override may redirect model traffic, prompts, or credentials to a third-party endpoint.

### AIT015 VS Code task runs automatically when folder opens

- Category: `ai-tool`
- Severity: `high`
- Description: VS Code tasks.json config can execute a command automatically when the project folder is opened.

### AIT016 AI skill reference is unpinned or from an untrusted source

- Category: `ai-tool`
- Severity: `high`
- Description: AI skill or command reference appears to use a mutable version or external registry/source.

### AIT017 Gemini CLI configuration contains unsafe automation setting

- Category: `ai-tool`
- Severity: `high`
- Description: Gemini CLI related configuration appears to enable broad automation or disable confirmation/sandbox controls.

### SEC001 OpenAI API key detected

- Category: `secrets`
- Severity: `critical`
- Description: OpenAI-style API key pattern.

### SEC002 GitHub token detected

- Category: `secrets`
- Severity: `critical`
- Description: GitHub token pattern.

### SEC003 Anthropic API key detected

- Category: `secrets`
- Severity: `critical`
- Description: Anthropic API key pattern.

### SEC004 Bearer token detected

- Category: `secrets`
- Severity: `high`
- Description: Authorization bearer token pattern.

### SEC005 Private key block detected

- Category: `secrets`
- Severity: `critical`
- Description: Private key PEM block.

### SEC006 AWS access key detected

- Category: `secrets`
- Severity: `critical`
- Description: AWS access key ID pattern.

### SEC007 Slack token detected

- Category: `secrets`
- Severity: `critical`
- Description: Slack token pattern.

### SEC008 Discord token or webhook detected

- Category: `secrets`
- Severity: `critical`
- Description: Discord token or webhook pattern.

### SEC009 Hugging Face token detected

- Category: `secrets`
- Severity: `critical`
- Description: Hugging Face token pattern.

### SEC010 npm access token detected

- Category: `secrets`
- Severity: `critical`
- Description: npm access token pattern.

### SEC011 PyPI API token detected

- Category: `secrets`
- Severity: `critical`
- Description: PyPI API token pattern.

### SEC012 Stripe API key detected

- Category: `secrets`
- Severity: `critical`
- Description: Stripe secret or restricted key pattern.

### SEC013 Google API key detected

- Category: `secrets`
- Severity: `critical`
- Description: Google API key pattern.

### SEC014 Azure Storage connection string detected

- Category: `secrets`
- Severity: `critical`
- Description: Azure Storage AccountKey in a connection string.

### SEC015 JWT detected

- Category: `secrets`
- Severity: `high`
- Description: JWT-like token pattern in credential context.

### SEC016 Database URL with embedded password detected

- Category: `secrets`
- Severity: `high`
- Description: Database connection URL embeds a password.

### SEC017 Generic high-entropy credential detected

- Category: `secrets`
- Severity: `high`
- Description: Credential-like assignment contains a high-entropy value.

### SEC018 DeepSeek API key detected

- Category: `secrets`
- Severity: `critical`
- Description: DeepSeek API key pattern or provider-specific assignment.

### SEC019 Groq API key detected

- Category: `secrets`
- Severity: `critical`
- Description: Groq API key pattern or provider-specific assignment.

### SEC020 xAI / Grok API key detected

- Category: `secrets`
- Severity: `critical`
- Description: xAI or Grok API key pattern or provider-specific assignment.

### SEC021 Perplexity API key detected

- Category: `secrets`
- Severity: `high`
- Description: Perplexity API key pattern or provider-specific assignment.

### SEC022 OpenRouter API key detected

- Category: `secrets`
- Severity: `high`
- Description: OpenRouter API key pattern or provider-specific assignment.

### SEC023 Together AI API key detected

- Category: `secrets`
- Severity: `high`
- Description: Together AI API key provider-specific assignment.

### SEC024 Fireworks AI API key detected

- Category: `secrets`
- Severity: `high`
- Description: Fireworks AI API key provider-specific assignment.

### SEC025 Mistral AI API key detected

- Category: `secrets`
- Severity: `high`
- Description: Mistral AI API key provider-specific assignment.

### SEC026 Cohere API key detected

- Category: `secrets`
- Severity: `high`
- Description: Cohere API key provider-specific assignment.

### SEC027 Replicate API token detected

- Category: `secrets`
- Severity: `high`
- Description: Replicate API token pattern or provider-specific assignment.

### SEC028 Azure OpenAI API key detected

- Category: `secrets`
- Severity: `high`
- Description: Azure OpenAI API key provider-specific assignment.

### SEC029 NVIDIA NIM / NGC API key detected

- Category: `secrets`
- Severity: `high`
- Description: NVIDIA AI API key provider-specific assignment.

### SEC030 Stability AI API key detected

- Category: `secrets`
- Severity: `high`
- Description: Stability AI API key pattern or provider-specific assignment.

### SEC031 ElevenLabs API key detected

- Category: `secrets`
- Severity: `high`
- Description: ElevenLabs API key provider-specific assignment.

### SEC032 Voyage AI API key detected

- Category: `secrets`
- Severity: `high`
- Description: Voyage AI API key provider-specific assignment.

### SEC033 Tavily API key detected

- Category: `secrets`
- Severity: `high`
- Description: Tavily API key pattern or provider-specific assignment.

### SEC034 Zhipu GLM / Z.ai API key detected

- Category: `secrets`
- Severity: `critical`
- Description: Zhipu GLM or Z.ai API key provider-specific assignment.

### SEC035 Kimi / Moonshot API key detected

- Category: `secrets`
- Severity: `critical`
- Description: Kimi or Moonshot API key provider-specific assignment.

### SEC036 Volcengine Ark / Doubao / Seedance API key detected

- Category: `secrets`
- Severity: `critical`
- Description: Volcengine Ark, Doubao, Seedance, or Seedream API key provider-specific assignment.

### SEC037 Alibaba Bailian / Qwen / DashScope API key detected

- Category: `secrets`
- Severity: `critical`
- Description: Alibaba Bailian, Qwen, or DashScope API key provider-specific assignment.

### SEC038 Baidu Qianfan / ERNIE API key detected

- Category: `secrets`
- Severity: `high`
- Description: Baidu Qianfan or ERNIE API key provider-specific assignment.

### SEC039 Tencent Hunyuan secret detected

- Category: `secrets`
- Severity: `high`
- Description: Tencent Hunyuan or Tencent Cloud AI credential pattern.

### SEC040 iFlytek Spark API key detected

- Category: `secrets`
- Severity: `high`
- Description: iFlytek Spark API key or secret provider-specific assignment.

### SEC041 MiniMax / Hailuo / Minmo API key detected

- Category: `secrets`
- Severity: `high`
- Description: MiniMax, Hailuo, or Minmo API key provider-specific assignment.

### SEC042 Baichuan AI API key detected

- Category: `secrets`
- Severity: `high`
- Description: Baichuan AI API key provider-specific assignment.

### SEC043 01.AI / Yi API key detected

- Category: `secrets`
- Severity: `high`
- Description: 01.AI or Yi API key provider-specific assignment.

### SEC044 StepFun API key detected

- Category: `secrets`
- Severity: `high`
- Description: StepFun API key provider-specific assignment.

### SEC045 SiliconFlow API key detected

- Category: `secrets`
- Severity: `high`
- Description: SiliconFlow API key pattern or provider-specific assignment.

### SEC046 SenseNova API key detected

- Category: `secrets`
- Severity: `high`
- Description: SenseNova API key or access key provider-specific assignment.

### SEC047 360 Zhinao API key detected

- Category: `secrets`
- Severity: `high`
- Description: 360 Zhinao API key provider-specific assignment.

### SEC048 ModelScope API token detected

- Category: `secrets`
- Severity: `high`
- Description: ModelScope API token provider-specific assignment.

### SEC049 Infini-AI API key detected

- Category: `secrets`
- Severity: `high`
- Description: Infini-AI API key provider-specific assignment.

### SEC050 Vidu / Shengshu API key detected

- Category: `secrets`
- Severity: `high`
- Description: Vidu or Shengshu API key provider-specific assignment.

### SEC051 Kling AI secret detected

- Category: `secrets`
- Severity: `high`
- Description: Kling AI access key, secret key, or API key provider-specific assignment.

### SEC052 OpenAI-compatible proxy key detected

- Category: `secrets`
- Severity: `high`
- Description: OpenAI-compatible API key combined with a non-OpenAI provider base URL or proxy context.

### SEC053 AI service access key pair detected

- Category: `secrets`
- Severity: `high`
- Description: Paired access key and secret key for an AI or cloud AI service.

### MCP001 Overly broad filesystem access

- Category: `mcp`
- Severity: `high`
- Description: MCP filesystem server grants root, home, or drive-level paths.

### MCP002 Shell-capable MCP command

- Category: `mcp`
- Severity: `high`
- Description: MCP server command can execute arbitrary shell instructions.

### MCP003 Secret value embedded in MCP environment

- Category: `mcp`
- Severity: `critical`
- Description: MCP environment variable contains a plaintext credential-like value.

### MCP004 Remote MCP server configured

- Category: `mcp`
- Severity: `medium`
- Description: Remote MCP server can receive tool context and should be reviewed.

### MCP005 Dangerous MCP server arguments

- Category: `mcp`
- Severity: `critical`
- Description: MCP server arguments disable or broaden safety controls.

### MCP006 MCP remote server uses plaintext HTTP

- Category: `mcp`
- Severity: `high`
- Description: MCP remote server transport is not encrypted.

### MCP007 MCP remote endpoint targets private or metadata address

- Category: `mcp`
- Severity: `high`
- Description: MCP remote endpoint points at localhost, private network, or cloud metadata services.

### MCP008 MCP tool scope is overly broad

- Category: `mcp`
- Severity: `high`
- Description: MCP configuration grants broad or administrative tool scope.

### MCP009 MCP forwards host credential environment variable

- Category: `mcp`
- Severity: `medium`
- Description: MCP configuration passes host credential environment variables into a server.

### MCP010 MCP filesystem access includes sensitive local path

- Category: `mcp`
- Severity: `high`
- Description: MCP filesystem access includes paths that commonly store credentials or browser/session data.

### MCP011 Writable MCP filesystem access is too broad

- Category: `mcp`
- Severity: `critical`
- Description: MCP filesystem access grants write-capable permissions to a broad path.

### MCP012 MCP tool or resource description contains unsafe instruction

- Category: `mcp`
- Severity: `high`
- Description: MCP tool/resource text attempts to override instructions, hide behavior, or access sensitive data.

### MCP013 MCP tool output is treated as executable instruction

- Category: `mcp`
- Severity: `high`
- Description: MCP configuration encourages following or executing instructions returned by a tool/resource.

### MCP014 MCP resource may inject remote prompt content

- Category: `mcp`
- Severity: `medium`
- Description: MCP resource text suggests loading prompt instructions from an external or remote source.

### MCP015 Remote MCP server has no obvious authentication configuration

- Category: `mcp`
- Severity: `high`
- Description: Remote MCP server configuration does not include an obvious OAuth, Authorization, token, API key, or auth header setting.

### MCP016 MCP stdio server lacks an obvious container or sandbox boundary

- Category: `mcp`
- Severity: `medium`
- Description: MCP stdio server runs a local command without an obvious container, sandbox, or isolation hint in configuration.

### MCP017 MCP tool name is declared by multiple servers

- Category: `mcp`
- Severity: `medium`
- Description: Multiple MCP servers declare the same tool name, which can confuse routing or enable tool-name impersonation.

### MCP018 MCP OAuth redirect URI uses wildcard or unsafe value

- Category: `mcp`
- Severity: `high`
- Description: MCP OAuth redirect URI configuration uses a wildcard, broad host, or unsafe redirect value.

### SH001 Recursive force delete command

- Category: `shell`
- Severity: `critical`
- Description: Broad destructive delete command.

### SH002 Downloaded script piped to shell

- Category: `shell`
- Severity: `critical`
- Description: Downloaded script executed directly by a shell.

### SH003 Disabled execution safety controls

- Category: `shell`
- Severity: `high`
- Description: Sandbox bypass or world-writable permission pattern.

### SH004 Potential secret exfiltration command

- Category: `shell`
- Severity: `high`
- Description: Shell command may send local secrets to a remote endpoint.

### SH005 Encoded command execution

- Category: `shell`
- Severity: `high`
- Description: Opaque encoded command execution pattern.

### SH006 PowerShell expression execution

- Category: `shell`
- Severity: `high`
- Description: Dynamic PowerShell expression execution pattern.

### SH007 Reverse shell pattern

- Category: `shell`
- Severity: `critical`
- Description: Reverse shell command pattern.

### SH008 Destructive disk or filesystem command

- Category: `shell`
- Severity: `critical`
- Description: Disk formatting or raw device overwrite pattern.

### SH009 Inline dynamic code execution

- Category: `shell`
- Severity: `medium`
- Description: Inline interpreter execution pattern.

### SH010 Package manager immediate execution command

- Category: `shell`
- Severity: `medium`
- Description: npx, npm create, pnpm dlx, or similar package manager immediate execution pattern.

### SC001 Package lifecycle script executes during install

- Category: `supply-chain`
- Severity: `high`
- Description: package.json contains a lifecycle script that runs automatically during install or publish.

### SC002 Package script contains risky install or execution command

- Category: `supply-chain`
- Severity: `high`
- Description: package.json script downloads or executes code dynamically.

### SC003 Package dependency uses remote Git or URL source

- Category: `supply-chain`
- Severity: `medium`
- Description: Package dependency is installed from a remote URL or Git source.

### SC004 Package dependency version is unpinned

- Category: `supply-chain`
- Severity: `medium`
- Description: Package dependency uses a wildcard or latest version.

### SC005 Package manager credential stored in config file

- Category: `supply-chain`
- Severity: `critical`
- Description: Package manager configuration contains a plaintext credential value.

### SC006 Docker base image uses latest tag

- Category: `supply-chain`
- Severity: `medium`
- Description: Dockerfile uses a mutable latest tag for the base image.

### SC007 Dockerfile ADD downloads remote content

- Category: `supply-chain`
- Severity: `medium`
- Description: Dockerfile ADD pulls remote content during build.

### SC008 Docker build executes downloaded script

- Category: `supply-chain`
- Severity: `high`
- Description: Dockerfile downloads and executes a script during image build.

### SC009 Container service uses privileged or host-level settings

- Category: `supply-chain`
- Severity: `high`
- Description: Compose service uses privileged mode or host-level namespace/network settings.

### SC010 Container mounts sensitive host path

- Category: `supply-chain`
- Severity: `high`
- Description: Compose service mounts a sensitive host path into a container.

### SC011 Devcontainer lifecycle command executes risky shell content

- Category: `supply-chain`
- Severity: `high`
- Description: devcontainer lifecycle command downloads or executes dynamic code.

### SC012 Devcontainer mounts sensitive host path

- Category: `supply-chain`
- Severity: `high`
- Description: devcontainer configuration mounts a sensitive host path.

### SC013 Python requirement uses remote URL or VCS source

- Category: `supply-chain`
- Severity: `medium`
- Description: requirements file installs a dependency from a remote URL or VCS source.

### SC014 Python requirement is not version pinned

- Category: `supply-chain`
- Severity: `low`
- Description: requirements file contains an unpinned package requirement.

### SC015 binding.gyp contains command substitution

- Category: `supply-chain`
- Severity: `critical`
- Description: binding.gyp can execute command substitutions during native package build or install.

### SC016 setup.py contains suspicious install-time command execution

- Category: `supply-chain`
- Severity: `high`
- Description: setup.py appears to execute shell commands, subprocesses, downloaded code, or decoded payloads during package installation.

### GHA001 pull_request_target workflow checks out code

- Category: `github-actions`
- Severity: `high`
- Description: Workflow combines elevated pull_request_target context with repository checkout.

### GHA002 Unpinned GitHub Action reference

- Category: `github-actions`
- Severity: `medium`
- Description: Third-party action is referenced by a mutable branch or tag.

### GHA003 Secret echoed in GitHub Actions shell

- Category: `github-actions`
- Severity: `critical`
- Description: Workflow shell step echoes a GitHub secret expression.

### GHA004 Dangerous script download in GitHub Actions

- Category: `github-actions`
- Severity: `critical`
- Description: Workflow downloads a script and executes it directly.

### GHA005 Overly broad GitHub Actions permissions

- Category: `github-actions`
- Severity: `high`
- Description: Workflow grants write-all or broad write permissions.

### GHA006 Self-hosted GitHub Actions runner

- Category: `github-actions`
- Severity: `medium`
- Description: Workflow runs on a self-hosted runner.

### GHA007 Untrusted GitHub context used directly in shell

- Category: `github-actions`
- Severity: `high`
- Description: Workflow shell step interpolates untrusted event data directly into a run command.

### GHA008 OIDC token permission granted

- Category: `github-actions`
- Severity: `medium`
- Description: Workflow job can mint GitHub OIDC tokens.

### GHA009 Cache or artifact action used in untrusted workflow context

- Category: `github-actions`
- Severity: `medium`
- Description: Workflow uses cache or artifact transfer on an event that may be influenced by untrusted contributors.

### GHA010 Downloaded artifact or cache content is executed

- Category: `github-actions`
- Severity: `high`
- Description: Workflow appears to execute content from an artifact or cache path.

### GHA011 workflow_run workflow may process untrusted artifacts with elevated permissions

- Category: `github-actions`
- Severity: `high`
- Description: workflow_run can run with privileged context and may consume attacker-controlled artifacts.

### GHA012 OIDC cloud trust policy constraints require verification

- Category: `github-actions`
- Severity: `medium`
- Description: Workflow grants id-token: write for cloud authentication, but repository-side YAML cannot prove strict cloud subject and audience constraints.

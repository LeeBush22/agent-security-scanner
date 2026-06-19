# Agent Security Scanner 规则索引

本文档由内置规则目录生成，用于发布前复核、SARIF 元数据和用户理解扫描范围。

内置规则总数：**126**

## 规则分类

| 分类 | 规则数 |
|---|---:|
| `ai-tool` | 17 |
| `github-actions` | 12 |
| `mcp` | 18 |
| `secrets` | 53 |
| `shell` | 10 |
| `supply-chain` | 16 |

## 规则总览

### AI 编程工具

| 规则 | 等级 | 标题 | 说明 |
|---|---|---|---|
| [AIT001](#ait001-ai-tool-auto-approval-is-enabled-or-too-broad) | `高危` | AI 编程工具启用了自动批准 | AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。 |
| [AIT002](#ait002-ai-tool-permission-checks-are-bypassed) | `严重` | AI 编程工具绕过了权限检查 | AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。 |
| [AIT003](#ait003-ai-tool-workspace-access-is-too-broad) | `高危` | AI 编程工具工作区访问范围过宽 | AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。 |
| [AIT004](#ait004-ai-tool-can-invoke-a-shell-capable-command) | `高危` | AI 编程工具可调用 Shell 命令 | AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。 |
| [AIT005](#ait005-secret-embedded-in-ai-coding-tool-config) | `严重` | AI 编程工具配置中包含明文密钥 | AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。 |
| [AIT006](#ait006-ai-instruction-file-contains-unsafe-instruction) | `高危` | AI 指令文件中包含不安全指令 | AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。 |
| [AIT007](#ait007-ai-memory-or-rule-file-contains-persistence-instruction) | `高危` | AI 记忆或规则文件包含持久化危险指令 | AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。 |
| [AIT008](#ait008-ai-instruction-grants-excessive-autonomy) | `高危` | AI 指令授予过度自治能力 | AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。 |
| [AIT009](#ait009-ai-instruction-allows-data-exfiltration) | `严重` | AI 指令允许数据外传 | AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。 |
| [AIT010](#ait010-ai-tool-grants-high-risk-tool-combination) | `高危` | AI 工具授予高风险工具组合 | AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。 |
| [AIT011](#ait011-claude-code-hook-executes-a-shell-command) | `严重` | Claude Code Hook 会执行 Shell 命令 | Claude Code Hook 配置会在 Agent 事件中自动执行 Shell 命令。 |
| [AIT012](#ait012-ai-instruction-file-contains-invisible-unicode-control-character) | `高危` | AI 指令文件包含不可见 Unicode 控制字符 | AI 指令文件包含零宽字符或双向控制字符，可能隐藏审查者看不见的指令。 |
| [AIT013](#ait013-ai-instruction-file-contains-dynamic-shell-execution) | `严重` | AI 指令文件包含动态 Shell 执行 | AI 指令或 Skill 文件包含预处理 Shell 命令，或授予 Bash(*) 这类过宽命令权限。 |
| [AIT014](#ait014-ai-api-base-url-points-to-a-non-official-endpoint) | `高危` | AI API Base URL 指向非官方端点 | AI API Base URL 被改写到非官方端点，可能把提示词、模型流量或凭据转发给第三方。 |
| [AIT015](#ait015-vs-code-task-runs-automatically-when-folder-opens) | `高危` | VS Code 打开文件夹时自动运行任务 | VS Code tasks.json 配置可能在打开项目文件夹时自动执行命令。 |
| [AIT016](#ait016-ai-skill-reference-is-unpinned-or-from-an-untrusted-source) | `高危` | AI Skill 引用未固定或来自不可信来源 | AI Skill 或命令引用使用可变版本、外部注册表或不可信来源。 |
| [AIT017](#ait017-gemini-cli-configuration-contains-unsafe-automation-setting) | `高危` | Gemini CLI 配置包含不安全自动化设置 | Gemini CLI 相关配置可能启用宽泛自动化，或关闭确认、沙箱等安全控制。 |

### GitHub Actions

| 规则 | 等级 | 标题 | 说明 |
|---|---|---|---|
| [GHA001](#gha001-pull-request-target-workflow-checks-out-code) | `高危` | pull_request_target 工作流检出代码 | GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。 |
| [GHA002](#gha002-unpinned-github-action-reference) | `中危` | GitHub Action 未固定到提交哈希 | GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。 |
| [GHA003](#gha003-secret-echoed-in-github-actions-shell) | `严重` | GitHub Actions 中输出了 Secret | GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。 |
| [GHA004](#gha004-dangerous-script-download-in-github-actions) | `严重` | GitHub Actions 中下载脚本后直接执行 | GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。 |
| [GHA005](#gha005-overly-broad-github-actions-permissions) | `高危` | GitHub Actions 权限过宽 | GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。 |
| [GHA006](#gha006-self-hosted-github-actions-runner) | `中危` | 使用自托管 GitHub Actions Runner | GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。 |
| [GHA007](#gha007-untrusted-github-context-used-directly-in-shell) | `高危` | GitHub Actions 直接在 Shell 中使用不可信上下文 | GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。 |
| [GHA008](#gha008-oidc-token-permission-granted) | `中危` | GitHub Actions 授予 OIDC Token 权限 | GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。 |
| [GHA009](#gha009-cache-or-artifact-action-used-in-untrusted-workflow-context) | `中危` | 不可信工作流上下文中使用 Cache 或 Artifact | GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。 |
| [GHA010](#gha010-downloaded-artifact-or-cache-content-is-executed) | `高危` | 执行了下载的 Artifact 或 Cache 内容 | GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。 |
| [GHA011](#gha011-workflow-run-workflow-may-process-untrusted-artifacts-with-elevated-permissions) | `高危` | workflow_run 可能以高权限处理不可信 Artifact | GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。 |
| [GHA012](#gha012-oidc-cloud-trust-policy-constraints-require-verification) | `中危` | OIDC 云侧信任策略约束需要核验 | 工作流为云认证授予 id-token: write，但仓库侧 YAML 无法证明云侧 subject、audience 等信任约束足够严格。 |

### MCP 配置

| 规则 | 等级 | 标题 | 说明 |
|---|---|---|---|
| [MCP001](#mcp001-overly-broad-filesystem-access) | `高危` | MCP 文件系统访问范围过宽 | MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。 |
| [MCP002](#mcp002-shell-capable-mcp-command) | `高危` | MCP 使用可执行 Shell 的命令 | MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。 |
| [MCP003](#mcp003-secret-value-embedded-in-mcp-environment) | `严重` | MCP 环境变量中包含明文密钥 | MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。 |
| [MCP004](#mcp004-remote-mcp-server-configured) | `中危` | 配置了远程 MCP Server | MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。 |
| [MCP005](#mcp005-dangerous-mcp-server-arguments) | `严重` | MCP Server 使用危险参数 | MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。 |
| [MCP006](#mcp006-mcp-remote-server-uses-plaintext-http) | `高危` | MCP 远程 Server 使用明文 HTTP | MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。 |
| [MCP007](#mcp007-mcp-remote-endpoint-targets-private-or-metadata-address) | `高危` | MCP 远程端点指向私有或 metadata 地址 | MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。 |
| [MCP008](#mcp008-mcp-tool-scope-is-overly-broad) | `高危` | MCP 工具 Scope 过宽 | MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。 |
| [MCP009](#mcp009-mcp-forwards-host-credential-environment-variable) | `中危` | MCP 转发主机凭据环境变量 | MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。 |
| [MCP010](#mcp010-mcp-filesystem-access-includes-sensitive-local-path) | `高危` | MCP 文件系统访问包含敏感本地路径 | MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。 |
| [MCP011](#mcp011-writable-mcp-filesystem-access-is-too-broad) | `严重` | MCP 可写文件系统访问范围过宽 | MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。 |
| [MCP012](#mcp012-mcp-tool-or-resource-description-contains-unsafe-instruction) | `高危` | MCP 工具或资源描述包含不安全指令 | MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。 |
| [MCP013](#mcp013-mcp-tool-output-is-treated-as-executable-instruction) | `高危` | MCP 工具输出被当作可执行指令 | MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。 |
| [MCP014](#mcp014-mcp-resource-may-inject-remote-prompt-content) | `中危` | MCP 资源可能注入远程 Prompt 内容 | MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。 |
| [MCP015](#mcp015-remote-mcp-server-has-no-obvious-authentication-configuration) | `高危` | 远程 MCP Server 缺少明显认证配置 | 远程 MCP Server 配置未包含明显的 OAuth、Authorization、Token、API Key 或认证请求头。 |
| [MCP016](#mcp016-mcp-stdio-server-lacks-an-obvious-container-or-sandbox-boundary) | `中危` | MCP stdio Server 缺少明显容器或沙箱隔离 | MCP stdio Server 运行本地命令，但配置中缺少明显容器、沙箱或隔离边界。 |
| [MCP017](#mcp017-mcp-tool-name-is-declared-by-multiple-servers) | `中危` | 多个 MCP Server 声明了相同工具名 | 多个 MCP Server 声明了相同工具名，可能造成工具路由混淆或工具名冒充。 |
| [MCP018](#mcp018-mcp-oauth-redirect-uri-uses-wildcard-or-unsafe-value) | `高危` | MCP OAuth Redirect URI 使用通配或不安全值 | MCP OAuth Redirect URI 使用通配符、过宽主机或不安全跳转值。 |

### 敏感信息

| 规则 | 等级 | 标题 | 说明 |
|---|---|---|---|
| [SEC001](#sec001-openai-api-key-detected) | `严重` | 发现 OpenAI API Key | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC002](#sec002-github-token-detected) | `严重` | 发现 GitHub Token | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC003](#sec003-anthropic-api-key-detected) | `严重` | 发现 Anthropic API Key | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC004](#sec004-bearer-token-detected) | `高危` | 发现 Bearer Token | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC005](#sec005-private-key-block-detected) | `严重` | 发现私钥块 | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC006](#sec006-aws-access-key-detected) | `严重` | 发现 AWS Access Key | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC007](#sec007-slack-token-detected) | `严重` | 发现 Slack Token | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC008](#sec008-discord-token-or-webhook-detected) | `严重` | 发现 Discord Token 或 Webhook | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC009](#sec009-hugging-face-token-detected) | `严重` | 发现 Hugging Face Token | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC010](#sec010-npm-access-token-detected) | `严重` | 发现 npm Access Token | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC011](#sec011-pypi-api-token-detected) | `严重` | 发现 PyPI API Token | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC012](#sec012-stripe-api-key-detected) | `严重` | 发现 Stripe API Key | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC013](#sec013-google-api-key-detected) | `严重` | 发现 Google API Key | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC014](#sec014-azure-storage-connection-string-detected) | `严重` | 发现 Azure Storage 连接字符串 | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC015](#sec015-jwt-detected) | `高危` | 发现 JWT | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC016](#sec016-database-url-with-embedded-password-detected) | `高危` | 数据库 URL 中包含密码 | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC017](#sec017-generic-high-entropy-credential-detected) | `高危` | 发现高熵凭据值 | 文件中存在疑似应受保护的凭据或密钥材料。 |
| [SEC018](#sec018-deepseek-api-key-detected) | `严重` | 发现 DeepSeek API Key | 文件中存在疑似 DeepSeek API Key 或服务商上下文中的明文凭据。 |
| [SEC019](#sec019-groq-api-key-detected) | `严重` | 发现 Groq API Key | 文件中存在疑似 Groq API Key 或服务商上下文中的明文凭据。 |
| [SEC020](#sec020-xai-grok-api-key-detected) | `严重` | 发现 xAI / Grok API Key | 文件中存在疑似 xAI / Grok API Key 或服务商上下文中的明文凭据。 |
| [SEC021](#sec021-perplexity-api-key-detected) | `高危` | 发现 Perplexity API Key | 文件中存在疑似 Perplexity API Key 或服务商上下文中的明文凭据。 |
| [SEC022](#sec022-openrouter-api-key-detected) | `高危` | 发现 OpenRouter API Key | 文件中存在疑似 OpenRouter API Key 或服务商上下文中的明文凭据。 |
| [SEC023](#sec023-together-ai-api-key-detected) | `高危` | 发现 Together AI API Key | 文件中存在疑似 Together AI API Key 或服务商上下文中的明文凭据。 |
| [SEC024](#sec024-fireworks-ai-api-key-detected) | `高危` | 发现 Fireworks AI API Key | 文件中存在疑似 Fireworks AI API Key 或服务商上下文中的明文凭据。 |
| [SEC025](#sec025-mistral-ai-api-key-detected) | `高危` | 发现 Mistral AI API Key | 文件中存在疑似 Mistral AI API Key 或服务商上下文中的明文凭据。 |
| [SEC026](#sec026-cohere-api-key-detected) | `高危` | 发现 Cohere API Key | 文件中存在疑似 Cohere API Key 或服务商上下文中的明文凭据。 |
| [SEC027](#sec027-replicate-api-token-detected) | `高危` | 发现 Replicate API Token | 文件中存在疑似 Replicate API Token 或服务商上下文中的明文凭据。 |
| [SEC028](#sec028-azure-openai-api-key-detected) | `高危` | 发现 Azure OpenAI API Key | 文件中存在疑似 Azure OpenAI API Key 或服务商上下文中的明文凭据。 |
| [SEC029](#sec029-nvidia-nim-ngc-api-key-detected) | `高危` | 发现 NVIDIA NIM / NGC API Key | 文件中存在疑似 NVIDIA NIM / NGC API Key 或服务商上下文中的明文凭据。 |
| [SEC030](#sec030-stability-ai-api-key-detected) | `高危` | 发现 Stability AI API Key | 文件中存在疑似 Stability AI API Key 或服务商上下文中的明文凭据。 |
| [SEC031](#sec031-elevenlabs-api-key-detected) | `高危` | 发现 ElevenLabs API Key | 文件中存在疑似 ElevenLabs API Key 或服务商上下文中的明文凭据。 |
| [SEC032](#sec032-voyage-ai-api-key-detected) | `高危` | 发现 Voyage AI API Key | 文件中存在疑似 Voyage AI API Key 或服务商上下文中的明文凭据。 |
| [SEC033](#sec033-tavily-api-key-detected) | `高危` | 发现 Tavily API Key | 文件中存在疑似 Tavily API Key 或服务商上下文中的明文凭据。 |
| [SEC034](#sec034-zhipu-glm-z-ai-api-key-detected) | `严重` | 发现智谱 GLM / Z.ai API Key | 文件中存在疑似智谱 GLM / Z.ai API Key 或服务商上下文中的明文凭据。 |
| [SEC035](#sec035-kimi-moonshot-api-key-detected) | `严重` | 发现 Kimi / Moonshot API Key | 文件中存在疑似 Kimi / Moonshot API Key 或服务商上下文中的明文凭据。 |
| [SEC036](#sec036-volcengine-ark-doubao-seedance-api-key-detected) | `严重` | 发现火山 Ark / 豆包 / Seedance API Key | 文件中存在疑似火山 Ark、豆包、Seedance 或 Seedream API Key。 |
| [SEC037](#sec037-alibaba-bailian-qwen-dashscope-api-key-detected) | `严重` | 发现阿里百炼 / Qwen / DashScope API Key | 文件中存在疑似阿里百炼、Qwen 或 DashScope API Key。 |
| [SEC038](#sec038-baidu-qianfan-ernie-api-key-detected) | `高危` | 发现百度千帆 / 文心 ERNIE API Key | 文件中存在疑似百度千帆或文心 ERNIE API Key。 |
| [SEC039](#sec039-tencent-hunyuan-secret-detected) | `高危` | 发现腾讯混元密钥 | 文件中存在疑似腾讯混元或腾讯云 AI 服务凭据。 |
| [SEC040](#sec040-iflytek-spark-api-key-detected) | `高危` | 发现讯飞星火 API Key | 文件中存在疑似讯飞星火 API Key、Secret 或服务商上下文凭据。 |
| [SEC041](#sec041-minimax-hailuo-minmo-api-key-detected) | `高危` | 发现 MiniMax / 海螺 / Minmo API Key | 文件中存在疑似 MiniMax、海螺或 Minmo API Key。 |
| [SEC042](#sec042-baichuan-ai-api-key-detected) | `高危` | 发现百川 AI API Key | 文件中存在疑似百川 AI API Key 或服务商上下文凭据。 |
| [SEC043](#sec043-01-ai-yi-api-key-detected) | `高危` | 发现 01.AI / 零一万物 / Yi API Key | 文件中存在疑似 01.AI、零一万物或 Yi API Key。 |
| [SEC044](#sec044-stepfun-api-key-detected) | `高危` | 发现阶跃星辰 StepFun API Key | 文件中存在疑似阶跃星辰 StepFun API Key。 |
| [SEC045](#sec045-siliconflow-api-key-detected) | `高危` | 发现硅基流动 SiliconFlow API Key | 文件中存在疑似硅基流动 SiliconFlow API Key。 |
| [SEC046](#sec046-sensenova-api-key-detected) | `高危` | 发现商汤日日新 SenseNova API Key | 文件中存在疑似商汤日日新 SenseNova API Key 或 Access Key。 |
| [SEC047](#sec047-360-zhinao-api-key-detected) | `高危` | 发现 360 智脑 API Key | 文件中存在疑似 360 智脑 API Key。 |
| [SEC048](#sec048-modelscope-api-token-detected) | `高危` | 发现 ModelScope API Token | 文件中存在疑似 ModelScope API Token。 |
| [SEC049](#sec049-infini-ai-api-key-detected) | `高危` | 发现 Infini-AI API Key | 文件中存在疑似 Infini-AI API Key。 |
| [SEC050](#sec050-vidu-shengshu-api-key-detected) | `高危` | 发现 Vidu / 生数科技 API Key | 文件中存在疑似 Vidu / 生数科技 API Key。 |
| [SEC051](#sec051-kling-ai-secret-detected) | `高危` | 发现可灵 Kling AI 密钥 | 文件中存在疑似可灵 Kling AI Access Key、Secret Key 或 API Key。 |
| [SEC052](#sec052-openai-compatible-proxy-key-detected) | `高危` | 发现 OpenAI 兼容代理密钥 | 文件中存在 OpenAI 兼容 API Key，并伴随非 OpenAI 服务商 Base URL 或代理上下文。 |
| [SEC053](#sec053-ai-service-access-key-pair-detected) | `高危` | 发现 AI 服务 Access Key / Secret Key 成对凭据 | 文件中存在 AI 或云 AI 服务的 Access Key 与 Secret Key 成对凭据。 |

### Shell 命令

| 规则 | 等级 | 标题 | 说明 |
|---|---|---|---|
| [SH001](#sh001-recursive-force-delete-command) | `严重` | 递归强制删除命令 | 文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。 |
| [SH002](#sh002-downloaded-script-piped-to-shell) | `严重` | 下载脚本后直接交给 Shell 执行 | 文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。 |
| [SH003](#sh003-disabled-execution-safety-controls) | `高危` | 禁用了执行安全控制 | 文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。 |
| [SH004](#sh004-potential-secret-exfiltration-command) | `高危` | 疑似敏感信息外传命令 | 文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。 |
| [SH005](#sh005-encoded-command-execution) | `高危` | 编码命令执行 | 文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。 |
| [SH006](#sh006-powershell-expression-execution) | `高危` | PowerShell 动态表达式执行 | 文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。 |
| [SH007](#sh007-reverse-shell-pattern) | `严重` | 反弹 Shell 模式 | 文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。 |
| [SH008](#sh008-destructive-disk-or-filesystem-command) | `严重` | 破坏性磁盘或文件系统命令 | 文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。 |
| [SH009](#sh009-inline-dynamic-code-execution) | `中危` | 内联动态代码执行 | 文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。 |
| [SH010](#sh010-package-manager-immediate-execution-command) | `中危` | 包管理器下载后立即执行命令 | 脚本使用 npx、npm create、pnpm dlx 等包管理器命令下载后立即执行代码。 |

### 供应链

| 规则 | 等级 | 标题 | 说明 |
|---|---|---|---|
| [SC001](#sc001-package-lifecycle-script-executes-during-install) | `高危` | 包安装生命周期脚本会自动执行 | 供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。 |
| [SC002](#sc002-package-script-contains-risky-install-or-execution-command) | `高危` | 包脚本包含高风险安装或执行命令 | 供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。 |
| [SC003](#sc003-package-dependency-uses-remote-git-or-url-source) | `中危` | 包依赖使用远程 Git 或 URL 来源 | 供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。 |
| [SC004](#sc004-package-dependency-version-is-unpinned) | `中危` | 包依赖版本未固定 | 供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。 |
| [SC005](#sc005-package-manager-credential-stored-in-config-file) | `严重` | 包管理器配置中存储明文凭据 | 供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。 |
| [SC006](#sc006-docker-base-image-uses-latest-tag) | `中危` | Docker 基础镜像使用 latest 标签 | 供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。 |
| [SC007](#sc007-dockerfile-add-downloads-remote-content) | `中危` | Dockerfile ADD 下载远程内容 | 供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。 |
| [SC008](#sc008-docker-build-executes-downloaded-script) | `高危` | Docker 构建执行下载脚本 | 供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。 |
| [SC009](#sc009-container-service-uses-privileged-or-host-level-settings) | `高危` | 容器服务使用 privileged 或主机级设置 | 供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。 |
| [SC010](#sc010-container-mounts-sensitive-host-path) | `高危` | 容器挂载敏感主机路径 | 供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。 |
| [SC011](#sc011-devcontainer-lifecycle-command-executes-risky-shell-content) | `高危` | Devcontainer 生命周期命令执行高风险 Shell 内容 | 供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。 |
| [SC012](#sc012-devcontainer-mounts-sensitive-host-path) | `高危` | Devcontainer 挂载敏感主机路径 | 供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。 |
| [SC013](#sc013-python-requirement-uses-remote-url-or-vcs-source) | `中危` | Python requirements 使用远程 URL 或 VCS 来源 | 供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。 |
| [SC014](#sc014-python-requirement-is-not-version-pinned) | `低危` | Python requirements 依赖未固定版本 | 供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。 |
| [SC015](#sc015-binding-gyp-contains-command-substitution) | `严重` | binding.gyp 包含命令替换 | binding.gyp 中的命令替换可能在原生包构建或安装阶段执行命令。 |
| [SC016](#sc016-setup-py-contains-suspicious-install-time-command-execution) | `高危` | setup.py 包含安装期可疑命令执行 | setup.py 可能在包安装阶段执行 Shell、subprocess、下载代码或解码载荷。 |

## 规则详情

<a id="ait001-ai-tool-auto-approval-is-enabled-or-too-broad"></a>

### AIT001 AI 编程工具启用了自动批准

- 分类：`AI 编程工具`
- 等级：`高危`
- 中文标题：AI 编程工具启用了自动批准
- 说明：AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。

<a id="ait002-ai-tool-permission-checks-are-bypassed"></a>

### AIT002 AI 编程工具绕过了权限检查

- 分类：`AI 编程工具`
- 等级：`严重`
- 中文标题：AI 编程工具绕过了权限检查
- 说明：AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。

<a id="ait003-ai-tool-workspace-access-is-too-broad"></a>

### AIT003 AI 编程工具工作区访问范围过宽

- 分类：`AI 编程工具`
- 等级：`高危`
- 中文标题：AI 编程工具工作区访问范围过宽
- 说明：AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。

<a id="ait004-ai-tool-can-invoke-a-shell-capable-command"></a>

### AIT004 AI 编程工具可调用 Shell 命令

- 分类：`AI 编程工具`
- 等级：`高危`
- 中文标题：AI 编程工具可调用 Shell 命令
- 说明：AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。

<a id="ait005-secret-embedded-in-ai-coding-tool-config"></a>

### AIT005 AI 编程工具配置中包含明文密钥

- 分类：`AI 编程工具`
- 等级：`严重`
- 中文标题：AI 编程工具配置中包含明文密钥
- 说明：AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。

<a id="ait006-ai-instruction-file-contains-unsafe-instruction"></a>

### AIT006 AI 指令文件中包含不安全指令

- 分类：`AI 编程工具`
- 等级：`高危`
- 中文标题：AI 指令文件中包含不安全指令
- 说明：AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。

<a id="ait007-ai-memory-or-rule-file-contains-persistence-instruction"></a>

### AIT007 AI 记忆或规则文件包含持久化危险指令

- 分类：`AI 编程工具`
- 等级：`高危`
- 中文标题：AI 记忆或规则文件包含持久化危险指令
- 说明：AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。

<a id="ait008-ai-instruction-grants-excessive-autonomy"></a>

### AIT008 AI 指令授予过度自治能力

- 分类：`AI 编程工具`
- 等级：`高危`
- 中文标题：AI 指令授予过度自治能力
- 说明：AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。

<a id="ait009-ai-instruction-allows-data-exfiltration"></a>

### AIT009 AI 指令允许数据外传

- 分类：`AI 编程工具`
- 等级：`严重`
- 中文标题：AI 指令允许数据外传
- 说明：AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。

<a id="ait010-ai-tool-grants-high-risk-tool-combination"></a>

### AIT010 AI 工具授予高风险工具组合

- 分类：`AI 编程工具`
- 等级：`高危`
- 中文标题：AI 工具授予高风险工具组合
- 说明：AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。

<a id="ait011-claude-code-hook-executes-a-shell-command"></a>

### AIT011 Claude Code Hook 会执行 Shell 命令

- 分类：`AI 编程工具`
- 等级：`严重`
- 中文标题：Claude Code Hook 会执行 Shell 命令
- 说明：Claude Code Hook 配置会在 Agent 事件中自动执行 Shell 命令。

<a id="ait012-ai-instruction-file-contains-invisible-unicode-control-character"></a>

### AIT012 AI 指令文件包含不可见 Unicode 控制字符

- 分类：`AI 编程工具`
- 等级：`高危`
- 中文标题：AI 指令文件包含不可见 Unicode 控制字符
- 说明：AI 指令文件包含零宽字符或双向控制字符，可能隐藏审查者看不见的指令。

<a id="ait013-ai-instruction-file-contains-dynamic-shell-execution"></a>

### AIT013 AI 指令文件包含动态 Shell 执行

- 分类：`AI 编程工具`
- 等级：`严重`
- 中文标题：AI 指令文件包含动态 Shell 执行
- 说明：AI 指令或 Skill 文件包含预处理 Shell 命令，或授予 Bash(*) 这类过宽命令权限。

<a id="ait014-ai-api-base-url-points-to-a-non-official-endpoint"></a>

### AIT014 AI API Base URL 指向非官方端点

- 分类：`AI 编程工具`
- 等级：`高危`
- 中文标题：AI API Base URL 指向非官方端点
- 说明：AI API Base URL 被改写到非官方端点，可能把提示词、模型流量或凭据转发给第三方。

<a id="ait015-vs-code-task-runs-automatically-when-folder-opens"></a>

### AIT015 VS Code 打开文件夹时自动运行任务

- 分类：`AI 编程工具`
- 等级：`高危`
- 中文标题：VS Code 打开文件夹时自动运行任务
- 说明：VS Code tasks.json 配置可能在打开项目文件夹时自动执行命令。

<a id="ait016-ai-skill-reference-is-unpinned-or-from-an-untrusted-source"></a>

### AIT016 AI Skill 引用未固定或来自不可信来源

- 分类：`AI 编程工具`
- 等级：`高危`
- 中文标题：AI Skill 引用未固定或来自不可信来源
- 说明：AI Skill 或命令引用使用可变版本、外部注册表或不可信来源。

<a id="ait017-gemini-cli-configuration-contains-unsafe-automation-setting"></a>

### AIT017 Gemini CLI 配置包含不安全自动化设置

- 分类：`AI 编程工具`
- 等级：`高危`
- 中文标题：Gemini CLI 配置包含不安全自动化设置
- 说明：Gemini CLI 相关配置可能启用宽泛自动化，或关闭确认、沙箱等安全控制。

<a id="sec001-openai-api-key-detected"></a>

### SEC001 发现 OpenAI API Key

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现 OpenAI API Key
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec002-github-token-detected"></a>

### SEC002 发现 GitHub Token

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现 GitHub Token
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec003-anthropic-api-key-detected"></a>

### SEC003 发现 Anthropic API Key

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现 Anthropic API Key
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec004-bearer-token-detected"></a>

### SEC004 发现 Bearer Token

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 Bearer Token
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec005-private-key-block-detected"></a>

### SEC005 发现私钥块

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现私钥块
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec006-aws-access-key-detected"></a>

### SEC006 发现 AWS Access Key

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现 AWS Access Key
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec007-slack-token-detected"></a>

### SEC007 发现 Slack Token

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现 Slack Token
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec008-discord-token-or-webhook-detected"></a>

### SEC008 发现 Discord Token 或 Webhook

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现 Discord Token 或 Webhook
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec009-hugging-face-token-detected"></a>

### SEC009 发现 Hugging Face Token

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现 Hugging Face Token
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec010-npm-access-token-detected"></a>

### SEC010 发现 npm Access Token

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现 npm Access Token
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec011-pypi-api-token-detected"></a>

### SEC011 发现 PyPI API Token

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现 PyPI API Token
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec012-stripe-api-key-detected"></a>

### SEC012 发现 Stripe API Key

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现 Stripe API Key
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec013-google-api-key-detected"></a>

### SEC013 发现 Google API Key

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现 Google API Key
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec014-azure-storage-connection-string-detected"></a>

### SEC014 发现 Azure Storage 连接字符串

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现 Azure Storage 连接字符串
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec015-jwt-detected"></a>

### SEC015 发现 JWT

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 JWT
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec016-database-url-with-embedded-password-detected"></a>

### SEC016 数据库 URL 中包含密码

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：数据库 URL 中包含密码
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec017-generic-high-entropy-credential-detected"></a>

### SEC017 发现高熵凭据值

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现高熵凭据值
- 说明：文件中存在疑似应受保护的凭据或密钥材料。

<a id="sec018-deepseek-api-key-detected"></a>

### SEC018 发现 DeepSeek API Key

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现 DeepSeek API Key
- 说明：文件中存在疑似 DeepSeek API Key 或服务商上下文中的明文凭据。

<a id="sec019-groq-api-key-detected"></a>

### SEC019 发现 Groq API Key

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现 Groq API Key
- 说明：文件中存在疑似 Groq API Key 或服务商上下文中的明文凭据。

<a id="sec020-xai-grok-api-key-detected"></a>

### SEC020 发现 xAI / Grok API Key

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现 xAI / Grok API Key
- 说明：文件中存在疑似 xAI / Grok API Key 或服务商上下文中的明文凭据。

<a id="sec021-perplexity-api-key-detected"></a>

### SEC021 发现 Perplexity API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 Perplexity API Key
- 说明：文件中存在疑似 Perplexity API Key 或服务商上下文中的明文凭据。

<a id="sec022-openrouter-api-key-detected"></a>

### SEC022 发现 OpenRouter API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 OpenRouter API Key
- 说明：文件中存在疑似 OpenRouter API Key 或服务商上下文中的明文凭据。

<a id="sec023-together-ai-api-key-detected"></a>

### SEC023 发现 Together AI API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 Together AI API Key
- 说明：文件中存在疑似 Together AI API Key 或服务商上下文中的明文凭据。

<a id="sec024-fireworks-ai-api-key-detected"></a>

### SEC024 发现 Fireworks AI API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 Fireworks AI API Key
- 说明：文件中存在疑似 Fireworks AI API Key 或服务商上下文中的明文凭据。

<a id="sec025-mistral-ai-api-key-detected"></a>

### SEC025 发现 Mistral AI API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 Mistral AI API Key
- 说明：文件中存在疑似 Mistral AI API Key 或服务商上下文中的明文凭据。

<a id="sec026-cohere-api-key-detected"></a>

### SEC026 发现 Cohere API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 Cohere API Key
- 说明：文件中存在疑似 Cohere API Key 或服务商上下文中的明文凭据。

<a id="sec027-replicate-api-token-detected"></a>

### SEC027 发现 Replicate API Token

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 Replicate API Token
- 说明：文件中存在疑似 Replicate API Token 或服务商上下文中的明文凭据。

<a id="sec028-azure-openai-api-key-detected"></a>

### SEC028 发现 Azure OpenAI API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 Azure OpenAI API Key
- 说明：文件中存在疑似 Azure OpenAI API Key 或服务商上下文中的明文凭据。

<a id="sec029-nvidia-nim-ngc-api-key-detected"></a>

### SEC029 发现 NVIDIA NIM / NGC API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 NVIDIA NIM / NGC API Key
- 说明：文件中存在疑似 NVIDIA NIM / NGC API Key 或服务商上下文中的明文凭据。

<a id="sec030-stability-ai-api-key-detected"></a>

### SEC030 发现 Stability AI API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 Stability AI API Key
- 说明：文件中存在疑似 Stability AI API Key 或服务商上下文中的明文凭据。

<a id="sec031-elevenlabs-api-key-detected"></a>

### SEC031 发现 ElevenLabs API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 ElevenLabs API Key
- 说明：文件中存在疑似 ElevenLabs API Key 或服务商上下文中的明文凭据。

<a id="sec032-voyage-ai-api-key-detected"></a>

### SEC032 发现 Voyage AI API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 Voyage AI API Key
- 说明：文件中存在疑似 Voyage AI API Key 或服务商上下文中的明文凭据。

<a id="sec033-tavily-api-key-detected"></a>

### SEC033 发现 Tavily API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 Tavily API Key
- 说明：文件中存在疑似 Tavily API Key 或服务商上下文中的明文凭据。

<a id="sec034-zhipu-glm-z-ai-api-key-detected"></a>

### SEC034 发现智谱 GLM / Z.ai API Key

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现智谱 GLM / Z.ai API Key
- 说明：文件中存在疑似智谱 GLM / Z.ai API Key 或服务商上下文中的明文凭据。

<a id="sec035-kimi-moonshot-api-key-detected"></a>

### SEC035 发现 Kimi / Moonshot API Key

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现 Kimi / Moonshot API Key
- 说明：文件中存在疑似 Kimi / Moonshot API Key 或服务商上下文中的明文凭据。

<a id="sec036-volcengine-ark-doubao-seedance-api-key-detected"></a>

### SEC036 发现火山 Ark / 豆包 / Seedance API Key

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现火山 Ark / 豆包 / Seedance API Key
- 说明：文件中存在疑似火山 Ark、豆包、Seedance 或 Seedream API Key。

<a id="sec037-alibaba-bailian-qwen-dashscope-api-key-detected"></a>

### SEC037 发现阿里百炼 / Qwen / DashScope API Key

- 分类：`敏感信息`
- 等级：`严重`
- 中文标题：发现阿里百炼 / Qwen / DashScope API Key
- 说明：文件中存在疑似阿里百炼、Qwen 或 DashScope API Key。

<a id="sec038-baidu-qianfan-ernie-api-key-detected"></a>

### SEC038 发现百度千帆 / 文心 ERNIE API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现百度千帆 / 文心 ERNIE API Key
- 说明：文件中存在疑似百度千帆或文心 ERNIE API Key。

<a id="sec039-tencent-hunyuan-secret-detected"></a>

### SEC039 发现腾讯混元密钥

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现腾讯混元密钥
- 说明：文件中存在疑似腾讯混元或腾讯云 AI 服务凭据。

<a id="sec040-iflytek-spark-api-key-detected"></a>

### SEC040 发现讯飞星火 API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现讯飞星火 API Key
- 说明：文件中存在疑似讯飞星火 API Key、Secret 或服务商上下文凭据。

<a id="sec041-minimax-hailuo-minmo-api-key-detected"></a>

### SEC041 发现 MiniMax / 海螺 / Minmo API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 MiniMax / 海螺 / Minmo API Key
- 说明：文件中存在疑似 MiniMax、海螺或 Minmo API Key。

<a id="sec042-baichuan-ai-api-key-detected"></a>

### SEC042 发现百川 AI API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现百川 AI API Key
- 说明：文件中存在疑似百川 AI API Key 或服务商上下文凭据。

<a id="sec043-01-ai-yi-api-key-detected"></a>

### SEC043 发现 01.AI / 零一万物 / Yi API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 01.AI / 零一万物 / Yi API Key
- 说明：文件中存在疑似 01.AI、零一万物或 Yi API Key。

<a id="sec044-stepfun-api-key-detected"></a>

### SEC044 发现阶跃星辰 StepFun API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现阶跃星辰 StepFun API Key
- 说明：文件中存在疑似阶跃星辰 StepFun API Key。

<a id="sec045-siliconflow-api-key-detected"></a>

### SEC045 发现硅基流动 SiliconFlow API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现硅基流动 SiliconFlow API Key
- 说明：文件中存在疑似硅基流动 SiliconFlow API Key。

<a id="sec046-sensenova-api-key-detected"></a>

### SEC046 发现商汤日日新 SenseNova API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现商汤日日新 SenseNova API Key
- 说明：文件中存在疑似商汤日日新 SenseNova API Key 或 Access Key。

<a id="sec047-360-zhinao-api-key-detected"></a>

### SEC047 发现 360 智脑 API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 360 智脑 API Key
- 说明：文件中存在疑似 360 智脑 API Key。

<a id="sec048-modelscope-api-token-detected"></a>

### SEC048 发现 ModelScope API Token

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 ModelScope API Token
- 说明：文件中存在疑似 ModelScope API Token。

<a id="sec049-infini-ai-api-key-detected"></a>

### SEC049 发现 Infini-AI API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 Infini-AI API Key
- 说明：文件中存在疑似 Infini-AI API Key。

<a id="sec050-vidu-shengshu-api-key-detected"></a>

### SEC050 发现 Vidu / 生数科技 API Key

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 Vidu / 生数科技 API Key
- 说明：文件中存在疑似 Vidu / 生数科技 API Key。

<a id="sec051-kling-ai-secret-detected"></a>

### SEC051 发现可灵 Kling AI 密钥

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现可灵 Kling AI 密钥
- 说明：文件中存在疑似可灵 Kling AI Access Key、Secret Key 或 API Key。

<a id="sec052-openai-compatible-proxy-key-detected"></a>

### SEC052 发现 OpenAI 兼容代理密钥

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 OpenAI 兼容代理密钥
- 说明：文件中存在 OpenAI 兼容 API Key，并伴随非 OpenAI 服务商 Base URL 或代理上下文。

<a id="sec053-ai-service-access-key-pair-detected"></a>

### SEC053 发现 AI 服务 Access Key / Secret Key 成对凭据

- 分类：`敏感信息`
- 等级：`高危`
- 中文标题：发现 AI 服务 Access Key / Secret Key 成对凭据
- 说明：文件中存在 AI 或云 AI 服务的 Access Key 与 Secret Key 成对凭据。

<a id="mcp001-overly-broad-filesystem-access"></a>

### MCP001 MCP 文件系统访问范围过宽

- 分类：`MCP 配置`
- 等级：`高危`
- 中文标题：MCP 文件系统访问范围过宽
- 说明：MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。

<a id="mcp002-shell-capable-mcp-command"></a>

### MCP002 MCP 使用可执行 Shell 的命令

- 分类：`MCP 配置`
- 等级：`高危`
- 中文标题：MCP 使用可执行 Shell 的命令
- 说明：MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。

<a id="mcp003-secret-value-embedded-in-mcp-environment"></a>

### MCP003 MCP 环境变量中包含明文密钥

- 分类：`MCP 配置`
- 等级：`严重`
- 中文标题：MCP 环境变量中包含明文密钥
- 说明：MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。

<a id="mcp004-remote-mcp-server-configured"></a>

### MCP004 配置了远程 MCP Server

- 分类：`MCP 配置`
- 等级：`中危`
- 中文标题：配置了远程 MCP Server
- 说明：MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。

<a id="mcp005-dangerous-mcp-server-arguments"></a>

### MCP005 MCP Server 使用危险参数

- 分类：`MCP 配置`
- 等级：`严重`
- 中文标题：MCP Server 使用危险参数
- 说明：MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。

<a id="mcp006-mcp-remote-server-uses-plaintext-http"></a>

### MCP006 MCP 远程 Server 使用明文 HTTP

- 分类：`MCP 配置`
- 等级：`高危`
- 中文标题：MCP 远程 Server 使用明文 HTTP
- 说明：MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。

<a id="mcp007-mcp-remote-endpoint-targets-private-or-metadata-address"></a>

### MCP007 MCP 远程端点指向私有或 metadata 地址

- 分类：`MCP 配置`
- 等级：`高危`
- 中文标题：MCP 远程端点指向私有或 metadata 地址
- 说明：MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。

<a id="mcp008-mcp-tool-scope-is-overly-broad"></a>

### MCP008 MCP 工具 Scope 过宽

- 分类：`MCP 配置`
- 等级：`高危`
- 中文标题：MCP 工具 Scope 过宽
- 说明：MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。

<a id="mcp009-mcp-forwards-host-credential-environment-variable"></a>

### MCP009 MCP 转发主机凭据环境变量

- 分类：`MCP 配置`
- 等级：`中危`
- 中文标题：MCP 转发主机凭据环境变量
- 说明：MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。

<a id="mcp010-mcp-filesystem-access-includes-sensitive-local-path"></a>

### MCP010 MCP 文件系统访问包含敏感本地路径

- 分类：`MCP 配置`
- 等级：`高危`
- 中文标题：MCP 文件系统访问包含敏感本地路径
- 说明：MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。

<a id="mcp011-writable-mcp-filesystem-access-is-too-broad"></a>

### MCP011 MCP 可写文件系统访问范围过宽

- 分类：`MCP 配置`
- 等级：`严重`
- 中文标题：MCP 可写文件系统访问范围过宽
- 说明：MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。

<a id="mcp012-mcp-tool-or-resource-description-contains-unsafe-instruction"></a>

### MCP012 MCP 工具或资源描述包含不安全指令

- 分类：`MCP 配置`
- 等级：`高危`
- 中文标题：MCP 工具或资源描述包含不安全指令
- 说明：MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。

<a id="mcp013-mcp-tool-output-is-treated-as-executable-instruction"></a>

### MCP013 MCP 工具输出被当作可执行指令

- 分类：`MCP 配置`
- 等级：`高危`
- 中文标题：MCP 工具输出被当作可执行指令
- 说明：MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。

<a id="mcp014-mcp-resource-may-inject-remote-prompt-content"></a>

### MCP014 MCP 资源可能注入远程 Prompt 内容

- 分类：`MCP 配置`
- 等级：`中危`
- 中文标题：MCP 资源可能注入远程 Prompt 内容
- 说明：MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。

<a id="mcp015-remote-mcp-server-has-no-obvious-authentication-configuration"></a>

### MCP015 远程 MCP Server 缺少明显认证配置

- 分类：`MCP 配置`
- 等级：`高危`
- 中文标题：远程 MCP Server 缺少明显认证配置
- 说明：远程 MCP Server 配置未包含明显的 OAuth、Authorization、Token、API Key 或认证请求头。

<a id="mcp016-mcp-stdio-server-lacks-an-obvious-container-or-sandbox-boundary"></a>

### MCP016 MCP stdio Server 缺少明显容器或沙箱隔离

- 分类：`MCP 配置`
- 等级：`中危`
- 中文标题：MCP stdio Server 缺少明显容器或沙箱隔离
- 说明：MCP stdio Server 运行本地命令，但配置中缺少明显容器、沙箱或隔离边界。

<a id="mcp017-mcp-tool-name-is-declared-by-multiple-servers"></a>

### MCP017 多个 MCP Server 声明了相同工具名

- 分类：`MCP 配置`
- 等级：`中危`
- 中文标题：多个 MCP Server 声明了相同工具名
- 说明：多个 MCP Server 声明了相同工具名，可能造成工具路由混淆或工具名冒充。

<a id="mcp018-mcp-oauth-redirect-uri-uses-wildcard-or-unsafe-value"></a>

### MCP018 MCP OAuth Redirect URI 使用通配或不安全值

- 分类：`MCP 配置`
- 等级：`高危`
- 中文标题：MCP OAuth Redirect URI 使用通配或不安全值
- 说明：MCP OAuth Redirect URI 使用通配符、过宽主机或不安全跳转值。

<a id="sh001-recursive-force-delete-command"></a>

### SH001 递归强制删除命令

- 分类：`Shell 命令`
- 等级：`严重`
- 中文标题：递归强制删除命令
- 说明：文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。

<a id="sh002-downloaded-script-piped-to-shell"></a>

### SH002 下载脚本后直接交给 Shell 执行

- 分类：`Shell 命令`
- 等级：`严重`
- 中文标题：下载脚本后直接交给 Shell 执行
- 说明：文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。

<a id="sh003-disabled-execution-safety-controls"></a>

### SH003 禁用了执行安全控制

- 分类：`Shell 命令`
- 等级：`高危`
- 中文标题：禁用了执行安全控制
- 说明：文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。

<a id="sh004-potential-secret-exfiltration-command"></a>

### SH004 疑似敏感信息外传命令

- 分类：`Shell 命令`
- 等级：`高危`
- 中文标题：疑似敏感信息外传命令
- 说明：文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。

<a id="sh005-encoded-command-execution"></a>

### SH005 编码命令执行

- 分类：`Shell 命令`
- 等级：`高危`
- 中文标题：编码命令执行
- 说明：文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。

<a id="sh006-powershell-expression-execution"></a>

### SH006 PowerShell 动态表达式执行

- 分类：`Shell 命令`
- 等级：`高危`
- 中文标题：PowerShell 动态表达式执行
- 说明：文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。

<a id="sh007-reverse-shell-pattern"></a>

### SH007 反弹 Shell 模式

- 分类：`Shell 命令`
- 等级：`严重`
- 中文标题：反弹 Shell 模式
- 说明：文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。

<a id="sh008-destructive-disk-or-filesystem-command"></a>

### SH008 破坏性磁盘或文件系统命令

- 分类：`Shell 命令`
- 等级：`严重`
- 中文标题：破坏性磁盘或文件系统命令
- 说明：文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。

<a id="sh009-inline-dynamic-code-execution"></a>

### SH009 内联动态代码执行

- 分类：`Shell 命令`
- 等级：`中危`
- 中文标题：内联动态代码执行
- 说明：文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。

<a id="sh010-package-manager-immediate-execution-command"></a>

### SH010 包管理器下载后立即执行命令

- 分类：`Shell 命令`
- 等级：`中危`
- 中文标题：包管理器下载后立即执行命令
- 说明：脚本使用 npx、npm create、pnpm dlx 等包管理器命令下载后立即执行代码。

<a id="sc001-package-lifecycle-script-executes-during-install"></a>

### SC001 包安装生命周期脚本会自动执行

- 分类：`供应链`
- 等级：`高危`
- 中文标题：包安装生命周期脚本会自动执行
- 说明：供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。

<a id="sc002-package-script-contains-risky-install-or-execution-command"></a>

### SC002 包脚本包含高风险安装或执行命令

- 分类：`供应链`
- 等级：`高危`
- 中文标题：包脚本包含高风险安装或执行命令
- 说明：供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。

<a id="sc003-package-dependency-uses-remote-git-or-url-source"></a>

### SC003 包依赖使用远程 Git 或 URL 来源

- 分类：`供应链`
- 等级：`中危`
- 中文标题：包依赖使用远程 Git 或 URL 来源
- 说明：供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。

<a id="sc004-package-dependency-version-is-unpinned"></a>

### SC004 包依赖版本未固定

- 分类：`供应链`
- 等级：`中危`
- 中文标题：包依赖版本未固定
- 说明：供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。

<a id="sc005-package-manager-credential-stored-in-config-file"></a>

### SC005 包管理器配置中存储明文凭据

- 分类：`供应链`
- 等级：`严重`
- 中文标题：包管理器配置中存储明文凭据
- 说明：供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。

<a id="sc006-docker-base-image-uses-latest-tag"></a>

### SC006 Docker 基础镜像使用 latest 标签

- 分类：`供应链`
- 等级：`中危`
- 中文标题：Docker 基础镜像使用 latest 标签
- 说明：供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。

<a id="sc007-dockerfile-add-downloads-remote-content"></a>

### SC007 Dockerfile ADD 下载远程内容

- 分类：`供应链`
- 等级：`中危`
- 中文标题：Dockerfile ADD 下载远程内容
- 说明：供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。

<a id="sc008-docker-build-executes-downloaded-script"></a>

### SC008 Docker 构建执行下载脚本

- 分类：`供应链`
- 等级：`高危`
- 中文标题：Docker 构建执行下载脚本
- 说明：供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。

<a id="sc009-container-service-uses-privileged-or-host-level-settings"></a>

### SC009 容器服务使用 privileged 或主机级设置

- 分类：`供应链`
- 等级：`高危`
- 中文标题：容器服务使用 privileged 或主机级设置
- 说明：供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。

<a id="sc010-container-mounts-sensitive-host-path"></a>

### SC010 容器挂载敏感主机路径

- 分类：`供应链`
- 等级：`高危`
- 中文标题：容器挂载敏感主机路径
- 说明：供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。

<a id="sc011-devcontainer-lifecycle-command-executes-risky-shell-content"></a>

### SC011 Devcontainer 生命周期命令执行高风险 Shell 内容

- 分类：`供应链`
- 等级：`高危`
- 中文标题：Devcontainer 生命周期命令执行高风险 Shell 内容
- 说明：供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。

<a id="sc012-devcontainer-mounts-sensitive-host-path"></a>

### SC012 Devcontainer 挂载敏感主机路径

- 分类：`供应链`
- 等级：`高危`
- 中文标题：Devcontainer 挂载敏感主机路径
- 说明：供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。

<a id="sc013-python-requirement-uses-remote-url-or-vcs-source"></a>

### SC013 Python requirements 使用远程 URL 或 VCS 来源

- 分类：`供应链`
- 等级：`中危`
- 中文标题：Python requirements 使用远程 URL 或 VCS 来源
- 说明：供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。

<a id="sc014-python-requirement-is-not-version-pinned"></a>

### SC014 Python requirements 依赖未固定版本

- 分类：`供应链`
- 等级：`低危`
- 中文标题：Python requirements 依赖未固定版本
- 说明：供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。

<a id="sc015-binding-gyp-contains-command-substitution"></a>

### SC015 binding.gyp 包含命令替换

- 分类：`供应链`
- 等级：`严重`
- 中文标题：binding.gyp 包含命令替换
- 说明：binding.gyp 中的命令替换可能在原生包构建或安装阶段执行命令。

<a id="sc016-setup-py-contains-suspicious-install-time-command-execution"></a>

### SC016 setup.py 包含安装期可疑命令执行

- 分类：`供应链`
- 等级：`高危`
- 中文标题：setup.py 包含安装期可疑命令执行
- 说明：setup.py 可能在包安装阶段执行 Shell、subprocess、下载代码或解码载荷。

<a id="gha001-pull-request-target-workflow-checks-out-code"></a>

### GHA001 pull_request_target 工作流检出代码

- 分类：`GitHub Actions`
- 等级：`高危`
- 中文标题：pull_request_target 工作流检出代码
- 说明：GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。

<a id="gha002-unpinned-github-action-reference"></a>

### GHA002 GitHub Action 未固定到提交哈希

- 分类：`GitHub Actions`
- 等级：`中危`
- 中文标题：GitHub Action 未固定到提交哈希
- 说明：GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。

<a id="gha003-secret-echoed-in-github-actions-shell"></a>

### GHA003 GitHub Actions 中输出了 Secret

- 分类：`GitHub Actions`
- 等级：`严重`
- 中文标题：GitHub Actions 中输出了 Secret
- 说明：GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。

<a id="gha004-dangerous-script-download-in-github-actions"></a>

### GHA004 GitHub Actions 中下载脚本后直接执行

- 分类：`GitHub Actions`
- 等级：`严重`
- 中文标题：GitHub Actions 中下载脚本后直接执行
- 说明：GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。

<a id="gha005-overly-broad-github-actions-permissions"></a>

### GHA005 GitHub Actions 权限过宽

- 分类：`GitHub Actions`
- 等级：`高危`
- 中文标题：GitHub Actions 权限过宽
- 说明：GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。

<a id="gha006-self-hosted-github-actions-runner"></a>

### GHA006 使用自托管 GitHub Actions Runner

- 分类：`GitHub Actions`
- 等级：`中危`
- 中文标题：使用自托管 GitHub Actions Runner
- 说明：GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。

<a id="gha007-untrusted-github-context-used-directly-in-shell"></a>

### GHA007 GitHub Actions 直接在 Shell 中使用不可信上下文

- 分类：`GitHub Actions`
- 等级：`高危`
- 中文标题：GitHub Actions 直接在 Shell 中使用不可信上下文
- 说明：GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。

<a id="gha008-oidc-token-permission-granted"></a>

### GHA008 GitHub Actions 授予 OIDC Token 权限

- 分类：`GitHub Actions`
- 等级：`中危`
- 中文标题：GitHub Actions 授予 OIDC Token 权限
- 说明：GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。

<a id="gha009-cache-or-artifact-action-used-in-untrusted-workflow-context"></a>

### GHA009 不可信工作流上下文中使用 Cache 或 Artifact

- 分类：`GitHub Actions`
- 等级：`中危`
- 中文标题：不可信工作流上下文中使用 Cache 或 Artifact
- 说明：GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。

<a id="gha010-downloaded-artifact-or-cache-content-is-executed"></a>

### GHA010 执行了下载的 Artifact 或 Cache 内容

- 分类：`GitHub Actions`
- 等级：`高危`
- 中文标题：执行了下载的 Artifact 或 Cache 内容
- 说明：GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。

<a id="gha011-workflow-run-workflow-may-process-untrusted-artifacts-with-elevated-permissions"></a>

### GHA011 workflow_run 可能以高权限处理不可信 Artifact

- 分类：`GitHub Actions`
- 等级：`高危`
- 中文标题：workflow_run 可能以高权限处理不可信 Artifact
- 说明：GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。

<a id="gha012-oidc-cloud-trust-policy-constraints-require-verification"></a>

### GHA012 OIDC 云侧信任策略约束需要核验

- 分类：`GitHub Actions`
- 等级：`中危`
- 中文标题：OIDC 云侧信任策略约束需要核验
- 说明：工作流为云认证授予 id-token: write，但仓库侧 YAML 无法证明云侧 subject、audience 等信任约束足够严格。

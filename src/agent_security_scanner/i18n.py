from __future__ import annotations

from enum import Enum

from agent_security_scanner.rules_catalog import rule_prefix


class Language(str, Enum):
    EN = "en"
    ZH = "zh"


TRANSLATIONS: dict[str, dict[Language, str]] = {
    "agent_name": {Language.EN: "Agent Security Scanner", Language.ZH: "Agent Security Scanner"},
    "target": {Language.EN: "Target", Language.ZH: "扫描目标"},
    "findings": {Language.EN: "Findings", Language.ZH: "发现数量"},
    "no_findings": {Language.EN: "No findings.", Language.ZH: "未发现风险。"},
    "severity": {Language.EN: "Severity", Language.ZH: "风险等级"},
    "rule": {Language.EN: "Rule", Language.ZH: "规则"},
    "title": {Language.EN: "Title", Language.ZH: "标题"},
    "file": {Language.EN: "File", Language.ZH: "文件"},
    "line": {Language.EN: "Line", Language.ZH: "行号"},
    "effort": {Language.EN: "Effort", Language.ZH: "修复难度"},
    "category": {Language.EN: "Category", Language.ZH: "分类"},
    "status": {Language.EN: "Status", Language.ZH: "状态"},
    "detail": {Language.EN: "Detail", Language.ZH: "详情"},
    "check": {Language.EN: "Check", Language.ZH: "检查项"},
    "ok": {Language.EN: "OK", Language.ZH: "通过"},
    "fail": {Language.EN: "FAIL", Language.ZH: "失败"},
    "installed": {Language.EN: "installed", Language.ZH: "已安装"},
    "missing": {Language.EN: "missing", Language.ZH: "缺失"},
    "doctor_title": {Language.EN: "Agent Security Scanner Doctor", Language.ZH: "Agent Security Scanner 环境诊断"},
    "python_version": {Language.EN: "Python version", Language.ZH: "Python 版本"},
    "project_directory": {Language.EN: "Project directory", Language.ZH: "项目目录"},
    "output_directory_writable": {Language.EN: "Output directory writable", Language.ZH: "输出目录可写"},
    "rule_catalog_unique_ids": {Language.EN: "Rule catalog unique IDs", Language.ZH: "规则目录 ID 唯一性"},
    "rule_catalog_id_format": {Language.EN: "Rule catalog ID format", Language.ZH: "规则目录 ID 格式"},
    "rule_catalog_prefix_category": {Language.EN: "Rule prefix/category consistency", Language.ZH: "规则前缀与分类一致性"},
    "rule_catalog_metadata": {Language.EN: "Rule metadata completeness", Language.ZH: "规则元数据完整性"},
    "rule_emitters_registered": {Language.EN: "Scanner rules registered", Language.ZH: "扫描器规则已登记"},
    "rule_catalog_reachable": {Language.EN: "Catalog rules reachable", Language.ZH: "规则目录可触达性"},
    "rules_title": {Language.EN: "Built-in Rules", Language.ZH: "内置规则"},
    "no_rules_found": {Language.EN: "No rules found for category", Language.ZH: "未找到该分类的规则"},
    "reports_in": {Language.EN: "Reports in", Language.ZH: "报告目录"},
    "format": {Language.EN: "Format", Language.ZH: "格式"},
    "filename": {Language.EN: "Filename", Language.ZH: "文件名"},
    "size": {Language.EN: "Size", Language.ZH: "大小"},
    "no_reports_found": {Language.EN: "No reports found in", Language.ZH: "未找到报告目录"},
    "wrote_config": {Language.EN: "Wrote config to", Language.ZH: "已写入配置文件"},
    "config_exists": {Language.EN: "Config already exists", Language.ZH: "配置文件已存在"},
    "use_force": {Language.EN: "Use --force to overwrite.", Language.ZH: "可使用 --force 覆盖。"},
    "wrote_baseline": {Language.EN: "Wrote baseline to", Language.ZH: "已写入 baseline"},
    "finding_count": {Language.EN: "finding(s)", Language.ZH: "个发现"},
    "wrote_excel": {Language.EN: "Wrote Excel report to", Language.ZH: "已写入 Excel 报告"},
    "wrote_pdf": {Language.EN: "Wrote PDF report to", Language.ZH: "已写入 PDF 报告"},
    "wrote_reports": {Language.EN: "Wrote reports to", Language.ZH: "已写入报告目录"},
    "wrote_all_reports": {Language.EN: "Wrote all reports to", Language.ZH: "已写入全部报告"},
    "wrote_english": {Language.EN: "Wrote English report to", Language.ZH: "已写入英文报告"},
    "wrote_chinese": {Language.EN: "Wrote Chinese report to", Language.ZH: "已写入中文报告"},
    "wrote_report": {Language.EN: "Wrote report to", Language.ZH: "已写入报告"},
    "fail_on_gate": {Language.EN: "Fail-on gate triggered", Language.ZH: "安全门禁已触发"},
    "at_or_above": {Language.EN: "at or above", Language.ZH: "等级不低于"},
    "welcome_back": {Language.EN: "Welcome back", Language.ZH: "欢迎回来"},
    "quick_start": {Language.EN: "Tips for getting started", Language.ZH: "快速开始"},
    "reports": {Language.EN: "Reports", Language.ZH: "报告"},
    "checks": {Language.EN: "Checks", Language.ZH: "检查项"},
    "local_first": {Language.EN: "Local-first AI Agent / MCP scanner", Language.ZH: "本地优先的 AI Agent / MCP 扫描器"},
    "version": {Language.EN: "Version", Language.ZH: "版本"},
    "interactive_menu": {Language.EN: "Interactive Menu", Language.ZH: "交互式菜单"},
    "select_option": {Language.EN: "Select an option", Language.ZH: "请选择操作"},
    "scan_current": {Language.EN: "Scan current directory", Language.ZH: "扫描当前目录"},
    "scan_another": {Language.EN: "Scan another directory", Language.ZH: "扫描其他目录"},
    "generate_all_reports": {Language.EN: "Generate all reports", Language.ZH: "生成全部报告"},
    "generate_excel_pdf": {Language.EN: "Generate Excel and PDF reports", Language.ZH: "生成 Excel 和 PDF 报告"},
    "init_config": {Language.EN: "Initialize .agent-scan.yml", Language.ZH: "初始化 .agent-scan.yml"},
    "run_doctor": {Language.EN: "Run doctor checks", Language.ZH: "运行环境诊断"},
    "list_rules": {Language.EN: "List built-in rules", Language.ZH: "查看内置规则"},
    "list_reports": {Language.EN: "List generated reports", Language.ZH: "查看已生成报告"},
    "create_baseline": {Language.EN: "Create or update baseline", Language.ZH: "创建或更新 baseline"},
    "baseline_gate_preview": {Language.EN: "Scan with baseline gate preview", Language.ZH: "预览 baseline 门禁"},
    "show_examples": {Language.EN: "Show command examples", Language.ZH: "显示命令示例"},
    "exit": {Language.EN: "Exit", Language.ZH: "退出"},
    "switch_language": {Language.EN: "Switch language", Language.ZH: "切换语言"},
    "path_to_scan": {Language.EN: "Path to scan", Language.ZH: "扫描路径"},
    "output_directory": {Language.EN: "Output directory", Language.ZH: "输出目录"},
    "all_reports_project_directory": {
        Language.EN: "Project directory for all reports",
        Language.ZH: "要生成全部报告的项目目录",
    },
    "all_reports_output_directory": {
        Language.EN: "All reports output directory",
        Language.ZH: "全部报告输出目录",
    },
    "excel_pdf_project_directory": {
        Language.EN: "Project directory for Excel/PDF reports",
        Language.ZH: "要生成 Excel/PDF 报告的项目目录",
    },
    "excel_pdf_output_directory": {
        Language.EN: "Excel/PDF reports output directory",
        Language.ZH: "Excel/PDF 报告输出目录",
    },
    "baseline_project_directory": {
        Language.EN: "Project directory for baseline",
        Language.ZH: "要创建 baseline 的项目目录",
    },
    "baseline_file_path": {
        Language.EN: "Baseline file path",
        Language.ZH: "Baseline 文件保存路径",
    },
    "project_directory_prompt": {Language.EN: "Project directory", Language.ZH: "项目目录"},
    "project_directory_hint": {
        Language.EN: "Example: press Enter or type . for the current directory; use a full path for another project.",
        Language.ZH: "示例：直接回车或输入 . 表示当前目录；扫描其他项目请输入完整路径。",
    },
    "output_directory_hint": {
        Language.EN: "Example: press Enter to write reports to output.",
        Language.ZH: "直接回车将报告写入 output 目录。",
    },
    "last_target_hint": {
        Language.EN: "Press Enter to use the last scanned project directory.",
        Language.ZH: "直接回车将使用上次扫描的项目目录。",
    },
    "report_scan_target": {
        Language.EN: "Report scan target",
        Language.ZH: "报告扫描目标",
    },
    "category_filter": {Language.EN: "Category filter (optional)", Language.ZH: "分类过滤（可选）"},
    "category_filter_hint": {
        Language.EN: "Category filter: press Enter for all rules; or enter secrets, mcp, shell, github-actions, ai-tool, or supply-chain.",
        Language.ZH: "分类过滤：直接回车显示全部；可输入 secrets、mcp、shell、github-actions、ai-tool、supply-chain。",
    },
    "baseline_path": {Language.EN: "Baseline path", Language.ZH: "Baseline 路径"},
    "baseline_missing_hint": {
        Language.EN: "Create a baseline first with option 9, or enter the path to an existing baseline file.",
        Language.ZH: "请先使用选项 9 创建 baseline，或输入已有 baseline 文件路径。",
    },
    "file_operation_failed": {Language.EN: "File operation failed", Language.ZH: "文件写入失败"},
    "file_operation_hint": {
        Language.EN: "Close any open report files, check directory permissions, or choose another output directory.",
        Language.ZH: "请关闭已打开的报告文件，检查目录权限，或选择其他输出目录。",
    },
    "config_directory": {Language.EN: "Directory for .agent-scan.yml", Language.ZH: ".agent-scan.yml 所在目录"},
    "overwrite_existing": {Language.EN: "Overwrite if it already exists?", Language.ZH: "如果已存在，是否覆盖？"},
    "path_not_exist": {Language.EN: "Path does not exist", Language.ZH: "路径不存在"},
    "gate_fail": {Language.EN: "Gate would fail", Language.ZH: "门禁将失败"},
    "gate_pass": {Language.EN: "Gate would pass.", Language.ZH: "门禁将通过。"},
    "high_critical": {Language.EN: "high/critical finding(s)", Language.ZH: "个高危/严重发现"},
    "unknown_option": {Language.EN: "Unknown option. Choose 1-13.", Language.ZH: "未知选项，请选择 1-13。"},
    "goodbye": {Language.EN: "Goodbye.", Language.ZH: "再见。"},
    "command_examples": {Language.EN: "Command Examples", Language.ZH: "命令示例"},
    "language_now": {Language.EN: "Language switched to English.", Language.ZH: "语言已切换为中文。"},
    "back_hint": {Language.EN: "Type q, back, or esc to go back.", Language.ZH: "输入 q、back 或 esc 返回上一级。"},
    "back_to_menu": {Language.EN: "Returned to the previous menu.", Language.ZH: "已返回上一级菜单。"},
}


SEVERITY_ZH = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}

CATEGORY_ZH = {
    "secrets": "敏感信息",
    "mcp": "MCP 配置",
    "shell": "Shell 命令",
    "github-actions": "GitHub Actions",
    "ai-tool": "AI 编程工具",
    "filesystem": "文件系统",
}

CATEGORY_ZH.update({"supply-chain": "供应链"})

EFFORT_ZH = {
    "low": "低",
    "medium": "中",
    "high": "高",
}

REPORT_LABELS_ZH = {
    "Markdown (English)": "Markdown（英文）",
    "Markdown (Chinese)": "Markdown（中文）",
    "Excel (English)": "Excel（英文）",
    "Excel (Chinese)": "Excel（中文）",
    "PDF (English)": "PDF（英文）",
    "PDF (Chinese)": "PDF（中文）",
    "SARIF": "SARIF",
    "JSON": "JSON",
    "Excel": "Excel",
    "PDF": "PDF",
}

RULE_TITLE_ZH = {
    "AIT001": "AI 编程工具启用了自动批准",
    "AIT002": "AI 编程工具绕过了权限检查",
    "AIT003": "AI 编程工具工作区访问范围过宽",
    "AIT004": "AI 编程工具可调用 Shell 命令",
    "AIT005": "AI 编程工具配置中包含明文密钥",
    "SEC001": "发现 OpenAI API Key",
    "SEC002": "发现 GitHub Token",
    "SEC003": "发现 Anthropic API Key",
    "SEC004": "发现 Bearer Token",
    "SEC005": "发现私钥块",
    "SEC006": "发现 AWS Access Key",
    "MCP001": "MCP 文件系统访问范围过宽",
    "MCP002": "MCP 使用可执行 Shell 的命令",
    "MCP003": "MCP 环境变量中包含明文密钥",
    "MCP004": "配置了远程 MCP Server",
    "MCP005": "MCP Server 使用危险参数",
    "SH001": "递归强制删除命令",
    "SH002": "下载脚本后直接交给 Shell 执行",
    "SH003": "禁用了执行安全控制",
    "SH004": "疑似敏感信息外传命令",
    "SH005": "编码命令执行",
    "GHA001": "pull_request_target 工作流检出代码",
    "GHA002": "GitHub Action 未固定到提交哈希",
    "GHA003": "GitHub Actions 中输出了 Secret",
    "GHA004": "GitHub Actions 中下载脚本后直接执行",
    "GHA005": "GitHub Actions 权限过宽",
    "GHA006": "使用自托管 GitHub Actions Runner",
}

RULE_DESCRIPTION_ZH_BY_PREFIX = {
    "SEC": "文件中存在疑似应受保护的凭据或密钥材料。",
    "MCP": "MCP 配置中存在可能扩大工具权限或暴露敏感信息的风险。",
    "SH": "文件中存在可能造成破坏、绕过安全控制或外传数据的 Shell 命令模式。",
    "GHA": "GitHub Actions 工作流中存在可能扩大自动化权限或执行不可信代码的风险。",
    "AIT": "AI 编程工具配置中存在可能扩大自动执行、文件访问或命令执行权限的风险。",
    "SC": "供应链配置中存在可能在安装、构建或容器运行阶段扩大风险的配置。",
}

RULE_DESCRIPTION_ZH: dict[str, str] = {}

RULE_RECOMMENDATION_ZH = {
    "AIT001": "请关闭宽泛的自动批准，为命令执行、文件修改和外部工具调用保留人工确认。",
    "AIT002": "请保持权限提示和沙箱检查开启，只在必要时授予最小范围的例外。",
    "AIT003": "请将 AI 编程工具的文件系统访问限制到最小必要项目目录。",
    "AIT004": "请将命令执行限制到经过审查的程序，并在访问 Shell 前要求确认。",
    "AIT005": "请将凭据迁移到本地环境变量或密钥管理系统，并轮换已暴露的值。",
    "SEC": "请将密钥迁移到本地环境变量或专用密钥管理系统，并轮换已暴露的值。",
    "MCP001": "请将文件系统访问范围限制到最小必要项目目录。",
    "MCP002": "请确认该 MCP Server 是否必须具备 Shell 执行能力，并限制参数和工作目录。",
    "MCP003": "请改为从本地环境变量引用密钥，不要把明文值写入 MCP 配置文件。",
    "MCP004": "请审查远程服务的所有者、传输安全和数据暴露范围后再启用。",
    "MCP005": "请移除危险参数，仅授予 MCP Server 所需的最小权限。",
    "SH001": "请避免宽泛的破坏性删除，限制目标路径并加入显式安全检查。",
    "SH002": "请先下载到文件并审查内容、校验完整性，再以最小权限执行。",
    "SH003": "请保持沙箱和权限检查开启，避免使用全局可写权限。",
    "SH004": "请不要通过 Shell 命令发送本地密钥或凭据材料，改用受控且可审计的凭据流转方式。",
    "SH005": "请避免执行不可读的编码命令，改用可审查的脚本文件。",
    "GHA001": "请优先使用 pull_request 处理不可信代码，或避免在 pull_request_target 中检出攻击者可控引用。",
    "GHA002": "请将第三方 Action 固定到完整提交哈希，并有计划地审查更新。",
    "GHA003": "请不要输出 Secret，仅通过可信工具的环境变量或 secret input 使用。",
    "GHA004": "请先下载到文件并审查内容、校验完整性，再执行脚本。",
    "GHA005": "请按最小权限原则配置工作流权限，默认优先使用只读权限。",
    "GHA006": "请避免让不可信代码运行在自托管 Runner 上，或对 Runner 做隔离和加固。",
}


RULE_TITLE_ZH.update(
    {
        "AIT006": "AI 指令文件中包含不安全指令",
        "SEC007": "发现 Slack Token",
        "SEC008": "发现 Discord Token 或 Webhook",
        "SEC009": "发现 Hugging Face Token",
        "SEC010": "发现 npm Access Token",
        "SEC011": "发现 PyPI API Token",
        "SEC012": "发现 Stripe API Key",
        "SEC013": "发现 Google API Key",
        "SEC014": "发现 Azure Storage 连接字符串",
        "SEC015": "发现 JWT",
        "SEC016": "数据库 URL 中包含密码",
        "SEC017": "发现高熵凭据值",
        "MCP006": "MCP 远程 Server 使用明文 HTTP",
        "MCP007": "MCP 远程端点指向私有或 metadata 地址",
        "MCP008": "MCP 工具 Scope 过宽",
        "MCP009": "MCP 转发主机凭据环境变量",
        "SH006": "PowerShell 动态表达式执行",
        "SH007": "反弹 Shell 模式",
        "SH008": "破坏性磁盘或文件系统命令",
        "SH009": "内联动态代码执行",
    }
)

RULE_RECOMMENDATION_ZH.update(
    {
        "AIT006": "请移除绕过安全控制、请求访问密钥或泄露系统提示的指令。",
        "MCP006": "请使用 HTTPS 或可信任的本地传输方式，避免通过明文 HTTP 传输 MCP 上下文。",
        "MCP007": "请审查该端点是否需要访问本地、私有网络或 metadata 地址，并设置网络访问限制。",
        "MCP008": "请用明确的最小工具、资源和操作权限替换 wildcard 或 admin scope。",
        "MCP009": "请不要将主机上的广泛凭据转发给 MCP Server，改用专用且范围受限的 token。",
        "SH006": "请避免 PowerShell 动态表达式执行，改用明确命令或可审查脚本。",
        "SH007": "请移除反弹 Shell 行为，改用经过身份验证和审计的远程管理方式。",
        "SH008": "请不要在项目脚本中执行磁盘格式化或原始设备写入操作，除非做了严格隔离和保护。",
        "SH009": "请优先使用已提交、可审查的脚本，避免在自动化路径中使用内联动态代码。",
    }
)


RULE_TITLE_ZH.update(
    {
        "MCP010": "MCP 文件系统访问包含敏感本地路径",
        "MCP011": "MCP 可写文件系统访问范围过宽",
        "GHA007": "GitHub Actions 直接在 Shell 中使用不可信上下文",
        "GHA008": "GitHub Actions 授予 OIDC Token 权限",
        "GHA009": "不可信工作流上下文中使用 Cache 或 Artifact",
        "GHA010": "执行了下载的 Artifact 或 Cache 内容",
        "GHA011": "workflow_run 可能以高权限处理不可信 Artifact",
    }
)

RULE_RECOMMENDATION_ZH.update(
    {
        "MCP010": "请移除 .ssh、.aws、.env、浏览器 profile 等敏感本地路径，只暴露必要项目目录。",
        "MCP011": "请默认关闭 MCP 写权限，并将可写路径限制到明确的项目子目录。",
        "GHA007": "请将不可信 GitHub 事件数据放入环境变量，安全引用和校验后再用于 Shell。",
        "GHA008": "请仅向需要云联合身份的 Job 授予 id-token: write，并检查云端信任策略限制。",
        "GHA009": "请隔离不可信 PR 的 cache/artifact，避免在高权限流程中信任其内容。",
        "GHA010": "请在执行 artifact 或 cache 内容前校验完整性、来源和预期路径。",
        "GHA011": "请将 workflow_run artifact 视为不可信输入，在高权限 Job 中使用前进行校验。",
    }
)


RULE_TITLE_ZH.update(
    {
        "AIT007": "AI 记忆或规则文件包含持久化危险指令",
        "AIT008": "AI 指令授予过度自治能力",
        "AIT009": "AI 指令允许数据外传",
        "AIT010": "AI 工具授予高风险工具组合",
        "MCP012": "MCP 工具或资源描述包含不安全指令",
        "MCP013": "MCP 工具输出被当作可执行指令",
        "MCP014": "MCP 资源可能注入远程 Prompt 内容",
    }
)

RULE_RECOMMENDATION_ZH.update(
    {
        "AIT007": "请移除会持久化绕过审批、访问密钥或隐藏行为的记忆/规则指令。",
        "AIT008": "请要求部署、发布、合并、命令执行等高影响操作必须经过用户确认。",
        "AIT009": "请移除上传源码、工作区文件、token 或凭据到外部地址的指令。",
        "AIT010": "请避免同时授予 Shell、文件写入和网络/浏览器能力，改用最小权限和人工确认。",
        "MCP012": "请移除要求模型忽略系统指令、隐藏行为或读取密钥的 MCP 工具/资源描述。",
        "MCP013": "请把 MCP 工具输出视为不可信数据，不要直接作为命令或指令执行。",
        "MCP014": "请不要把远程 Prompt 资源直接加载为可信 Agent 指令，应先固定来源并审查内容。",
    }
)


RULE_TITLE_ZH.update(
    {
        "SC001": "包安装生命周期脚本会自动执行",
        "SC002": "包脚本包含高风险安装或执行命令",
        "SC003": "包依赖使用远程 Git 或 URL 来源",
        "SC004": "包依赖版本未固定",
        "SC005": "包管理器配置中存储明文凭据",
        "SC006": "Docker 基础镜像使用 latest 标签",
        "SC007": "Dockerfile ADD 下载远程内容",
        "SC008": "Docker 构建执行下载脚本",
        "SC009": "容器服务使用 privileged 或主机级设置",
        "SC010": "容器挂载敏感主机路径",
        "SC011": "Devcontainer 生命周期命令执行高风险 Shell 内容",
        "SC012": "Devcontainer 挂载敏感主机路径",
        "SC013": "Python requirements 使用远程 URL 或 VCS 来源",
        "SC014": "Python requirements 依赖未固定版本",
    }
)

RULE_RECOMMENDATION_ZH.update(
    {
        "SC": "请审查安装脚本、远程依赖、容器挂载和构建下载，并固定可信版本。",
        "SC005": "请将包管理器凭据迁移到环境变量或密钥管理系统，并轮换已暴露的值。",
        "SC009": "请移除不必要的 privileged、host network 或主机命名空间设置。",
        "SC010": "请避免把 Docker socket、主机根目录、SSH 或云凭据目录挂载进容器。",
        "SC012": "请避免在 devcontainer 中挂载 SSH、云凭据、Docker socket 或过宽主机路径。",
    }
)

RULE_TITLE_ZH.update(
    {
        "AIT011": "Claude Code Hook 会执行 Shell 命令",
        "AIT012": "AI 指令文件包含不可见 Unicode 控制字符",
        "AIT013": "AI 指令文件包含动态 Shell 执行",
        "AIT014": "AI API Base URL 指向非官方端点",
        "AIT015": "VS Code 打开文件夹时自动运行任务",
        "AIT016": "AI Skill 引用未固定或来自不可信来源",
        "AIT017": "Gemini CLI 配置包含不安全自动化设置",
        "SEC018": "发现 DeepSeek API Key",
        "SEC019": "发现 Groq API Key",
        "SEC020": "发现 xAI / Grok API Key",
        "SEC021": "发现 Perplexity API Key",
        "SEC022": "发现 OpenRouter API Key",
        "SEC023": "发现 Together AI API Key",
        "SEC024": "发现 Fireworks AI API Key",
        "SEC025": "发现 Mistral AI API Key",
        "SEC026": "发现 Cohere API Key",
        "SEC027": "发现 Replicate API Token",
        "SEC028": "发现 Azure OpenAI API Key",
        "SEC029": "发现 NVIDIA NIM / NGC API Key",
        "SEC030": "发现 Stability AI API Key",
        "SEC031": "发现 ElevenLabs API Key",
        "SEC032": "发现 Voyage AI API Key",
        "SEC033": "发现 Tavily API Key",
        "SEC034": "发现智谱 GLM / Z.ai API Key",
        "SEC035": "发现 Kimi / Moonshot API Key",
        "SEC036": "发现火山 Ark / 豆包 / Seedance API Key",
        "SEC037": "发现阿里百炼 / Qwen / DashScope API Key",
        "SEC038": "发现百度千帆 / 文心 ERNIE API Key",
        "SEC039": "发现腾讯混元密钥",
        "SEC040": "发现讯飞星火 API Key",
        "SEC041": "发现 MiniMax / 海螺 / Minmo API Key",
        "SEC042": "发现百川 AI API Key",
        "SEC043": "发现 01.AI / 零一万物 / Yi API Key",
        "SEC044": "发现阶跃星辰 StepFun API Key",
        "SEC045": "发现硅基流动 SiliconFlow API Key",
        "SEC046": "发现商汤日日新 SenseNova API Key",
        "SEC047": "发现 360 智脑 API Key",
        "SEC048": "发现 ModelScope API Token",
        "SEC049": "发现 Infini-AI API Key",
        "SEC050": "发现 Vidu / 生数科技 API Key",
        "SEC051": "发现可灵 Kling AI 密钥",
        "SEC052": "发现 OpenAI 兼容代理密钥",
        "SEC053": "发现 AI 服务 Access Key / Secret Key 成对凭据",
        "MCP015": "远程 MCP Server 缺少明显认证配置",
        "MCP016": "MCP stdio Server 缺少明显容器或沙箱隔离",
        "MCP017": "多个 MCP Server 声明了相同工具名",
        "MCP018": "MCP OAuth Redirect URI 使用通配或不安全值",
        "SH010": "包管理器下载后立即执行命令",
        "SC015": "binding.gyp 包含命令替换",
        "SC016": "setup.py 包含安装期可疑命令执行",
        "GHA012": "OIDC 云侧信任策略约束需要核验",
    }
)

RULE_DESCRIPTION_ZH.update(
    {
        "AIT011": "Claude Code Hook 配置会在 Agent 事件中自动执行 Shell 命令。",
        "AIT012": "AI 指令文件包含零宽字符或双向控制字符，可能隐藏审查者看不见的指令。",
        "AIT013": "AI 指令或 Skill 文件包含预处理 Shell 命令，或授予 Bash(*) 这类过宽命令权限。",
        "AIT014": "AI API Base URL 被改写到非官方端点，可能把提示词、模型流量或凭据转发给第三方。",
        "AIT015": "VS Code tasks.json 配置可能在打开项目文件夹时自动执行命令。",
        "AIT016": "AI Skill 或命令引用使用可变版本、外部注册表或不可信来源。",
        "AIT017": "Gemini CLI 相关配置可能启用宽泛自动化，或关闭确认、沙箱等安全控制。",
        "SEC018": "文件中存在疑似 DeepSeek API Key 或服务商上下文中的明文凭据。",
        "SEC019": "文件中存在疑似 Groq API Key 或服务商上下文中的明文凭据。",
        "SEC020": "文件中存在疑似 xAI / Grok API Key 或服务商上下文中的明文凭据。",
        "SEC021": "文件中存在疑似 Perplexity API Key 或服务商上下文中的明文凭据。",
        "SEC022": "文件中存在疑似 OpenRouter API Key 或服务商上下文中的明文凭据。",
        "SEC023": "文件中存在疑似 Together AI API Key 或服务商上下文中的明文凭据。",
        "SEC024": "文件中存在疑似 Fireworks AI API Key 或服务商上下文中的明文凭据。",
        "SEC025": "文件中存在疑似 Mistral AI API Key 或服务商上下文中的明文凭据。",
        "SEC026": "文件中存在疑似 Cohere API Key 或服务商上下文中的明文凭据。",
        "SEC027": "文件中存在疑似 Replicate API Token 或服务商上下文中的明文凭据。",
        "SEC028": "文件中存在疑似 Azure OpenAI API Key 或服务商上下文中的明文凭据。",
        "SEC029": "文件中存在疑似 NVIDIA NIM / NGC API Key 或服务商上下文中的明文凭据。",
        "SEC030": "文件中存在疑似 Stability AI API Key 或服务商上下文中的明文凭据。",
        "SEC031": "文件中存在疑似 ElevenLabs API Key 或服务商上下文中的明文凭据。",
        "SEC032": "文件中存在疑似 Voyage AI API Key 或服务商上下文中的明文凭据。",
        "SEC033": "文件中存在疑似 Tavily API Key 或服务商上下文中的明文凭据。",
        "SEC034": "文件中存在疑似智谱 GLM / Z.ai API Key 或服务商上下文中的明文凭据。",
        "SEC035": "文件中存在疑似 Kimi / Moonshot API Key 或服务商上下文中的明文凭据。",
        "SEC036": "文件中存在疑似火山 Ark、豆包、Seedance 或 Seedream API Key。",
        "SEC037": "文件中存在疑似阿里百炼、Qwen 或 DashScope API Key。",
        "SEC038": "文件中存在疑似百度千帆或文心 ERNIE API Key。",
        "SEC039": "文件中存在疑似腾讯混元或腾讯云 AI 服务凭据。",
        "SEC040": "文件中存在疑似讯飞星火 API Key、Secret 或服务商上下文凭据。",
        "SEC041": "文件中存在疑似 MiniMax、海螺或 Minmo API Key。",
        "SEC042": "文件中存在疑似百川 AI API Key 或服务商上下文凭据。",
        "SEC043": "文件中存在疑似 01.AI、零一万物或 Yi API Key。",
        "SEC044": "文件中存在疑似阶跃星辰 StepFun API Key。",
        "SEC045": "文件中存在疑似硅基流动 SiliconFlow API Key。",
        "SEC046": "文件中存在疑似商汤日日新 SenseNova API Key 或 Access Key。",
        "SEC047": "文件中存在疑似 360 智脑 API Key。",
        "SEC048": "文件中存在疑似 ModelScope API Token。",
        "SEC049": "文件中存在疑似 Infini-AI API Key。",
        "SEC050": "文件中存在疑似 Vidu / 生数科技 API Key。",
        "SEC051": "文件中存在疑似可灵 Kling AI Access Key、Secret Key 或 API Key。",
        "SEC052": "文件中存在 OpenAI 兼容 API Key，并伴随非 OpenAI 服务商 Base URL 或代理上下文。",
        "SEC053": "文件中存在 AI 或云 AI 服务的 Access Key 与 Secret Key 成对凭据。",
        "MCP015": "远程 MCP Server 配置未包含明显的 OAuth、Authorization、Token、API Key 或认证请求头。",
        "MCP016": "MCP stdio Server 运行本地命令，但配置中缺少明显容器、沙箱或隔离边界。",
        "MCP017": "多个 MCP Server 声明了相同工具名，可能造成工具路由混淆或工具名冒充。",
        "MCP018": "MCP OAuth Redirect URI 使用通配符、过宽主机或不安全跳转值。",
        "SH010": "脚本使用 npx、npm create、pnpm dlx 等包管理器命令下载后立即执行代码。",
        "SC015": "binding.gyp 中的命令替换可能在原生包构建或安装阶段执行命令。",
        "SC016": "setup.py 可能在包安装阶段执行 Shell、subprocess、下载代码或解码载荷。",
        "GHA012": "工作流为云认证授予 id-token: write，但仓库侧 YAML 无法证明云侧 subject、audience 等信任约束足够严格。",
    }
)

RULE_RECOMMENDATION_ZH.update(
    {
        "AIT011": "请审查 Claude Code hooks，除非严格必要，否则移除项目级 Shell Hook，并要求外部命令执行前人工确认。",
        "AIT012": "请移除不可见 Unicode 控制字符，并用可审查的明文指令替代隐藏内容。",
        "AIT013": "请移除 AI 指令文件中的动态 Shell 执行，避免 Bash(*) 这类过宽工具授权。",
        "AIT014": "请核验 AI API Base URL 覆盖配置，优先使用官方端点，并显式记录已批准的企业网关。",
        "AIT015": "请禁用文件夹打开时自动运行的任务，或将其限制为明确、可审查且需要确认的命令。",
        "AIT016": "请将 AI Skill 或命令引用固定到可信版本、提交哈希或本地审查过的来源。",
        "AIT017": "请关闭 Gemini CLI 中的宽泛自动化、自动批准或沙箱绕过设置。",
        "MCP015": "请为远程 MCP Server 启用认证，优先使用 OAuth 2.1 + PKCE 或源码外管理的受限 Token。",
        "MCP016": "请尽可能在容器或沙箱中运行 stdio MCP Server，并限制文件系统和网络访问。",
        "MCP017": "请重命名工具或拆分 Server 配置，确保每个 MCP 工具名唯一且归属清晰。",
        "MCP018": "请将 OAuth Redirect URI 限制到明确、可信、最小范围的回调地址。",
        "SH010": "请避免在自动化脚本中直接执行临时下载的包，改为固定版本、审查来源并使用锁文件。",
        "SC015": "请移除 binding.gyp 中的命令替换，改用已审查并提交的静态构建配置。",
        "SC016": "请避免在 setup.py 中执行任意命令，将构建逻辑移到可审查脚本并保持安装过程确定性。",
        "GHA012": "请核验云 IAM 信任策略是否限制 subject、audience、仓库、分支、环境和工作流。",
    }
)



REMEDIATION_SUMMARY_ZH = {
    "AIT": "降低 AI 编程工具的自动化权限和文件系统访问范围。",
    "AIT006": "移除 AI 工具规则文件中的不安全指令。",
    "AIT007": "移除不安全的持久化记忆或规则指令。",
    "AIT008": "要求用户审核高影响的自主 Agent 操作。",
    "AIT009": "移除允许数据外传的指令。",
    "AIT010": "避免在缺少审批门禁时同时授予 Shell、文件写入和网络访问能力。",
    "GHA": "加固 GitHub Actions 工作流权限和执行路径。",
    "GHA007": "避免将不可信 GitHub 事件数据直接插入 Shell 命令。",
    "GHA008": "限制 OIDC Token 权限和云端信任策略。",
    "GHA009": "避免信任来自不可信工作流上下文的 Cache 或 Artifact 内容。",
    "GHA010": "执行 Artifact 或 Cache 内容前先校验完整性和来源。",
    "GHA011": "加固处理 Artifact 的 workflow_run 流水线。",
    "MCP001": "将 MCP 文件系统访问限制到明确的项目目录。",
    "MCP002": "审查并限制具备 Shell 能力的 MCP Server 命令。",
    "MCP003": "移除 MCP 环境设置中的明文密钥。",
    "MCP004": "启用远程 MCP Server 前进行所有者和数据暴露审查。",
    "MCP005": "移除危险的 MCP 权限参数。",
    "MCP006": "为远程 MCP Server 使用加密传输。",
    "MCP007": "审查指向私有网络或 metadata 服务的 MCP 端点。",
    "MCP008": "用明确的最小权限 scope 替代宽泛 scope。",
    "MCP009": "避免将主机上的广泛凭据转发给 MCP Server。",
    "MCP010": "移除 MCP 文件系统访问中的敏感本地路径。",
    "MCP011": "将 MCP 可写文件系统访问限制到明确子目录。",
    "MCP012": "移除 MCP 工具和资源描述中的不安全指令。",
    "MCP013": "将 MCP 工具输出视为不可信数据，而不是可执行指令。",
    "MCP014": "不要把远程 Prompt 内容加载为可信 Agent 指令。",
    "SC": "加固供应链配置，并固定可信输入。",
    "SC005": "从配置文件中移除包管理器凭据。",
    "SC009": "避免 privileged 或主机级容器设置。",
    "SC010": "避免将敏感主机路径挂载进容器。",
    "SC012": "避免在 devcontainer 中挂载敏感主机路径。",
    "SEC": "移除文件中的明文凭据，并轮换已暴露的值。",
    "SH": "用可审查、最小权限的命令替换危险 Shell 模式。",
}

REMEDIATION_STEPS_ZH = {
    "AIT": [
        "关闭宽泛的自动批准和权限绕过设置。",
        "将工作区访问限制到当前项目目录。",
        "Shell 命令、文件修改和网络访问前要求用户确认。",
    ],
    "AIT006": [
        "删除绕过安全控制、审批或权限检查的指令。",
        "移除请求密钥、私钥、凭据或系统提示的指令。",
        "保持项目指令最小、可审查，并符合最小权限原则。",
    ],
    "AIT007": [
        "删除会持久化审批绕过、密钥访问或隐藏行为的记忆项。",
        "在使用不可信仓库或 Prompt 后审查 Agent 记忆文件。",
        "将长期项目规则保持为明确、最小且经过版本审查的内容。",
    ],
    "AIT008": [
        "移除要求 Agent 未经确认就部署、发布、合并或执行命令的指令。",
        "对长时间运行任务和外部副作用要求显式确认。",
        "将自动化限制到范围明确、可回滚的任务。",
    ],
    "AIT009": [
        "删除上传仓库、工作区文件、token 或凭据的指令。",
        "必要的遥测或上传应走经过审查和记录的目标。",
        "外部 webhook 和回调地址应默认视为不可信，除非明确批准。",
    ],
    "AIT010": [
        "将高风险工具拆分为需要单独审批的权限。",
        "Shell、文件写入、浏览器或网络操作前要求人工确认。",
        "使用最小权限 allowlist，避免授予 all-tools 类权限。",
    ],
    "GHA": [
        "使用最小权限的 workflow permissions。",
        "将第三方 Action 固定到完整提交 SHA。",
        "避免让不可信代码在高权限事件或自托管 Runner 上运行。",
    ],
    "GHA007": [
        "将不可信表达式移动到环境变量。",
        "在 Shell 命令中使用前对值进行引用和校验。",
        "避免执行由 PR 标题、正文、评论或分支名派生的命令。",
    ],
    "GHA008": [
        "仅向确实需要云联合身份的 Job 授予 id-token: write。",
        "检查云角色信任策略是否限制仓库、分支、工作流、subject 和 audience。",
        "避免将宽泛仓库写权限与 OIDC 部署权限组合使用。",
    ],
    "GHA009": [
        "为可信和不可信事件使用独立 cache key。",
        "避免在 fork PR 工作流中恢复高权限 cache。",
        "下载的 artifact 在校验前都应视为不可信输入。",
    ],
    "GHA010": [
        "不要在没有完整性校验的情况下执行 artifact 或 cache 中的文件。",
        "执行前校验 checksum、来源和预期文件路径。",
        "除非确实需要写权限，否则 artifact 处理 Job 应保持只读。",
    ],
    "GHA011": [
        "假设上游 workflow 产物可能由攻击者控制。",
        "在高权限 Job 中使用 artifact 前校验来源和内容。",
        "除非部署或发布明确需要写权限，否则 workflow_run 权限应保持只读。",
    ],
    "MCP001": [
        "将 root、home 或磁盘级路径替换为项目专用目录。",
        "仅保留 MCP Server 必须读取或写入的目录。",
        "重新运行扫描器，确认过宽路径已移除。",
    ],
    "MCP002": [
        "确认该 MCP Server 是否确实需要 Shell 执行能力。",
        "尽可能用专用可执行程序替代宽泛 Shell 命令。",
        "对命令执行路径要求人工确认。",
    ],
    "MCP003": [
        "用本地环境变量引用替代明文 env 值。",
        "轮换所有已暴露的凭据。",
        "只记录所需环境变量名称，不提交具体值。",
    ],
    "MCP004": [
        "确认远程 Server 的所有者和传输安全。",
        "记录哪些数据可能被发送到远程 Server。",
        "敏感仓库优先使用本地 MCP Server。",
    ],
    "MCP005": [
        "移除 --allow-all、--no-sandbox 等不安全参数。",
        "只授予 MCP Server 必需的最小权限。",
        "对高风险操作使用项目本地路径和人工审批。",
    ],
    "MCP006": [
        "将明文 HTTP 端点替换为 HTTPS 或可信本地传输。",
        "验证远程 Server 所有者和证书配置。",
        "避免通过未加密传输发送工具上下文或凭据。",
    ],
    "MCP007": [
        "确认 MCP Server 是否确实需要访问 localhost、私有网络或 metadata 服务。",
        "除非明确需要，否则阻断云 metadata 地址和内部网络。",
        "为远程 MCP Server 使用 allowlist 和网络出口控制。",
    ],
    "MCP008": [
        "移除 wildcard、admin 或 full-access scope。",
        "只列出 MCP Server 必需的工具、资源和操作。",
        "缩小 scope 后重新运行扫描器确认结果。",
    ],
    "MCP009": [
        "用 Server 专用的受限 token 替代主机凭据透传。",
        "限制暴露给每个 MCP Server 的环境变量和请求头。",
        "轮换可能暴露给不可信 MCP Server 的凭据。",
    ],
    "MCP010": [
        "移除 .ssh、.aws、.env、浏览器 profile 和云凭据目录等路径。",
        "只暴露 MCP Server 必需的项目目录。",
        "使用独立受限凭据，不要授予主机凭据存储访问权。",
    ],
    "MCP011": [
        "除非确实需要，否则关闭 MCP 写权限。",
        "将 root、home 或磁盘级可写路径替换为项目专用子目录。",
        "写入型 MCP 工具修改文件前要求用户批准。",
    ],
    "MCP012": [
        "删除要求模型忽略系统/开发者指令或隐藏行为的描述。",
        "移除读取或传输 secret、token、私钥、环境文件的要求。",
        "启用第三方 MCP Server 前审查其元数据。",
    ],
    "MCP013": [
        "移除要求 Agent 执行工具输出或返回命令的指令。",
        "在传给 Shell、解释器或自动化前校验并引用工具输出。",
        "对远程工具建议的命令要求用户批准。",
    ],
    "MCP014": [
        "将外部 Prompt 资源视为不可信内容。",
        "固定并审查会影响 Agent 行为的 Prompt 模板。",
        "除非具备完整性和所有者检查，否则避免为高权限工具使用远程 Prompt URL。",
    ],
    "SC": [
        "审查 install hook、远程依赖来源、容器挂载和构建期下载。",
        "将依赖版本和容器镜像固定到已审查版本或 digest。",
        "将包管理器凭据迁移到环境变量或密钥管理系统。",
    ],
    "SC005": [
        "将 npm、PyPI 或 netrc 凭据迁移到环境变量或密钥管理系统。",
        "轮换已暴露的包仓库凭据。",
        "避免提交包含明文认证值的包管理器配置文件。",
    ],
    "SC009": [
        "除非明确需要，否则移除 privileged 模式和 host namespace/network 设置。",
        "以最小权限和限定 capability 运行容器。",
        "对需要高权限的开发容器做隔离。",
    ],
    "SC010": [
        "移除 Docker socket、主机根目录、SSH、云凭据和过宽 home 目录挂载。",
        "只挂载服务必需的项目本地目录。",
        "使用受限凭据，不要共享主机凭据存储。",
    ],
    "SC012": [
        "从 devcontainer 设置中移除 SSH、云凭据、Docker socket 或过宽主机挂载。",
        "使用项目专用凭据和明确挂载路径。",
        "贡献者使用前审查 devcontainer 生命周期命令。",
    ],
    "SEC": [
        "将凭据迁移到环境变量或密钥管理系统。",
        "在服务提供商控制台轮换已暴露的凭据。",
        "如果明文值已提交，清理源码历史中的敏感内容。",
    ],
    "SH": [
        "避免将下载内容直接通过管道交给 Shell 执行。",
        "避免宽泛破坏性命令和不透明的编码执行。",
        "使用明确路径、完整性校验和经过审查的脚本。",
    ],
}
REMEDIATION_SUMMARY_ZH.update(
    {
        "AIT011": "限制 Claude Code Hook 的自动命令执行。",
        "AIT012": "移除 AI 指令文件中的隐藏 Unicode 控制字符。",
        "AIT013": "移除 AI 指令中的动态 Shell 执行和过宽 Bash 授权。",
        "AIT014": "核验 AI API Base URL 覆盖和代理端点。",
        "AIT015": "禁用打开项目时自动运行的 VS Code 任务。",
        "AIT016": "固定 AI Skill 或命令引用来源。",
        "AIT017": "关闭 Gemini CLI 的不安全自动化设置。",
        "MCP015": "为远程 MCP Server 配置明确认证。",
        "MCP016": "为 stdio MCP Server 增加隔离边界。",
        "MCP017": "消除 MCP 工具名冲突。",
        "MCP018": "收紧 MCP OAuth Redirect URI。",
        "SH010": "固定并审查包管理器即时执行命令。",
        "SC015": "移除 binding.gyp 构建期命令替换。",
        "SC016": "移除 setup.py 安装期可疑命令执行。",
        "GHA012": "核验 GitHub OIDC 对应的云侧信任策略约束。",
    }
)

REMEDIATION_STEPS_ZH.update(
    {
        "AIT011": [
            "审查 `.claude/settings.json` 等项目级 Hook 配置。",
            "移除会自动执行 Shell 的 Hook，或将其改为需要人工确认的安全流程。",
            "对确需保留的命令限制参数、工作目录和网络访问范围。",
        ],
        "AIT012": [
            "删除零宽字符和双向 Unicode 控制字符。",
            "用普通可见文本重新表达项目指令。",
            "在代码评审中开启隐藏字符显示或文本扫描检查。",
        ],
        "AIT013": [
            "删除 `!\\`command\\`` 这类预处理 Shell 执行内容。",
            "避免使用 `Bash(*)` 或等价的全量 Shell 工具授权。",
            "将必要命令拆分为固定、可审查、需要确认的步骤。",
        ],
        "AIT014": [
            "确认 Base URL 是否为官方端点或已批准的企业代理。",
            "移除未记录、未知或第三方代理端点。",
            "避免把模型请求、提示词或凭据发送到未经批准的服务。",
        ],
        "AIT015": [
            "移除 `runOptions.runOn: folderOpen` 等自动运行配置。",
            "将初始化命令改为手动触发，并保留可审查脚本。",
            "对确需自动化的任务限制命令内容和权限。",
        ],
        "AIT016": [
            "将外部 Skill 或命令引用固定到明确版本或提交哈希。",
            "优先使用仓库内已审查的本地 Skill。",
            "启用第三方 Skill 前审查发布者和权限说明。",
        ],
        "AIT017": [
            "关闭自动批准、绕过确认或禁用沙箱的配置。",
            "把 Gemini CLI 的文件、命令和网络能力限制到最小必要范围。",
            "对高风险操作保留人工确认。",
        ],
        "MCP015": [
            "为远程 MCP Server 添加 OAuth、Authorization Header 或受限 Token。",
            "不要把认证值写入源码，改用环境变量或密钥管理系统。",
            "记录远程 Server 所有者、数据暴露范围和认证方式。",
        ],
        "MCP016": [
            "优先在容器、沙箱或受限用户下运行 stdio MCP Server。",
            "限制该进程可访问的文件系统路径和网络出口。",
            "对高风险本地命令启用人工确认或禁用。",
        ],
        "MCP017": [
            "检查所有 MCP Server 声明的工具名。",
            "为重复工具重命名，或拆分配置使归属清晰。",
            "避免让不可信 Server 使用与可信工具相同的名称。",
        ],
        "MCP018": [
            "移除通配符、过宽域名或不可信 Redirect URI。",
            "只保留明确的 HTTPS 回调地址或受控本地回调。",
            "核验 OAuth 客户端配置与 MCP Server 所有者一致。",
        ],
        "SH010": [
            "避免在脚本中直接使用 `npx -y`、`npm create`、`pnpm dlx` 执行未知包。",
            "固定包版本并审查包来源、维护者和安装脚本。",
            "在 CI 或自动化中使用锁文件和可复现安装流程。",
        ],
        "SC015": [
            "删除 binding.gyp 中的 `<!(...)` 或类似命令替换。",
            "将构建参数改为静态、已审查的配置。",
            "重新构建并确认安装阶段不会执行额外命令。",
        ],
        "SC016": [
            "移除 setup.py 中的 shell、subprocess、下载执行或解码执行逻辑。",
            "把必要构建逻辑迁移到独立、可审查的脚本。",
            "保持包安装过程确定、可复现且无隐藏副作用。",
        ],
        "GHA012": [
            "检查云 IAM 信任策略是否限制仓库、分支、环境、workflow 和 subject。",
            "确认 audience 只允许预期的 GitHub OIDC 使用方。",
            "避免将宽泛仓库写权限与云部署 OIDC 权限组合使用。",
        ],
    }
)

DEFAULT_REMEDIATION_STEPS_ZH = [
    "复核该发现，确认相关行为是否为预期配置。",
    "优先采用最小权限或最小配置变更完成修复。",
    "重新运行 agent-scan，确认问题已解决，或在配置中附带原因显式忽略。",
]


def normalize_language(value: object | None, default: Language = Language.EN) -> Language:
    if isinstance(value, Language):
        return value
    if value is None:
        return default
    try:
        return Language(str(value).strip().lower())
    except ValueError:
        return default


def resolve_language(cli_language: Language | None, config_language: Language | None = None) -> Language:
    return cli_language or config_language or Language.EN


def other_language(language: Language) -> Language:
    return Language.ZH if language == Language.EN else Language.EN


def t(key: str, language: Language) -> str:
    values = TRANSLATIONS.get(key)
    if not values:
        return key
    return values.get(language, values[Language.EN])


def severity_label(value: str, language: Language) -> str:
    return SEVERITY_ZH.get(value, value) if language == Language.ZH else value


def category_label(value: str, language: Language) -> str:
    return CATEGORY_ZH.get(value, value) if language == Language.ZH else value


def effort_label(value: str, language: Language) -> str:
    return EFFORT_ZH.get(value, value) if language == Language.ZH else value


def report_label(value: str, language: Language) -> str:
    return REPORT_LABELS_ZH.get(value, value) if language == Language.ZH else value


def rule_title(rule_id: str, fallback: str, language: Language) -> str:
    return RULE_TITLE_ZH.get(rule_id, fallback) if language == Language.ZH else fallback


def rule_description(rule_id: str, fallback: str, language: Language) -> str:
    if language != Language.ZH:
        return fallback
    return RULE_DESCRIPTION_ZH.get(rule_id, RULE_DESCRIPTION_ZH_BY_PREFIX.get(rule_prefix(rule_id), fallback))


def rule_recommendation(rule_id: str, fallback: str, language: Language) -> str:
    if language != Language.ZH:
        return fallback
    prefix = rule_prefix(rule_id)
    return RULE_RECOMMENDATION_ZH.get(rule_id, RULE_RECOMMENDATION_ZH.get(prefix, fallback))


def remediation_summary(rule_id: str, fallback: str, language: Language) -> str:
    if language != Language.ZH:
        return fallback
    prefix = rule_prefix(rule_id)
    return REMEDIATION_SUMMARY_ZH.get(rule_id, REMEDIATION_SUMMARY_ZH.get(prefix, fallback))


def remediation_steps(rule_id: str, fallback: list[str], language: Language) -> list[str]:
    if language != Language.ZH:
        return fallback
    prefix = rule_prefix(rule_id)
    return REMEDIATION_STEPS_ZH.get(rule_id, REMEDIATION_STEPS_ZH.get(prefix, DEFAULT_REMEDIATION_STEPS_ZH))

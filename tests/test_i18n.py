from agent_security_scanner.i18n import Language, rule_description, rule_title
from agent_security_scanner.rules_catalog import RULE_CATALOG


def test_all_rules_have_chinese_titles_without_english_fallback():
    missing = [
        rule.rule_id
        for rule in RULE_CATALOG
        if rule_title(rule.rule_id, rule.title, Language.ZH) == rule.title
    ]

    assert missing == []


def test_new_rule_descriptions_are_localized():
    expected = {
        "AIT011": "Claude Code Hook 配置会在 Agent 事件中自动执行 Shell 命令。",
        "SEC034": "文件中存在疑似智谱 GLM / Z.ai API Key 或服务商上下文中的明文凭据。",
        "MCP015": "远程 MCP Server 配置未包含明显的 OAuth、Authorization、Token、API Key 或认证请求头。",
        "SH010": "脚本使用 npx、npm create、pnpm dlx 等包管理器命令下载后立即执行代码。",
        "SC015": "binding.gyp 中的命令替换可能在原生包构建或安装阶段执行命令。",
        "GHA012": "工作流为云认证授予 id-token: write，但仓库侧 YAML 无法证明云侧 subject、audience 等信任约束足够严格。",
    }

    rules = {rule.rule_id: rule for rule in RULE_CATALOG}
    for rule_id, zh_description in expected.items():
        rule = rules[rule_id]
        assert rule_description(rule.rule_id, rule.description, Language.ZH) == zh_description

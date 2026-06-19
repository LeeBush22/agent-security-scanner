from agent_security_scanner.i18n import Language
from agent_security_scanner.rules_catalog import RULE_CATALOG
from agent_security_scanner.rules_docs import render_rules_markdown


def test_render_rules_markdown_contains_catalog_rules():
    rendered = render_rules_markdown(Language.EN)

    assert "# Agent Security Scanner Rules" in rendered
    assert f"Total built-in rules: **{len(RULE_CATALOG)}**" in rendered
    assert "| SEC001 |" not in rendered
    assert "[SEC001]" in rendered
    assert "SC014" in rendered


def test_render_rules_markdown_can_be_chinese():
    rendered = render_rules_markdown(Language.ZH)

    assert "# Agent Security Scanner 规则索引" in rendered
    assert "内置规则总数" in rendered
    assert "SEC001" in rendered
    assert "发现 DeepSeek API Key" in rendered
    assert "远程 MCP Server 缺少明显认证配置" in rendered
    assert "binding.gyp 中的命令替换可能在原生包构建或安装阶段执行命令" in rendered
    assert '<a id="sec018-deepseek-api-key-detected"></a>' in rendered
    assert "DeepSeek API key detected" not in rendered

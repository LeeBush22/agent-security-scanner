# Launch Kit

Use this file when publishing Agent Security Scanner V1.0.3 on GitHub, social platforms, newsletters, or security communities.

## GitHub Release Title

Agent Security Scanner V1.0.3 - Release maturity, full PDF reports, and fix previews

## GitHub Release Summary

Agent Security Scanner V1.0.3 focuses on release maturity and functional gap fixes for the local-first AI Agent, MCP, and AI coding tool security scanner.

Highlights:

- Added project CI for Python 3.10, 3.11, and 3.12.
- Added coverage, mypy, and nox configuration.
- Added CHANGELOG.md and CONTRIBUTING.md.
- Removed the previous PDF 80-finding display cap; PDF reports now include all findings through normal pagination.
- Added filesystem rules for sensitive local files, sensitive host paths, and broad permission commands.
- Added `agent-scan fix` as a safe autofix preview command. It prints patch-style suggestions and does not modify files by default.
- Local-first scanning remains the default: no source code, secrets, prompts, or reports are uploaded.

## Short Announcement

I just released Agent Security Scanner V1.0.3.

This release strengthens the project for open-source use: CI, coverage, mypy, nox, CHANGELOG, and CONTRIBUTING are now included. It also fixes functional gaps from the previous release by removing the PDF 80-finding cap, adding filesystem risk rules, and introducing a safe autofix preview command.

Repo: https://github.com/LeeBush22/agent-security-scanner

Install:

```bash
python -m pip install --upgrade agentsec-scanner
```

Try:

```bash
agent-scan .
agent-scan . --format all
agent-scan fix .
agent-scan rules --category filesystem
```

## Chinese Announcement

我发布了 Agent Security Scanner V1.0.3。

这个版本主要补齐发布成熟度和功能缺口：新增项目自身 CI、coverage、mypy、nox、CHANGELOG 和 CONTRIBUTING；PDF 报告不再限制只展示前 80 条发现；新增文件系统风险规则；新增 `agent-scan fix` 安全修复预览命令，默认只展示补丁式建议，不会自动修改用户文件。

仓库地址：https://github.com/LeeBush22/agent-security-scanner

安装命令：

```bash
python -m pip install --upgrade agentsec-scanner
```

## README Star Checklist

- [ ] Keep the preview image visible in the first screen.
- [ ] Put the install and first scan command above detailed documentation.
- [ ] Keep the rule count badge updated.
- [ ] Keep examples obviously fake and safe.
- [ ] Include at least one screenshot or terminal preview in the GitHub repository media.
- [ ] Pin a GitHub issue for roadmap feedback.
- [ ] Add GitHub topics: `ai-agent`, `mcp`, `security`, `scanner`, `secrets`, `github-actions`, `sarif`, `llm`, `developer-tools`.

## Suggested Repository Topics

```text
ai-agent
mcp
security
scanner
secrets
github-actions
sarif
llm
developer-tools
cli
python
devsecops
```

## Demo Commands

```bash
agent-scan .
agent-scan . --format all
agent-scan . --lang zh
agent-scan rules --category mcp
agent-scan rules --category filesystem
agent-scan fix .
agent-scan . --format sarif --fail-on high
```

## Positioning

Agent Security Scanner is not a generic vulnerability scanner and not a replacement for mature SAST, dependency, or cloud security tooling. It is a focused local-first scanner for the AI Agent and AI coding tool layer: local permissions, MCP configuration, tool instructions, hooks, credentials, shell commands, workflow automation, filesystem exposure, and release-time reports.

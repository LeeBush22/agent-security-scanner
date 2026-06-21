# Launch Kit

Use this file when publishing Agent Security Scanner V1.0.2 on GitHub, social platforms, newsletters, or security communities.

## GitHub Release Title

Agent Security Scanner V1.0.2 - Progress feedback and timestamped reports

## GitHub Release Summary

Agent Security Scanner V1.0.2 improves the interactive CLI experience and report output behavior. Long-running scan and report actions now show visible status messages, report generation can reuse the last matching scan result, and default report files are grouped by project and timestamp with names like `my-project_20260621_153000_en.pdf`.

Highlights:

- Options 1, 2, 3, and 4 in interactive mode now show clear scan/report progress.
- Report generation reuses the last matching scan result when possible.
- Default Markdown, Excel, PDF, JSON, and SARIF reports are grouped under `output/<project>/<timestamp>/`.
- Human-readable report names use `project_timestamp_language.format`.
- Consecutive report runs no longer overwrite each other.
- Explicit file output remains compatible, and standalone SARIF still defaults to `output/machine/agent-scan.sarif`.
- Local-first scanning: no source code, secrets, prompts, or reports are uploaded.
- Broad AI provider API key coverage for global and Chinese providers.
- MCP, AI coding tool, GitHub Actions, shell, and supply-chain checks remain included.

## Short Announcement

I just released Agent Security Scanner V1.0.2: a usability-focused update for the local-first CLI scanner for AI Agent, MCP, and AI coding tool projects.

This release adds visible progress feedback for longer interactive scans and report generation. Reports now use project and timestamp based output directories, so scanning multiple projects in one session creates clean, separate report sets instead of overwriting `report.*` files.

Repo: https://github.com/LeeBush22/agent-security-scanner

Install:

```bash
python -m pip install --upgrade agentsec-scanner
```

## Chinese Announcement

我发布了 Agent Security Scanner V1.0.2：这是一次面向交互体验和报告输出的更新。

本次更新为交互式菜单中的扫描和报告生成增加了明确的等待提示，避免长时间任务看起来像卡死。默认报告输出也改为按项目名和时间戳分组，文件名格式为 `项目名_时间戳_语言.格式`，连续扫描多个项目时不会互相覆盖。

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
agent-scan . --format sarif --fail-on high
```

## Positioning

Agent Security Scanner is not a generic vulnerability scanner and not a replacement for mature SAST, dependency, or cloud security tooling. It is a focused local-first scanner for the AI Agent and AI coding tool layer: local permissions, MCP configuration, tool instructions, hooks, credentials, shell commands, workflow automation, and release-time reports.

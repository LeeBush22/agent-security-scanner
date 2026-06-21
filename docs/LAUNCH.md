# Launch Kit

Use this file when publishing Agent Security Scanner V1.0.1 on GitHub, social platforms, newsletters, or security communities.

## GitHub Release Title

Agent Security Scanner V1.0.1 - Interactive report target fix

## GitHub Release Summary

Agent Security Scanner V1.0.1 fixes an interactive CLI report-target issue. After scanning another directory, report generation now defaults to the last scanned project directory, so generated Markdown, Excel, PDF, and SARIF reports match the scan result shown in the terminal.

Highlights:

- Local-first scanning: no source code, secrets, prompts, or reports are uploaded.
- Broad AI provider API key coverage for global and Chinese providers.
- MCP-specific checks for filesystem access, remote server authentication, stdio isolation, duplicate tool names, OAuth redirect risks, prompt injection, and unsafe tool descriptions.
- AI coding tool checks for Claude Code hooks, Cursor/Codex/Continue/Roo/Cline/Gemini CLI settings, unsafe instruction files, dynamic shell execution, invisible Unicode, and base URL overrides.
- GitHub Actions checks for permissions, unpinned actions, OIDC, artifact/cache trust paths, self-hosted runners, and risky event contexts.
- Output formats: terminal, JSON, SARIF, Markdown, Excel, and PDF.
- Bilingual English/Chinese reports and CLI output.
- Baseline mode and `--fail-on` for CI adoption.

## Short Announcement

I just released Agent Security Scanner V1.0.1: a bugfix release for the local-first CLI scanner for AI Agent, MCP, and AI coding tool projects.

This release fixes interactive report generation after scanning another directory. Options 3 and 4 now default to the last scanned project directory, keeping terminal scan results and generated reports aligned.

Repo: https://github.com/LeeBush22/agent-security-scanner

Install:

```bash
python -m pip install agentsec-scanner
```

## Chinese Announcement

我发布了 Agent Security Scanner V1.0.1：这是一个针对交互式 CLI 的修复版本。

本次修复了扫描其他目录后生成报告目标不一致的问题。现在选项 3 和选项 4 会默认使用上次扫描的项目目录，确保终端扫描结果和生成报告保持一致。

仓库地址：https://github.com/LeeBush22/agent-security-scanner

安装命令：

```bash
python -m pip install agentsec-scanner
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

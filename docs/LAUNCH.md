# Launch Kit

Use this file when publishing Agent Security Scanner V1.0.0 on GitHub, social platforms, newsletters, or security communities.

## GitHub Release Title

Agent Security Scanner V1.0.0 - Local-first security scanning for AI Agent, MCP, and AI coding tool projects

## GitHub Release Summary

Agent Security Scanner is a local-first CLI security scanner for AI Agent, MCP, and AI coding tool projects. V1.0.0 includes 126 built-in rules across secrets, MCP, AI coding tools, shell commands, GitHub Actions, and supply-chain configuration.

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

I just released Agent Security Scanner V1.0.0: a local-first CLI scanner for AI Agent, MCP, and AI coding tool projects.

It checks for risky tool permissions, plaintext AI provider keys, MCP config risks, suspicious shell commands, GitHub Actions automation risks, and supply-chain footguns. It outputs terminal, JSON, SARIF, Markdown, Excel, and PDF reports, with English and Chinese support.

Repo: https://github.com/LeeBush22/agent-security-scanner

Install:

```bash
python -m pip install agentsec-scanner
```

## Chinese Announcement

我发布了 Agent Security Scanner V1.0.0：一个本地优先的 AI Agent / MCP / AI 编程工具安全扫描器。

它可以扫描危险工具权限、明文 AI 服务商 API Key、MCP 配置风险、可疑 Shell 命令、GitHub Actions 自动化风险和供应链配置风险。支持终端、JSON、SARIF、Markdown、Excel、PDF 报告，并支持中英双语输出。

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

# Agent Security Scanner

**Current release: V1.0.0**

[中文说明](README_zh.md)

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Rules](https://img.shields.io/badge/rules-126-brightgreen)](docs/RULES.md)
[![Local first](https://img.shields.io/badge/local--first-no%20upload-success)](#why-agent-security-scanner)
[![Reports](https://img.shields.io/badge/reports-JSON%20%7C%20SARIF%20%7C%20Markdown%20%7C%20Excel%20%7C%20PDF-informational)](#output-formats)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)

`agent-security-scanner` is a local-first security scanner for AI Agent, MCP, and AI coding tool projects. It finds risky permissions, plaintext credentials, suspicious shell commands, broad filesystem access, GitHub Actions automation risks, and supply-chain footguns before they ship.

The scanner runs entirely on your machine. It does not upload source code, secrets, prompts, or scan results.

![Agent Security Scanner terminal preview](docs/assets/github-preview.svg)

## Why Agent Security Scanner

AI coding tools and Agent frameworks change the local security model: a project can now contain tool permissions, MCP servers, hooks, memory files, instruction files, workflow automation, and provider credentials that directly affect what an AI assistant can read, execute, or send elsewhere.

This project focuses on that new attack surface:

- **AI-native checks** for MCP, Claude Code, Cursor, Codex, Continue, Roo Code, Cline, Gemini CLI, AGENTS.md, CLAUDE.md, SKILL.md, and related local agent files.
- **Broad AI provider secret coverage** across OpenAI, Anthropic, DeepSeek, Kimi, Qwen/DashScope, Zhipu GLM, Doubao/Seedance, MiniMax, Baichuan, SiliconFlow, ModelScope, and many more.
- **Release-ready reporting** with terminal, JSON, SARIF, Markdown, Excel, and PDF outputs, including separate English, Chinese, and machine-readable directories.
- **CI-friendly controls** such as `--fail-on`, SARIF upload, generated rule docs, and baseline mode for existing repositories.

## 30-Second Start

Install from PyPI:

```bash
python -m pip install agentsec-scanner
```

Or install from this repository:

```bash
git clone https://github.com/LeeBush22/agent-security-scanner.git
cd agent-security-scanner
python -m pip install .
```

Scan the current project:

```bash
agent-scan .
```

Generate bilingual reports:

```bash
agent-scan . --format all
```

Use Chinese output:

```bash
agent-scan . --lang zh
```

## Rule Coverage At A Glance

| Surface | Rules | What it catches |
|---|---:|---|
| Secrets | 53 | AI provider keys, cloud keys, platform tokens, private keys, database URLs, JWTs, high-entropy credentials |
| MCP | 18 | Broad filesystem access, remote MCP auth gaps, stdio isolation gaps, tool-name conflicts, OAuth redirect risks |
| AI coding tools | 17 | Auto-approval, permission bypass, Claude hooks, dynamic shell instructions, base URL overrides, unsafe memory/rules |
| Supply chain | 16 | Install hooks, package credentials, remote dependencies, Docker/devcontainer risks, `binding.gyp`, `setup.py` |
| GitHub Actions | 12 | Broad permissions, unpinned actions, `pull_request_target`, OIDC, artifact/cache trust chains |
| Shell | 10 | `curl | bash`, destructive commands, reverse shells, encoded execution, package-manager immediate execution |

## Output Matrix

| Format | Best for | Path |
|---|---|---|
| Terminal | Local review | stdout |
| JSON | Automation and custom pipelines | `output/machine/report.json` |
| SARIF | GitHub Code Scanning and security platforms | `output/machine/agent-scan.sarif` |
| Markdown | PR comments and human-readable reports | `output/en/report.md`, `output/zh/report.md` |
| Excel | Audit triage and spreadsheet review | `output/en/report.xlsx`, `output/zh/report.xlsx` |
| PDF | Shareable audit-style reports | `output/en/report.pdf`, `output/zh/report.pdf` |

## How It Differs

| Tool type | Great at | Gap this project targets |
|---|---|---|
| Secret scanners | Finding generic committed credentials | AI-provider context, OpenAI-compatible proxy keys, MCP/agent config secrets |
| SAST tools | Code-level vulnerabilities | Local AI tool permissions, prompt/instruction files, hooks, MCP routing, workflow automation |
| CI linters | Workflow syntax and conventions | Security-specific GitHub Actions risks, OIDC review hints, artifact/cache trust paths |
| Container scanners | Images and dependencies | Source-side Docker/devcontainer settings that expose host paths or execute downloaded scripts |

Agent Security Scanner is not a replacement for mature SAST, dependency, or cloud security tooling. It is a focused local-first companion for the AI Agent and AI coding tool layer those tools often do not understand yet.

## What This Tool Scans

Agent Security Scanner scans a local project directory. It is not a host vulnerability scanner, web scanner, antivirus tool, or cloud security product. Its job is to read files inside the directory you point it at and report security risks that commonly appear in AI Agent, MCP, AI coding tool, and automation projects.

A project directory usually means the root folder of a software project, for example:

```text
my-agent-project/
├─ main.py
├─ requirements.txt
├─ .env
├─ mcp.json
├─ config.yaml
├─ .github/
│  └─ workflows/
│     └─ ci.yml
├─ scripts/
│  └─ install.sh
└─ README.md
```

You should point the scanner at the folder that contains your code, configuration, scripts, workflow files, and AI tool settings. The directory can be a Python project, JavaScript or TypeScript project, Java project, C/C++ project, AI Agent prototype, MCP server project, or a repository that contains GitHub Actions automation.

Typical directories you can scan:

```text
D:\Projects\my-agent-project
D:\Projects\python-service
D:\Projects\mcp-server
D:\Projects\frontend-app
D:\Projects\automation-repo
```

If your terminal is already inside the project root, scan the current directory:

```bash
agent-scan .
```

If the project is somewhere else, pass the full path:

```bash
agent-scan D:\Projects\my-agent-project
```

In interactive mode, "Scan current directory" means the directory where your terminal is currently located. For prompts that ask for a project directory, press Enter or type `.` to use the current directory. To scan another project, enter its full path.

The scanner checks files such as:

- Source code files
- `.env` files and local configuration files
- JSON, YAML, TOML, and INI files
- Shell, PowerShell, and batch scripts
- MCP configuration files
- Cursor, Claude Code, Codex, Continue, Roo Code, Cline, and similar AI coding tool settings
- GitHub Actions workflows under `.github/workflows/`
- Documentation that contains executable commands

It primarily looks for:

- Plaintext API keys, platform tokens, private keys, database URLs with passwords, JWT-like values, and high-entropy credential assignments
- Dangerous shell commands such as recursive force delete, `curl | bash`, PowerShell dynamic execution, encoded commands, reverse shells, destructive disk commands, disabled safety controls, and possible secret exfiltration
- MCP filesystem access that is broader than necessary
- MCP servers with dangerous arguments, embedded secrets, remote endpoints, plaintext HTTP transport, private-network or metadata endpoints, broad scopes, credential pass-through, sensitive local paths, broad writable filesystem access, unsafe tool/resource descriptions, tool-output-as-instruction patterns, or remote prompt injection
- GitHub Actions risks such as `pull_request_target`, unpinned actions, broad workflow/job permissions, untrusted expression injection, OIDC permission exposure, cache/artifact poisoning, `workflow_run` artifact promotion, secret echoing, script downloads, and self-hosted runners
- AI coding tool risks such as auto-approval, skipped permission checks, broad workspace access, shell-capable tools, embedded credentials, unsafe agent instruction files, memory/rule poisoning, excessive autonomy, data exfiltration instructions, and high-risk tool combinations
- Supply-chain risks such as package install scripts, remote dependency sources, package manager credentials, Docker build downloads, privileged containers, sensitive host mounts, devcontainer lifecycle commands, and unpinned requirements

You do not need to create a special empty folder for this scanner. Use it against real project source directories that you want to review before development, release, open-source publication, or CI deployment.

## Features

- CLI command: `agent-scan`
- Recursive file scanner with sensible ignored directories
- Secret detection for OpenAI, Anthropic, Gemini/Google, DeepSeek, Groq, xAI/Grok, Perplexity, OpenRouter, Together AI, Fireworks AI, Mistral, Cohere, Replicate, Azure OpenAI, NVIDIA NIM/NGC, Stability AI, ElevenLabs, Voyage AI, Tavily, Zhipu GLM, Kimi/Moonshot, Doubao/Seedance/Volcengine Ark, Qwen/DashScope/Bailian, Baidu Qianfan, Tencent Hunyuan, iFlytek Spark, MiniMax, Baichuan, 01.AI/Yi, StepFun, SiliconFlow, SenseNova, 360 Zhinao, ModelScope, Infini-AI, Vidu, Kling AI, OpenAI-compatible proxy keys, AK/SK key pairs, GitHub, AWS, Slack, Discord, Hugging Face, npm, PyPI, Stripe, Azure Storage, bearer tokens, JWTs, database URLs, generic high-entropy credentials, and private keys
- Provider-aware AI secret detection engine for adding API key rules by provider, aliases, variable names, domains, token prefixes, and context keywords
- MCP config checks for broad filesystem access, dangerous commands, remote servers, missing remote authentication, stdio servers without obvious isolation, duplicate tool names, unsafe OAuth redirect URIs, plaintext HTTP, private or metadata endpoints, broad scopes, credential pass-through, sensitive host paths, writable broad paths, tool/resource description poisoning, remote prompt injection, embedded secrets, and unsafe flags
- AI coding tool config checks for Cursor, Claude Code, Codex, Continue, Roo Code, Cline, Gemini CLI, AGENTS.md, CLAUDE.md, SKILL.md, memory/rule files, Cursor rules, GitHub Copilot instructions, Claude Code hooks, invisible Unicode instruction hiding, dynamic shell syntax, AI API base URL overrides, VS Code folder-open tasks, unpinned skill references, and similar local agent settings
- Shell command checks for destructive deletes, `curl | bash`, PowerShell dynamic execution, encoded commands, reverse shells, destructive disk commands, disabled safety controls, inline dynamic code, package-manager immediate execution, and possible exfiltration
- GitHub Actions checks for `pull_request_target`, unpinned actions, workflow/job permissions, expression injection, OIDC permission exposure, OIDC cloud trust policy verification hints, cache/artifact poisoning, `workflow_run`, secret echoing, script downloads, and self-hosted runners
- Supply-chain checks for `package.json`, package manager auth files, Dockerfile, Docker Compose, devcontainer, Python requirements, `binding.gyp` command substitution, and suspicious `setup.py` install-time command execution
- Polished responsive native terminal interactive CLI plus command-oriented subcommands
- English and Chinese CLI language switching
- Terminal, JSON, Markdown, SARIF, Excel, and PDF output
- Separate English, Chinese, and machine-readable report directories
- SARIF output for GitHub Code Scanning and compatible tools, with rule metadata, help URIs, severity, precision, and tags
- Generated rule documentation in `docs/RULES.md` and `docs/RULES_zh.md`
- Release quality checks for rule ID uniqueness, prefix/category consistency, metadata completeness, and registered scanner rules
- Example unsafe fixtures and pytest coverage

## Install

For local development:

```bash
python -m pip install -e ".[dev]"
```

On Windows paths that contain non-ASCII characters, editable installs can be affected by Python `.pth` decoding behavior in some environments. If that happens, use:

```bash
python -m pip install ".[dev]"
```

For runtime-only use:

```bash
python -m pip install .
```

Published package name:

```bash
python -m pip install agentsec-scanner
```

## Usage

Start the polished native terminal interactive CLI:

```bash
agent-scan
```

By default, interactive mode uses Rich-powered native terminal output: a branded header, responsive menu, colored tables, and clear section dividers. The branded header appears on startup, after `r` redraws the home menu, and after switching language; when other actions return to the main menu, only the compact interactive menu is shown. It uses normal terminal scrollback, so long rules, doctor results, and scan results remain available through your terminal history. On Windows PowerShell or Windows Terminal, use the window's native scrollbar or mouse wheel to review earlier content. The interface reads the current window width each time it draws; resize the window and type `r` to redraw the home menu, or run an action and return to a compact menu. Use number keys or commands to run an action, type `back`, `q`, `exit`, or `esc` to return from a sub-step, and type `q` or `exit` at the main menu to quit.

The shorter alias works too:

```bash
agentsec
```

Scan the current directory and print a Rich terminal table:

```bash
agent-scan .
```

Use the Chinese CLI:

```bash
agent-scan . --lang zh
agent-scan scan . --lang zh
```

The explicit subcommand form is also available:

```bash
agent-scan scan .
```

Write English and Chinese Markdown reports:

```bash
agent-scan --format markdown
```

This writes:

```text
output/en/report.md
output/zh/report.md
```

Write reports to a custom directory:

```bash
agent-scan --format markdown --output output
```

Print JSON:

```bash
agent-scan --format json
```

Write SARIF to `output/machine/agent-scan.sarif`:

```bash
agent-scan --format sarif
```

Write English and Chinese Excel or PDF reports:

```bash
agent-scan . --format excel
agent-scan . --format pdf
```

Write all report formats at once:

```bash
agent-scan . --format all
```

Show the welcome and quick-start screen:

```bash
agent-scan --welcome
```

Initialize a starter project configuration:

```bash
agent-scan init
```

Check local dependencies and output directory access:

```bash
agent-scan doctor
agent-scan doctor --lang zh
```

List built-in rules:

```bash
agent-scan rules
agent-scan rules --category mcp
agent-scan rules --category mcp --lang zh
```

Generate rule documentation:

```bash
agent-scan rules --format markdown --output docs/RULES.md
agent-scan rules --format markdown --output docs/RULES_zh.md --lang zh
```

List generated reports in `output/`:

```bash
agent-scan report
agent-scan report --lang zh
```

Scan with a minimum severity:

```bash
agent-scan . --severity high
```

Fail CI or pre-commit when findings at or above a severity exist:

```bash
agent-scan . --fail-on high
```

Create or refresh a baseline of current findings:

```bash
agent-scan . --update-baseline --baseline-output .agent-scan-baseline.json
```

Only report findings that are not already in the baseline:

```bash
agent-scan . --baseline .agent-scan-baseline.json --fail-on high
```

## Output Formats

Terminal output is optimized for humans:

```text
Agent Security Scanner
Target: .
Findings: 2
```

JSON output is intended for automation:

```json
{
  "target": ".",
  "summary": {
    "total": 1,
    "by_severity": {
      "critical": 1
    },
    "by_category": {
      "secrets": 1
    }
  },
  "findings": []
}
```

Human-readable reports are grouped by language, and machine-readable reports are grouped under `machine/`:

```text
output/
├─ en/
│  ├─ report.md
│  ├─ report.xlsx
│  └─ report.pdf
├─ zh/
│  ├─ report.md
│  ├─ report.xlsx
│  └─ report.pdf
└─ machine/
   ├─ agent-scan.sarif
   └─ report.json
```

Markdown output is intended for reports and issue comments. It writes two files:

- `output/en/report.md`
- `output/zh/report.md`

`--format all` writes every supported report artifact:

- `output/en/report.md`
- `output/en/report.xlsx`
- `output/en/report.pdf`
- `output/zh/report.md`
- `output/zh/report.xlsx`
- `output/zh/report.pdf`
- `output/machine/agent-scan.sarif`

SARIF output is intended for security automation and code scanning systems:

- `output/machine/agent-scan.sarif`

Excel output contains `Summary`, `Findings`, `Remediation`, and `Rules` sheets in English, and matching Chinese sheets in the Chinese report. Chinese Markdown, Excel, and PDF reports localize remediation summaries and suggested steps instead of reusing English guidance. PDF output uses a polished audit-report layout with blue title styling, blue section headings, blue table headers, a combined summary table, and structured remediation sections.

Markdown, JSON, and SARIF findings include structured remediation metadata with:

- Remediation summary
- Suggested steps
- Estimated effort
- Whether a finding class is likely automatable

## Configuration

`agent-scan` automatically looks for `.agent-scan.yml` or `.agent-scan.yaml` from the scanned directory upward.

Create a starter config:

```bash
agent-scan init
```

Example:

```yaml
min_severity: medium
language: en

exclude:
  - output/
  - vendor/
  - generated/**

disabled_rules:
  - SH003

ignore:
  - rule_id: SEC001
    path: examples/sample-project/app.py
    reason: Intentional fake key used as a scanner fixture.
```

Config fields:

| Field | Description |
|---|---|
| `min_severity` | Default minimum severity: `info`, `low`, `medium`, `high`, or `critical` |
| `language` | Default CLI language: `en` or `zh` |
| `exclude` | File or directory patterns to skip |
| `disabled_rules` | Rule IDs to suppress |
| `enabled_rules` | If present, only these rule IDs are reported |
| `ignore` | Finding allowlist entries with `rule_id`, `path`, and optional `reason` |
| `allowlist` | Alias for `ignore` |
| `max_file_size_bytes` | Maximum file size to scan |

## AI Coding Tool Checks

The scanner includes dedicated checks for local AI coding tool and agent configuration files, including common Cursor, Claude Code, Codex, Continue, Roo Code, Cline, and VS Code-style settings paths.

It looks for:

- Broad auto-approval or auto-execution
- Permission or sandbox bypass settings
- Root, home, or drive-level workspace access
- Shell-capable command configuration
- Plaintext credential fields in AI tool config files

## CI And Pre-Commit

Use `--fail-on` to turn scan results into an exit-code gate:

```bash
agent-scan . --fail-on high
```

The command exits with code `1` if any finding is at or above the selected severity.

This repository includes `.pre-commit-hooks.yaml` so it can be used as a pre-commit hook. For local development, see:

```yaml
repos:
  - repo: local
    hooks:
      - id: agent-security-scanner
        name: Agent Security Scanner
        entry: agent-scan . --fail-on high
        language: system
        pass_filenames: false
        always_run: true
```

An example is available at `examples/pre-commit-config.yaml`.

## Baseline Mode

Baseline mode helps existing projects adopt the scanner gradually.

Create a baseline:

```bash
agent-scan . --update-baseline --baseline-output .agent-scan-baseline.json
```

Use the baseline in CI:

```bash
agent-scan . --baseline .agent-scan-baseline.json --fail-on high
```

Known findings in the baseline are hidden from the report. New findings remain visible and can fail the build. Baseline files are JSON and are intended to be reviewed and committed.

## GitHub Actions

An example workflow is available at:

```text
examples/github-actions/agent-security-scan.yml
```

It installs the scanner, writes SARIF to `output/machine/agent-scan.sarif`, applies baseline filtering, and uploads SARIF through GitHub Code Scanning.

Use a specific config file:

```bash
agent-scan . --config examples/.agent-scan.yml
```

Disable config loading:

```bash
agent-scan . --no-config
```

## Rules

Show rules in the terminal:

```bash
agent-scan rules
agent-scan rules --category ai-tool
```

V1.0.0 core scanning now includes the first-stage rule expansion for broader secret providers, PowerShell and reverse-shell patterns, MCP remote transport/scope risks, and unsafe AI agent instruction files. The second-stage core upgrade adds structured GitHub Actions analysis and deeper MCP path semantics. The third-stage upgrade adds Agent/MCP-specific checks for memory poisoning, excessive autonomy, tool description poisoning, and remote prompt injection. The fourth-stage upgrade adds local-first supply-chain configuration checks. The fifth-stage release upgrade adds rule catalog consistency checks, generated rule documentation, and richer SARIF rule metadata.

| Rule | Category | Severity | Description |
|---|---|---:|---|
| AIT001 | ai-tool | high | AI coding tool auto-approval is enabled or too broad |
| AIT002 | ai-tool | critical | AI coding tool permission checks are bypassed |
| AIT003 | ai-tool | high | AI coding tool workspace access is too broad |
| AIT004 | ai-tool | high | AI coding tool can invoke a shell-capable command |
| AIT005 | ai-tool | critical | Secret embedded in AI coding tool config |
| AIT006 | ai-tool | high | AI instruction file contains unsafe instruction |
| AIT007 | ai-tool | high | AI memory or rule file contains persistence instruction |
| AIT008 | ai-tool | high | AI instruction grants excessive autonomy |
| AIT009 | ai-tool | critical | AI instruction allows data exfiltration |
| AIT010 | ai-tool | high | AI tool grants high-risk tool combination |
| SEC001 | secrets | critical | OpenAI API key detected |
| SEC002 | secrets | critical | GitHub token detected |
| SEC003 | secrets | critical | Anthropic API key detected |
| SEC004 | secrets | high | Bearer token detected |
| SEC005 | secrets | critical | Private key block detected |
| SEC006 | secrets | critical | AWS access key detected |
| SEC007 | secrets | critical | Slack token detected |
| SEC008 | secrets | critical | Discord token or webhook detected |
| SEC009 | secrets | critical | Hugging Face token detected |
| SEC010 | secrets | critical | npm access token detected |
| SEC011 | secrets | critical | PyPI API token detected |
| SEC012 | secrets | critical | Stripe API key detected |
| SEC013 | secrets | critical | Google API key detected |
| SEC014 | secrets | critical | Azure Storage connection string detected |
| SEC015 | secrets | high | JWT detected |
| SEC016 | secrets | high | Database URL with embedded password detected |
| SEC017 | secrets | high | Generic high-entropy credential detected |
| MCP001 | mcp | high | Overly broad filesystem access |
| MCP002 | mcp | high | Shell-capable MCP command |
| MCP003 | mcp | critical | Secret value embedded in MCP environment |
| MCP004 | mcp | medium | Remote MCP server configured |
| MCP005 | mcp | critical | Dangerous MCP server arguments |
| MCP006 | mcp | high | MCP remote server uses plaintext HTTP |
| MCP007 | mcp | high | MCP remote endpoint targets private or metadata address |
| MCP008 | mcp | high | MCP tool scope is overly broad |
| MCP009 | mcp | medium | MCP forwards host credential environment variable |
| MCP010 | mcp | high | MCP filesystem access includes sensitive local path |
| MCP011 | mcp | critical | Writable MCP filesystem access is too broad |
| MCP012 | mcp | high | MCP tool or resource description contains unsafe instruction |
| MCP013 | mcp | high | MCP tool output is treated as executable instruction |
| MCP014 | mcp | medium | MCP resource may inject remote prompt content |
| SH001 | shell | critical | Recursive force delete command |
| SH002 | shell | critical | Downloaded script piped to shell |
| SH003 | shell | high | Disabled execution safety controls |
| SH004 | shell | high | Potential secret exfiltration command |
| SH005 | shell | high | Encoded command execution |
| SH006 | shell | high | PowerShell expression execution |
| SH007 | shell | critical | Reverse shell pattern |
| SH008 | shell | critical | Destructive disk or filesystem command |
| SH009 | shell | medium | Inline dynamic code execution |
| SC001 | supply-chain | high | Package lifecycle script executes during install |
| SC002 | supply-chain | high | Package script contains risky install or execution command |
| SC003 | supply-chain | medium | Package dependency uses remote Git or URL source |
| SC004 | supply-chain | medium | Package dependency version is unpinned |
| SC005 | supply-chain | critical | Package manager credential stored in config file |
| SC006 | supply-chain | medium | Docker base image uses latest tag |
| SC007 | supply-chain | medium | Dockerfile ADD downloads remote content |
| SC008 | supply-chain | high | Docker build executes downloaded script |
| SC009 | supply-chain | high | Container service uses privileged or host-level settings |
| SC010 | supply-chain | high | Container mounts sensitive host path |
| SC011 | supply-chain | high | Devcontainer lifecycle command executes risky shell content |
| SC012 | supply-chain | high | Devcontainer mounts sensitive host path |
| SC013 | supply-chain | medium | Python requirement uses remote URL or VCS source |
| SC014 | supply-chain | low | Python requirement is not version pinned |
| GHA001 | github-actions | high | `pull_request_target` workflow checks out code |
| GHA002 | github-actions | medium | Unpinned GitHub Action reference |
| GHA003 | github-actions | critical | Secret echoed in GitHub Actions shell |
| GHA004 | github-actions | critical | Dangerous script download in GitHub Actions |
| GHA005 | github-actions | high | Overly broad GitHub Actions permissions |
| GHA006 | github-actions | medium | Self-hosted GitHub Actions runner |
| GHA007 | github-actions | high | Untrusted GitHub context used directly in shell |
| GHA008 | github-actions | medium | OIDC token permission granted |
| GHA009 | github-actions | medium | Cache or artifact action used in untrusted workflow context |
| GHA010 | github-actions | high | Downloaded artifact or cache content is executed |
| GHA011 | github-actions | high | `workflow_run` may process untrusted artifacts with elevated permissions |

## Examples

The `examples/` directory contains intentionally unsafe files that should trigger findings:

```bash
agent-scan examples/sample-project
agent-scan examples/sample-project --format json
agent-scan examples/sample-project --format markdown --output output
agent-scan examples/unsafe-script.sh
```

The sample files use fake demo secrets only. They are designed to exercise the expanded V1.0.0 rule set, including:

- multi-provider AI API key detection for OpenAI, Anthropic, DeepSeek, Moonshot/Kimi, DashScope/Qwen, Volcengine Ark/Doubao, Zhipu GLM, and other compatible providers
- MCP risks such as missing remote authentication, local stdio servers without an obvious isolation boundary, duplicate tool names, unsafe OAuth redirect URIs, broad file access, and embedded environment secrets
- AI coding tool risks such as Claude Code hooks, base URL overrides, unsafe skill/agent instructions, and invisible Unicode control characters
- supply-chain risks in `binding.gyp`, `setup.py`, package manifests, Docker, devcontainers, and requirements files
- GitHub Actions risks such as broad permissions, OIDC cloud trust policy verification, untrusted workflow contexts, and artifact/cache execution paths
- shell risks such as dangerous deletion, encoded execution, reverse shell patterns, and package-manager commands that immediately execute downloaded code

## Development

Run tests:

```bash
pytest
```

Run release/preflight checks:

```bash
agent-scan doctor
agent-scan rules --format markdown --output docs/RULES.md
agent-scan rules --format markdown --output docs/RULES_zh.md --lang zh
pytest
```

For the full V1.0.0 release checklist, see `docs/RELEASE_CHECKLIST.md`. For release announcements, GitHub topics, and launch copy, see `docs/LAUNCH.md`.

Run the CLI without installing:

```bash
python -m agent_security_scanner.cli examples/sample-project
```

## Design Notes

This first release is intentionally conservative:

- It scans local files only.
- It skips common dependency and cache directories.
- It uses high-signal pattern rules before deeper semantic analysis.
- It masks detected secret evidence in reports.

## Roadmap

- MCP server risk profiles
- Safe autofix suggestions

## License

MIT. See `LICENSE`.

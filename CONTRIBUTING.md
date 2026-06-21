# Contributing

Thanks for helping improve Agent Security Scanner.

## Development Setup

```bash
git clone https://github.com/LeeBush22/agent-security-scanner.git
cd agent-security-scanner
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install -e ".[dev]"
```

On macOS or Linux:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Local Checks

Run the test suite:

```bash
pytest
```

Run tests with coverage:

```bash
coverage run -m pytest -q
coverage report
```

Run type checks:

```bash
mypy
```

Run the nox sessions:

```bash
nox
```

## Adding Rules

When adding a rule:

1. Add the implementation under `src/agent_security_scanner/rules/`.
2. Register the rule in `src/agent_security_scanner/rules/__init__.py` if it is a new rule class.
3. Add rule metadata to `src/agent_security_scanner/rules_catalog.py`.
4. Add remediation guidance in `src/agent_security_scanner/remediation.py`.
5. Add or update Chinese labels in `src/agent_security_scanner/i18n.py`.
6. Add tests under `tests/`.
7. Regenerate rule docs:

```bash
agent-scan rules --format markdown --output docs/RULES.md
agent-scan rules --format markdown --output docs/RULES_zh.md --lang zh
```

Rule IDs should use the existing prefix format:

- `SEC###` for secrets
- `MCP###` for MCP
- `SH###` for shell
- `GHA###` for GitHub Actions
- `AIT###` for AI coding tools
- `SC###` for supply chain
- `FS###` for filesystem risks

## Pull Requests

Please keep PRs focused. Include:

- A short description of the risk or behavior being changed.
- Tests for new rules or CLI behavior.
- Documentation updates when user-facing behavior changes.

Do not include real credentials, private paths, local recovery codes, or generated report artifacts in commits.

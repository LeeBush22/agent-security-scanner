# V1.0.0 Release Checklist

Use this checklist before publishing Agent Security Scanner V1.0.0.

## Version

- [ ] `pyproject.toml` version is `1.0.0`.
- [ ] `pyproject.toml` package name is `agentsec-scanner` for PyPI publishing.
- [ ] `src/agent_security_scanner/__init__.py` version is `1.0.0`.
- [ ] `pyproject.toml` package status is `Development Status :: 4 - Beta`.
- [ ] `pyproject.toml` includes Homepage, Repository, Issues, and Documentation URLs.
- [ ] README files describe the current V1.0.0 feature set.
- [ ] Generated rule docs are up to date.

## Tests

- [ ] Run the full test suite:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

- [ ] Run rule documentation checks:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_rules_docs.py tests\test_i18n.py -q
```

- [ ] Run a sample scan:

```powershell
.\.venv\Scripts\agent-scan.exe examples\sample-project --format json
```

## Documentation

- [ ] Regenerate English rules documentation:

```powershell
.\.venv\Scripts\agent-scan.exe rules --format markdown --output docs\RULES.md
```

- [ ] Regenerate Chinese rules documentation:

```powershell
.\.venv\Scripts\agent-scan.exe rules --format markdown --output docs\RULES_zh.md --lang zh
```

- [ ] Confirm Chinese CLI output does not fall back to English rule titles for newly added rules.
- [ ] Confirm README and `README_zh.md` include usage examples, report formats, and supported rule families.
- [ ] Confirm README and `README_zh.md` show `python -m pip install agentsec-scanner` as the PyPI install command.

## Privacy

- [ ] Search for personal paths, usernames, phone numbers, email addresses, or real secrets.
- [ ] Confirm examples only contain fake demo credentials.
- [ ] Confirm generated reports are not committed unless intentionally included.
- [ ] Confirm `.pytest_cache`, `__pycache__`, temporary files, and local output artifacts are excluded.

## Package

- [ ] Reinstall the local package before final CLI verification:

```powershell
.\.venv\Scripts\python.exe -m pip install --no-deps --force-reinstall .
```

- [ ] Verify both command entry points:

```powershell
.\.venv\Scripts\agent-scan.exe --version
.\.venv\Scripts\agentsec.exe --version
```

## GitHub Release

- [ ] Add a concise release summary.
- [ ] Highlight local-first scanning, AI provider key detection, MCP checks, AI coding tool checks, GitHub Actions checks, SARIF, Excel, PDF, Markdown, and JSON reports.
- [ ] Include screenshots or terminal output examples.
- [ ] Mention that the project is rule-based and should be used as a security review aid, not as a complete security audit replacement.

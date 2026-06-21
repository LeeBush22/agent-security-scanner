# V1.0.3 Release Checklist

Use this checklist before publishing Agent Security Scanner V1.0.3.

## Version

- [ ] `pyproject.toml` version is `1.0.3`.
- [ ] `src/agent_security_scanner/__init__.py` version is `1.0.3`.
- [ ] `pyproject.toml` package name is `agentsec-scanner` for PyPI publishing.
- [ ] README files describe the current V1.0.3 feature set.
- [ ] Generated rule docs are up to date and show 129 built-in rules.
- [ ] CHANGELOG.md and CONTRIBUTING.md are present.

## Quality Gates

- [ ] Run the full test suite:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

- [ ] Run tests with coverage:

```powershell
.\.venv\Scripts\coverage.exe run -m pytest -q
.\.venv\Scripts\coverage.exe report
```

- [ ] Run type checks:

```powershell
.\.venv\Scripts\mypy.exe
```

- [ ] Run nox where supported:

```powershell
.\.venv\Scripts\nox.exe
```

## Feature Checks

- [ ] Generate English and Chinese rule docs:

```powershell
.\.venv\Scripts\agent-scan.exe rules --format markdown --output docs\RULES.md
.\.venv\Scripts\agent-scan.exe rules --format markdown --output docs\RULES_zh.md --lang zh
```

- [ ] Confirm PDF reports include more than 80 findings when the scan result is large.
- [ ] Confirm `agent-scan rules --category filesystem` lists FS001, FS002, and FS003.
- [ ] Confirm `agent-scan fix .` prints a preview and does not modify files.
- [ ] Confirm CI workflow exists at `.github/workflows/ci.yml`.

## Privacy

- [ ] Search for personal paths, usernames, phone numbers, email addresses, recovery codes, or real secrets.
- [ ] Confirm examples only contain fake demo credentials.
- [ ] Confirm generated reports, `.release-logs`, `dist`, `.pytest_cache`, and local output artifacts are not committed unless intentionally included.

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

- [ ] Highlight release maturity upgrades: CI, coverage, mypy, nox, CHANGELOG, and CONTRIBUTING.
- [ ] Highlight functional fixes: full PDF output, filesystem rules, and safe autofix preview.
- [ ] Mention that autofix is preview-only by default and does not modify files automatically.
- [ ] Include install and upgrade commands:

```bash
python -m pip install --upgrade agentsec-scanner
```

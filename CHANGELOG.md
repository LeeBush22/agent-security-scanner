# Changelog

All notable changes to Agent Security Scanner are documented in this file.

## V1.0.3 - 2026-06-21

- Added project CI for Python 3.10, 3.11, and 3.12.
- Added coverage, mypy, and nox configuration for release-quality checks.
- Added CONTRIBUTING.md with development, testing, and rule contribution guidance.
- Removed the PDF report 80-finding cap so large reports include every finding.
- Added filesystem risk rules for sensitive local files and broadly permissive permission files.
- Added a safe autofix preview command that produces patch-style guidance without modifying files by default.

## V1.0.2

- Added visible progress messages for longer interactive scan and report-generation actions.
- Changed default report names to `project_timestamp_language.format`.
- Grouped reports by project, timestamp, and language.
- Fixed report generation so options 3 and 4 reuse the correct last scanned project directory.

## V1.0.1

- Fixed report target alignment in interactive mode.
- Improved generated report path handling and bilingual report output behavior.
- Published the first PyPI repair release under the `agentsec-scanner` package name.

## V1.0.0

- Initial stable release.
- Added local-first scanning for AI Agent, MCP, AI coding tool, GitHub Actions, shell, secrets, and supply-chain risks.
- Added terminal, JSON, SARIF, Markdown, Excel, and PDF outputs.
- Added English and Chinese CLI/report support.

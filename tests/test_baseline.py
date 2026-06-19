import json
from pathlib import Path

import pytest

from agent_security_scanner.baseline import BaselineLoadError, filter_baseline, load_baseline, write_baseline
from agent_security_scanner.scanner import Scanner


def test_findings_have_stable_fingerprints(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")

    first = Scanner().scan(tmp_path).findings[0].fingerprint
    second = Scanner().scan(tmp_path).findings[0].fingerprint

    assert first
    assert first == second


def test_baseline_filters_known_findings(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")
    result = Scanner().scan(tmp_path)
    baseline_path = tmp_path / ".agent-scan-baseline.json"

    write_baseline(baseline_path, result)
    filtered = filter_baseline(result, load_baseline(baseline_path))

    assert filtered.summary.total == 0


def test_baseline_file_shape(tmp_path: Path):
    (tmp_path / "app.py").write_text('key = "sk-example1234567890example1234567890"', encoding="utf-8")
    baseline_path = tmp_path / ".agent-scan-baseline.json"

    write_baseline(baseline_path, Scanner().scan(tmp_path))
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))

    assert payload["version"] == 1
    assert payload["entries"][0]["fingerprint"]


def test_load_missing_baseline_raises_clear_error(tmp_path: Path):
    baseline_path = tmp_path / ".agent-scan-baseline.json"

    with pytest.raises(BaselineLoadError, match="Baseline file does not exist"):
        load_baseline(baseline_path)

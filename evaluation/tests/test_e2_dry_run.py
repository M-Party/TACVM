from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def test_e2_dry_run_writes_csv(tmp_path, monkeypatch):
    monkeypatch.setenv("TACVM_RESULTS_ROOT", str(tmp_path))
    monkeypatch.setenv("TACVM_TEE_BACKEND", "mock")
    monkeypatch.setenv("ITERATIONS", "1")
    monkeypatch.setenv("RULES", "10")
    monkeypatch.setenv("N", "4")
    script = REPO / "evaluation" / "scripts" / "e2_policy_scalability.sh"
    completed = subprocess.run(
        ["bash", str(script)],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "E2 complete:" in completed.stdout
    raw_files = list(tmp_path.glob("*/raw/e2_policy_scalability.csv"))
    assert len(raw_files) == 1
    with raw_files[0].open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["N"] == "4"
    assert rows[0]["P"] == "10"
    assert rows[0]["success"] == "True"
    assert int(rows[0]["total_us"]) >= 0

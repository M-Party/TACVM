from __future__ import annotations

import csv
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def test_e5_control_overhead_writes_summary(tmp_path, monkeypatch):
    monkeypatch.setenv("TACVM_RESULTS_ROOT", str(tmp_path))
    monkeypatch.setenv("TACVM_TEE_BACKEND", "mock")
    monkeypatch.setenv("ITERATIONS", "3")
    monkeypatch.setenv("WARMUPS", "1")
    script = REPO / "evaluation" / "scripts" / "e5_admission.sh"
    completed = subprocess.run(
        ["bash", str(script)],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "E5/Q3 complete:" in completed.stdout
    assert "TDX-Direct" in completed.stdout
    assert "TACVM" in completed.stdout

    raw_files = list(tmp_path.glob("*/raw/e5_control_overhead.csv"))
    summary_files = list(tmp_path.glob("*/summary/e5_control_overhead.csv"))
    assert len(raw_files) == 1
    assert len(summary_files) == 1

    with raw_files[0].open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    modes = {row["mode"] for row in rows}
    assert modes == {"TDX-Direct", "TACVM"}
    measured = [row for row in rows if row["warmup"] == "False"]
    assert len(measured) == 6
    assert all(float(row["control_latency_ms"]) >= 0 for row in measured)

    with summary_files[0].open(encoding="utf-8") as handle:
        summary = next(csv.DictReader(handle))
    assert summary["question"] == "Q3"
    assert float(summary["median_tacvm_ms"]) >= float(summary["median_tdx_direct_ms"])

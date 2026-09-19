from __future__ import annotations

import csv
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def test_e1_dry_run_writes_csv(tmp_path, monkeypatch):
    monkeypatch.setenv("TACVM_RESULTS_ROOT", str(tmp_path))
    monkeypatch.setenv("TACVM_TEE_BACKEND", "mock")
    monkeypatch.setenv("ITERATIONS", "1")
    monkeypatch.setenv("WARMUPS", "0")
    monkeypatch.setenv("N_LIST", "2 4")
    monkeypatch.setenv("RULES", "10")
    monkeypatch.setenv("P_LIST", "10")
    monkeypatch.setenv("P_N", "2")
    script = REPO / "evaluation" / "scripts" / "e1_trust_establishment.sh"
    completed = subprocess.run(
        ["bash", str(script)],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "E1 complete:" in completed.stdout
    raw_files = list(tmp_path.glob("*/raw/e1_trust_establishment.csv"))
    assert len(raw_files) == 1
    with raw_files[0].open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) >= 2
    assert {"2", "4"} <= {row["N"] for row in rows}
    assert all(row["backend"] == "mock" for row in rows)
    assert all(float(row["total_ms"]) >= 0 for row in rows)

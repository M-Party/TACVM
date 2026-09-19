"""Repo-wide pytest path bootstrap after the Op/Workload/Participant split."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PATHS = [
    ROOT / "shared" / "protocol",
    ROOT / "operation_cvm" / "policy_aggregation",
    ROOT / "operation_cvm" / "policy_aggregation" / "fixtures",
    ROOT / "operation_cvm" / "policy_coordinator",
    ROOT / "operation_cvm" / "participant_registry",
    ROOT / "operation_cvm" / "workload_launch",
    ROOT / "operation_cvm" / "dispatcher",
    ROOT / "workload_cvm" / "trusted_service",
    ROOT / "participants" / "policy_confirmer",
]
for path in PATHS:
    text = str(path)
    if text not in sys.path:
        sys.path.insert(0, text)

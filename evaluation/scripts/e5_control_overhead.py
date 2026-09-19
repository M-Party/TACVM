#!/usr/bin/env python3
"""Q3 — Workload management/control overhead (admit).

Compare TDX-Direct vs TACVM on the same Trusted Service local path.

Primary measurement boundary (identical for both modes):

  control_start  →  Trusted Service has accepted the request
                     (ready to invoke local runtime)

Excluded from the primary metric: container/model startup and steady-state work.

Modes:
  TDX-Direct — admit goes straight to the in-guest Trusted Service
  TACVM      — Operation CVM verifies/authorizes, then forwards to the same TS

Local mock note: no real TDX VM; portable control-path semantics only.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(REPO / "shared" / "protocol"),
    str(REPO / "operation_cvm" / "workload_launch"),
    str(REPO / "operation_cvm" / "dispatcher"),
    str(REPO / "workload_cvm" / "trusted_service"),
]

os.environ.setdefault("TACVM_TEE_BACKEND", "mock")

from dispatcher import TransitionDispatcher  # noqa: E402
from launch import WorkloadLaunchFSM  # noqa: E402
from tacvm_protocol import canonical_encode, get_tee_backend  # noqa: E402
from trusted_service import TrustedService, WorkloadLocalState  # noqa: E402

RAW_FIELDS = [
    "run_id",
    "session_id",
    "run_index",
    "mode",
    "warmup",
    "status",
    "control_start_ns",
    "trusted_service_accept_ns",
    "control_latency_ms",
    "authz_ms",
    "forward_ms",
    "backend",
]


def _sign_transition(private_key: Ed25519PrivateKey, fields: Mapping[str, object]) -> Dict[str, object]:
    body = canonical_encode("TACVM-TRANS", fields)
    return {**fields, "signature": private_key.sign(body)}


def _reset_workload(ts: TrustedService, dispatcher: TransitionDispatcher | None, w: str) -> None:
    ts._states[w] = WorkloadLocalState()
    if dispatcher is not None:
        dispatcher._processed_u.clear()


def run_direct(
    *,
    ts: TrustedService,
    w: str,
    operation_id: str,
    artifact_digest: str,
) -> Dict[str, Any]:
    """TDX-Direct: request issued → Trusted Service accept (no Operation CVM)."""

    control_start_ns = time.perf_counter_ns()
    ts.enforce_and_commit(
        w,
        operation_id=operation_id,
        prior_state="ABSENT",
        next_state="RUNNING",
        artifact_digest=artifact_digest,
    )
    trusted_service_accept_ns = time.perf_counter_ns()
    return {
        "mode": "TDX-Direct",
        "control_start_ns": control_start_ns,
        "trusted_service_accept_ns": trusted_service_accept_ns,
        "control_latency_ms": (trusted_service_accept_ns - control_start_ns) / 1e6,
        "authz_ms": "",
        "forward_ms": "",
        "status": "ok",
    }


def run_tacvm(
    *,
    dispatcher: TransitionDispatcher,
    requester: Ed25519PrivateKey,
    w: str,
    operation_id: str,
    artifact_digest: str,
) -> Dict[str, Any]:
    """TACVM: request → Op CVM authorize → forward → Trusted Service accept."""

    fields = {
        "participant_id": "id_O",
        "pid": dispatcher.pid,
        "policy_hash": dispatcher.policy_hash,
        "u": operation_id,
        "w": w,
        "operation": "admit",
        "prior_state": "ABSENT",
        "next_state": "RUNNING",
        "artifact_digest": artifact_digest,
    }
    request = _sign_transition(requester, fields)

    control_start_ns = time.perf_counter_ns()
    # Diagnostic: authorization wall time until TS returns (forward is inside).
    authz_start = time.perf_counter_ns()
    result = dispatcher.submit_transition(request)
    trusted_service_accept_ns = time.perf_counter_ns()
    authz_ms = (trusted_service_accept_ns - authz_start) / 1e6
    if result.get("status") != "COMMITTED":
        raise RuntimeError(f"unexpected TACVM result: {result}")
    return {
        "mode": "TACVM",
        "control_start_ns": control_start_ns,
        "trusted_service_accept_ns": trusted_service_accept_ns,
        "control_latency_ms": (trusted_service_accept_ns - control_start_ns) / 1e6,
        # Full Op-CVM+forward path; finer split needs TS hooks — keep as diagnostic.
        "authz_ms": round(authz_ms, 6),
        "forward_ms": "",
        "status": "ok",
    }


def _median(values: Sequence[float]) -> float:
    return float(statistics.median(values)) if values else float("nan")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--session", type=int, default=1)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    raw_path = args.out_dir / "raw" / "e5_control_overhead.csv"
    summary_path = args.out_dir / "summary" / "e5_control_overhead.csv"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    tee = get_tee_backend("mock")
    pid = "pid-q3"
    pk_ch = "pk-op-q3"
    policy_hash = "sha384:policy-q3"
    w = "w-q3-admit"
    artifact = "sha256:artifact-q3"

    launch_fsm = WorkloadLaunchFSM(tee=tee, pid=pid, pk_ch=pk_ch)
    launch_fsm.create_launch(w)
    launch_fsm.mark_provisioning(w)
    launch_fsm.authenticate_workload(w, pk_w="pk-w-q3", challenge_n_w="cc" * 32)

    requester = Ed25519PrivateKey.generate()
    ts = TrustedService()
    dispatcher = TransitionDispatcher(
        pid=pid,
        policy_hash=policy_hash,
        requester_keys={
            "id_O": requester.public_key().public_bytes_raw().hex(),
        },
        launch_fsm=launch_fsm,
        allowed_transitions={("admit", "ABSENT", "RUNNING")},
        trusted_service=ts,
    )

    rows: List[Dict[str, Any]] = []
    run_index = 0
    modes = ("TDX-Direct", "TACVM")

    with raw_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RAW_FIELDS, extrasaction="ignore")
        writer.writeheader()

        for mode in modes:
            for warmup in list(range(args.warmups)) + [None] * args.iterations:
                is_warmup = warmup is not None
                run_index += 1
                operation_id = f"op-{mode}-{run_index}"
                _reset_workload(ts, dispatcher if mode == "TACVM" else None, w)

                if mode == "TDX-Direct":
                    row = run_direct(
                        ts=ts,
                        w=w,
                        operation_id=operation_id,
                        artifact_digest=artifact,
                    )
                else:
                    row = run_tacvm(
                        dispatcher=dispatcher,
                        requester=requester,
                        w=w,
                        operation_id=operation_id,
                        artifact_digest=artifact,
                    )

                record = {
                    "run_id": args.run_id,
                    "session_id": args.session,
                    "run_index": run_index,
                    "warmup": is_warmup,
                    "backend": "mock",
                    **row,
                    "control_latency_ms": round(float(row["control_latency_ms"]), 6),
                }
                writer.writerow(record)
                rows.append(record)
                if not is_warmup:
                    print(
                        f"Q3 {mode} iter={run_index} "
                        f"control_latency_ms={record['control_latency_ms']:.6f}"
                    )

    measured = [r for r in rows if not r["warmup"] and r["status"] == "ok"]
    direct = [float(r["control_latency_ms"]) for r in measured if r["mode"] == "TDX-Direct"]
    tacvm = [float(r["control_latency_ms"]) for r in measured if r["mode"] == "TACVM"]
    t_direct = _median(direct)
    t_tacvm = _median(tacvm)
    delta = t_tacvm - t_direct
    overhead_pct = (delta / t_direct * 100.0) if t_direct > 0 else float("nan")

    summary = {
        "run_id": args.run_id,
        "question": "Q3",
        "backend": "mock",
        "iterations": args.iterations,
        "warmups": args.warmups,
        "median_tdx_direct_ms": round(t_direct, 6),
        "median_tacvm_ms": round(t_tacvm, 6),
        "delta_ms": round(delta, 6),
        "overhead_percent": round(overhead_pct, 4),
        "boundary": "request_issued -> trusted_service_accept",
        "excludes": ["container_startup", "model_startup", "steady_state"],
    }
    with summary_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary.keys()))
        writer.writeheader()
        writer.writerow(summary)

    (args.out_dir / "config.json").write_text(
        json.dumps(
            {
                **summary,
                "note": (
                    "Local mock control-path comparison. Same Trusted Service local "
                    "commit path for both modes; TACVM adds Operation CVM "
                    "verify/authorize/forward only."
                ),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print()
    print("| Scheme              | Median Control Latency |")
    print("| ------------------- | ---------------------: |")
    print(f"| TDX-Direct          | {t_direct:22.6f} ms |")
    print(f"| TACVM               | {t_tacvm:22.6f} ms |")
    print(f"| Additional overhead | {delta:22.6f} ms |")
    print(f"| Relative overhead   | {overhead_pct:21.4f}% |")
    print()
    print(f"Wrote {raw_path}")
    print(f"Wrote {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

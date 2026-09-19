#!/usr/bin/env python3
"""E1 / Q1 local dry-run: multi-party Operation CVM trust establishment.

Measures portable post-boot path under TACVM_TEE_BACKEND=mock:

  mock Operation Quote ready
  → N participants authenticate Op CVM (quote verify + TACVM-ACCEPT)
  → proposals / restrictive join / candidate / CONFIRM / policy_active

Does NOT include real TDX Operation CVM boot, dm-verity, or network RTT.
Those must be measured on the coauthor TDX host. Local boot_ms is only the
mock Quote generation stand-in so the CSV schema matches the evaluation spec.

Factors (defaults match EVALUATION_PLAN / E1):
  - N sweep: 2,4,8,16,32 at fixed P=100
  - P sweep: 10,100,1000 at fixed N=8
"""

from __future__ import annotations

import argparse
import base64
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
    str(REPO / "operation_cvm" / "policy_aggregation"),
    str(REPO / "operation_cvm" / "policy_aggregation" / "fixtures"),
    str(REPO / "operation_cvm" / "policy_coordinator"),
    str(REPO / "operation_cvm" / "participant_registry"),
    str(REPO / "participants" / "policy_confirmer"),
]

os.environ.setdefault("TACVM_TEE_BACKEND", "mock")

from confirm_policy import confirm_policy_candidate  # noqa: E402
from coordinator import PolicyCoordinator, proposal_signing_message  # noqa: E402
from generate_homogeneous import build_homogeneous_bundle, participant_ids  # noqa: E402
from registry import BootManifestParticipant, ParticipantRegistry  # noqa: E402
from tacvm_policy_core import normalize_proposal, proposal_digest  # noqa: E402
from tacvm_protocol import canonical_encode, get_tee_backend  # noqa: E402

RAW_FIELDS = [
    "run_id",
    "session_id",
    "run_index",
    "N",
    "P",
    "warmup",
    "status",
    "boot_ms",
    "participant_auth_ms",
    "policy_establishment_ms",
    "total_ms",
    "proposal_verify_ms",
    "restrictive_join_ms",
    "candidate_construct_ms",
    "participant_confirm_ms",
    "phase_sum_ms",
    "phase_gap_ms",
    "backend",
]


def _now_ms() -> float:
    return time.perf_counter() * 1000.0


def _ms(start: float, end: float) -> float:
    return round(end - start, 3)


def _sign_accept(boot_sk, policy_sk, participant_id: str, d_M: str, pk_ch: str):
    pk_policy = policy_sk.public_key().public_bytes_raw().hex()
    fields = {
        "participant_id": participant_id,
        "d_M": d_M,
        "pk_ch": pk_ch,
        "pk_policy": pk_policy,
    }
    body = canonical_encode("TACVM-ACCEPT", fields)
    return {
        **fields,
        "boot_signature": boot_sk.sign(body),
        "policy_signature": policy_sk.sign(body),
    }


def _sign_proposal(proposal: Mapping[str, Any], private_key: Ed25519PrivateKey):
    proposal = normalize_proposal(proposal)
    digest_value = proposal_digest(proposal, already_normalized=True)
    participant_id = proposal["author"]["participant_id"]
    signature = private_key.sign(
        proposal_signing_message(participant_id, proposal["context"], digest_value)
    )
    return {
        "proposal": proposal,
        "proposal_digest": digest_value,
        "signature_algorithm": "Ed25519",
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def run_once(
    *,
    n: int,
    rules: int,
    run_id: str,
    session_id: int,
    run_index: int,
    warmup: bool,
) -> Dict[str, Any]:
    tee = get_tee_backend("mock")
    order = participant_ids(n)
    d_M = f"sha384:manifest-e1-n{n}-p{rules}"
    pk_ch = "pk-op-e1-mock"
    pid = f"pid-e1-n{n}"

    boot_keys = {pid_: Ed25519PrivateKey.generate() for pid_ in order}
    policy_keys = {pid_: Ed25519PrivateKey.generate() for pid_ in order}

    t_total0 = _now_ms()

    # --- boot_ms (mock stand-in: Op CVM Quote ready) ---
    t0 = _now_ms()
    evidence = tee.generate_operation_quote(n_i="aa" * 32, pk_ch=pk_ch, d_M=d_M)
    expected = evidence.reportdata
    tee.verify_quote(evidence, expected)
    t1 = _now_ms()
    boot_ms = _ms(t0, t1)

    # --- participant_auth_ms: each participant verifies Op Quote + ACCEPT ---
    t2 = _now_ms()
    registry = ParticipantRegistry(
        d_M=d_M,
        pk_ch=pk_ch,
        participants=[
            BootManifestParticipant(
                participant_id=pid_,
                boot_public_key=boot_keys[pid_].public_key(),
                expected_protocol_id=pid,
            )
            for pid_ in order
        ],
    )
    for pid_ in order:
        # Serialized participant authentication (measure as implemented).
        tee.verify_quote(evidence, expected)
        registry.submit_acceptance(
            _sign_accept(boot_keys[pid_], policy_keys[pid_], pid_, d_M, pk_ch)
        )
    assert registry.all_registered()
    t3 = _now_ms()
    participant_auth_ms = _ms(t2, t3)

    # --- policy_establishment_ms ---
    bundle = build_homogeneous_bundle(n=n, rule_count=rules)
    context = bundle["context"]
    by_participant = {
        p["author"]["participant_id"]: p for p in bundle["proposals"]
    }
    coordinator = PolicyCoordinator(
        context,
        {pid_: policy_keys[pid_].public_key() for pid_ in order},
    )

    t_pol0 = _now_ms()

    t_pv0 = _now_ms()
    for pid_ in order:
        coordinator.submit_proposal(_sign_proposal(by_participant[pid_], policy_keys[pid_]))
    t_pv1 = _now_ms()
    proposal_verify_ms = _ms(t_pv0, t_pv1)

    # Single build over already-accepted envelopes (no second normalize/digest).
    t_cand0 = _now_ms()
    candidate_bundle = coordinator.build_candidate()
    t_cand1 = _now_ms()
    candidate_construct_ms = _ms(t_cand0, t_cand1)
    # Join is performed once inside build; keep a dedicated column for the
    # construct wall time (join-dominated) without re-running join.
    restrictive_join_ms = candidate_construct_ms

    inboxes: Dict[str, Any] = {}
    coordinator.distribute_candidate(
        lambda participant_id, message: inboxes.__setitem__(participant_id, message)
    )

    t_conf0 = _now_ms()
    for pid_ in order:
        confirmation = confirm_policy_candidate(
            pid_,
            by_participant[pid_],
            context,
            inboxes[pid_],
            policy_keys[pid_],
        )
        coordinator.submit_confirmation(confirmation)
    active = coordinator.activate()
    t_conf1 = _now_ms()
    participant_confirm_ms = _ms(t_conf0, t_conf1)

    t_pol1 = _now_ms()
    policy_establishment_ms = _ms(t_pol0, t_pol1)
    t_total1 = _now_ms()
    total_ms = _ms(t_total0, t_total1)

    phase_sum_ms = round(boot_ms + participant_auth_ms + policy_establishment_ms, 3)
    phase_gap_ms = round(total_ms - phase_sum_ms, 3)
    status = "ok"
    if abs(phase_gap_ms) > 0.05 * max(total_ms, 1e-6):
        status = "gap_flag"

    assert active is not None
    assert coordinator.state == "ACTIVE"

    return {
        "run_id": run_id,
        "session_id": session_id,
        "run_index": run_index,
        "N": n,
        "P": rules,
        "warmup": warmup,
        "status": status,
        "boot_ms": boot_ms,
        "participant_auth_ms": participant_auth_ms,
        "policy_establishment_ms": policy_establishment_ms,
        "total_ms": total_ms,
        "proposal_verify_ms": proposal_verify_ms,
        "restrictive_join_ms": restrictive_join_ms,
        "candidate_construct_ms": candidate_construct_ms,
        "participant_confirm_ms": participant_confirm_ms,
        "phase_sum_ms": phase_sum_ms,
        "phase_gap_ms": phase_gap_ms,
        "backend": "mock",
        "candidate_digest": candidate_bundle["candidate_digest"],
    }


def _summary_rows(rows: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    measured = [r for r in rows if not r["warmup"] and r["status"] in {"ok", "gap_flag"}]
    out = []
    keys = sorted({(r["N"], r["P"]) for r in measured})
    for n, p in keys:
        subset = [r for r in measured if r["N"] == n and r["P"] == p]
        totals = [float(r["total_ms"]) for r in subset]
        auths = [float(r["participant_auth_ms"]) for r in subset]
        pols = [float(r["policy_establishment_ms"]) for r in subset]
        boots = [float(r["boot_ms"]) for r in subset]
        out.append(
            {
                "N": n,
                "P": p,
                "trials": len(subset),
                "median_total_ms": round(statistics.median(totals), 3),
                "mean_total_ms": round(statistics.mean(totals), 3),
                "p95_total_ms": round(
                    statistics.quantiles(totals, n=20)[18]
                    if len(totals) >= 20
                    else max(totals),
                    3,
                ),
                "median_boot_ms": round(statistics.median(boots), 3),
                "median_participant_auth_ms": round(statistics.median(auths), 3),
                "median_policy_establishment_ms": round(statistics.median(pols), 3),
            }
        )
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--n-list",
        type=int,
        nargs="+",
        default=[2, 4, 8, 16, 32],
        help="participant counts for N-sweep at fixed --rules",
    )
    parser.add_argument(
        "--rules",
        type=int,
        default=100,
        help="fixed lifecycle rule count for N-sweep",
    )
    parser.add_argument(
        "--p-list",
        type=int,
        nargs="*",
        default=[10, 100, 1000],
        help="rule counts for P-sweep at fixed --p-n (empty to skip)",
    )
    parser.add_argument("--p-n", type=int, default=8, help="fixed N for P-sweep")
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--session", type=int, default=1)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    raw_path = args.out_dir / "raw" / "e1_trust_establishment.csv"
    summary_path = args.out_dir / "summary" / "e1_trust_establishment.csv"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    points: List[tuple[int, int]] = [(n, args.rules) for n in args.n_list]
    for p in args.p_list or []:
        points.append((args.p_n, p))
    # de-dupe preserving order
    seen = set()
    unique_points = []
    for point in points:
        if point not in seen:
            seen.add(point)
            unique_points.append(point)

    rows: List[Dict[str, Any]] = []
    run_index = 0
    with raw_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RAW_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for n, p in unique_points:
            for warmup_i in range(args.warmups):
                run_index += 1
                row = run_once(
                    n=n,
                    rules=p,
                    run_id=args.run_id,
                    session_id=args.session,
                    run_index=run_index,
                    warmup=True,
                )
                writer.writerow(row)
                rows.append(row)
            for _ in range(args.iterations):
                run_index += 1
                row = run_once(
                    n=n,
                    rules=p,
                    run_id=args.run_id,
                    session_id=args.session,
                    run_index=run_index,
                    warmup=False,
                )
                writer.writerow(row)
                rows.append(row)
                print(
                    f"E1 N={n} P={p} total_ms={row['total_ms']} "
                    f"auth={row['participant_auth_ms']} "
                    f"policy={row['policy_establishment_ms']} "
                    f"status={row['status']}"
                )

    summary = _summary_rows(rows)
    with summary_path.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = list(summary[0].keys()) if summary else [
            "N",
            "P",
            "trials",
            "median_total_ms",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in summary:
            writer.writerow(row)

    meta = {
        "experiment": "E1",
        "question": "Q1",
        "backend": "mock",
        "excludes": [
            "real_tdx_operation_cvm_boot",
            "dm_verity",
            "network_rtt",
            "dcap_qvl",
        ],
        "n_list": args.n_list,
        "rules_for_n_sweep": args.rules,
        "p_list": args.p_list,
        "p_n": args.p_n,
        "iterations": args.iterations,
        "warmups": args.warmups,
        "note": (
            "Local mock dry-run for portable trust-establishment phases. "
            "boot_ms is mock Quote generation only; replace on TDX host."
        ),
    }
    (args.out_dir / "config.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {raw_path}")
    print(f"Wrote {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

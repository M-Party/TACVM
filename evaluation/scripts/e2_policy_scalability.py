#!/usr/bin/env python3
"""E2 policy-processing scalability dry-run (no TDX / no network).

Measures proposal normalize+digest, restrictive join, and candidate construction
for fixed N with varying rule counts P. Uses the homogeneous fixture generator.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(REPO_ROOT / "shared" / "protocol"),
    str(REPO_ROOT / "operation_cvm" / "policy_aggregation"),
    str(REPO_ROOT / "operation_cvm" / "policy_aggregation" / "fixtures"),
]

from generate_homogeneous import build_homogeneous_bundle, participant_ids  # noqa: E402
from tacvm_policy_core import (  # noqa: E402
    candidate_digest,
    join_policy_bodies,
    normalize_proposal,
    proposal_digest,
)


def _timed_us(fn):
    start = time.perf_counter_ns()
    value = fn()
    end = time.perf_counter_ns()
    return value, (end - start) // 1000


def run_once(n: int, rules: int, iteration: int, session: int, run_id: str) -> dict:
    bundle = build_homogeneous_bundle(n=n, rule_count=rules)
    context = bundle["context"]
    order = participant_ids(n)
    by_participant = {
        proposal["author"]["participant_id"]: proposal for proposal in bundle["proposals"]
    }

    # Normalize once up front; timed phases must not re-normalize.
    normalized_map = {
        participant_id: normalize_proposal(by_participant[participant_id])
        for participant_id in order
    }

    def verify_all():
        return [
            proposal_digest(normalized_map[participant_id], already_normalized=True)
            for participant_id in order
        ]

    digests, proposal_verify_us = _timed_us(verify_all)

    def join_only():
        return join_policy_bodies(
            [normalized_map[pid] for pid in order],
            already_normalized=True,
        )

    joined, join_us = _timed_us(join_only)

    def construct():
        candidate = {
            "schema": "tacvm-policy-candidate/v0.2",
            "context": dict(context),
            "inputs": [
                {
                    "participant_id": participant_id,
                    "proposal_digest": digest,
                }
                for participant_id, digest in zip(order, digests)
            ],
            "policy": joined,
        }
        digest = candidate_digest(candidate)
        return {"candidate": candidate, "candidate_digest": digest}

    result, candidate_construct_us = _timed_us(construct)
    total_us = proposal_verify_us + join_us + candidate_construct_us
    return {
        "run_id": run_id,
        "session": session,
        "iteration": iteration,
        "N": n,
        "P": rules,
        "proposal_verify_us": proposal_verify_us,
        "join_us": join_us,
        "candidate_construct_us": candidate_construct_us,
        "total_us": total_us,
        "success": True,
        "candidate_digest": result["candidate_digest"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=3)
    parser.add_argument(
        "--rules",
        type=int,
        nargs="+",
        default=[10, 100, 1000],
        help="rule counts P to measure",
    )
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--session", type=int, default=1)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    raw_path = args.out_dir / "raw" / "e2_policy_scalability.csv"
    summary_path = args.out_dir / "summary" / "e2_policy_scalability.csv"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "run_id",
        "session",
        "iteration",
        "N",
        "P",
        "proposal_verify_us",
        "join_us",
        "candidate_construct_us",
        "total_us",
        "success",
    ]
    rows = []
    with raw_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for rules in args.rules:
            for iteration in range(1, args.iterations + 1):
                row = run_once(args.n, rules, iteration, args.session, args.run_id)
                writer.writerow(row)
                rows.append(row)
                print(
                    f"E2 N={args.n} P={rules} iter={iteration} "
                    f"total_us={row['total_us']} digest={row['candidate_digest'][:24]}..."
                )

    # Summary by P
    with summary_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "run_id",
                "N",
                "P",
                "iterations",
                "median_total_us",
                "mean_total_us",
                "median_join_us",
                "median_candidate_construct_us",
            ],
        )
        writer.writeheader()
        for rules in args.rules:
            subset = [row for row in rows if row["P"] == rules]
            totals = [row["total_us"] for row in subset]
            joins = [row["join_us"] for row in subset]
            cands = [row["candidate_construct_us"] for row in subset]
            writer.writerow(
                {
                    "run_id": args.run_id,
                    "N": args.n,
                    "P": rules,
                    "iterations": len(subset),
                    "median_total_us": int(statistics.median(totals)),
                    "mean_total_us": int(statistics.mean(totals)),
                    "median_join_us": int(statistics.median(joins)),
                    "median_candidate_construct_us": int(statistics.median(cands)),
                }
            )

    meta = {
        "experiment": "E2",
        "backend": "mock-policy-only",
        "n": args.n,
        "rules": args.rules,
        "iterations": args.iterations,
        "note": "Dry-run join timing only; excludes participant network RTT and TDX Quotes",
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

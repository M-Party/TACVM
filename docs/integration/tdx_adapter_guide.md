# TDX Host Adapter Guide (for coauthor)

**Audience:** Engineer with the existing TACVM/TDX testbed (`policy_server`, guest launchers, 16-CVM fleet).  
**Purpose:** Explain how to plug this repository’s portable protocol/evaluation pieces into your stack **without** replacing your verifier or concurrency fixes.  
**Dev host note:** The authoring environment has no TDX. Real Quotes/CVM launches happen only on your machine.

---

## 1. What you already have (keep these)

Do **not** remove or re-implement:

| Item | Why |
|---|---|
| Native `/root/vm-verifier/policy_server` on `:50051` | Live attestation/control plane entry |
| `state_mutex_` around `pending_challenges_` / `sessions_` | Prevents concurrent map corruption |
| Process-wide DCAP QVL/appraisal mutex | Serializes non-thread-safe appraisal |
| Global client IDs `cvm_<NN>_client_<M>` via `CVM_INSTANCE_ID` | Prevents cross-CVM challenge collisions |
| `launch-client.sh` / `cvm-fleet-test.sh` | Fleet orchestration already validated |
| Distinguishing “all requests passed” vs “server still alive” | Required for concurrency conclusions |

This repository will **not** ship a second `policy_server`. You adapt.

---

## 2. What this repository provides

| Package / doc | Role |
|---|---|
| `evaluation-assets/policy-aggregation-core` | Deterministic restrictive join + candidate digest |
| `evaluation-assets/operation-cvm-policy-coordinator` | Proposal collect → candidate → confirm → activate FSM |
| `evaluation-assets/participant-policy-confirmer` | Participant-side candidate check + `TACVM-CONFIRM` |
| Policy fixtures (3-party + homogeneous N=2..32) | Local/scale policy inputs |
| `docs/evaluation/*` | Mapping and status |
| Future: encode helpers, `B_w` FSM, dispatcher checks, E1–E7 harness | Portable logic + mock backend |

Treat Python components as **reference semantics / callable libraries** to port or embed. If you prefer C++, preserve the same wire fields, digests, and fail-closed rules.

---

## 3. Adapter points (contracts you implement)

Implement these on the TDX host. Names are logical; map onto your gRPC/messages.

### A. Attestation / Quote

```text
GenerateOperationQuote(challenge_n_i, pk_ch, d_M) -> (quote, event_log)
VerifyQuote(quote, expected_reportdata, ...) -> AppraisalResult
```

Requirements:

- `REPORTDATA = H(Encode("TACVM-BOOT", n_i, pk_ch, d_M))` (or the repo’s published encoder once landed)
- Keep appraisal under the existing process-wide mutex
- Fail closed on chain/TCB/RTMR/event-log mismatch

### B. Participant acceptance / policy-key registry

```text
SubmitAcceptance(id_i, d_M, pk_ch, pk_policy_i, boot_sig, policy_sig) -> OK|ERR_*
```

Reject unknown id, duplicate acceptance, duplicate policy-key binding, manifest/`pk_ch` mismatch.  
Policy collection starts only when all manifest participants are registered.

### C. Policy round (hook portable join here)

```text
OpenPolicyRound(pid, v, r)
SubmitPolicyProposal(signed proposal)
BuildCandidate()                    # call aggregation-core semantics
DistributeCandidate()
SubmitPolicyConfirmation(signed confirm)
ActivateIfComplete()                # atomic immutable snapshot
```

Your server remains the network endpoint; portable code owns join/confirm checks.

### D. Workload launch context / binding

```text
CreateLaunchContext(w, pid, pk_ch) -> lambda_w
ProvisionWorkloadCVM(opaque=lambda_w) -> platform_handle
VerifyWorkloadEvidence(...) -> B_w | reject
InvalidateBinding(w) on channel loss / restart
```

No secrets or transitions without `B_w == LIVE`.

### E. Runtime transition

```text
SubmitTransition(signed q_i) -> authorize -> dispatch over B_w
TrustedServiceEnforce(local_state, artifact, u) -> commit|reject
```

Preserve check order from the design spec (signature → pid/H(pi) → replay → B_w → policy → secrets → dispatch).

### F. Evaluation hooks

Emit monotonic timestamps / structured events listed in the design spec.  
Formal runners will live under `evaluation/scripts/e1_*.sh` … `e7_*.sh` (to be filled in later phases). Your fleet scripts should call those entrypoints instead of ad-hoc one-off timing.

---

## 4. Suggested integration sequence

1. **Freeze invariants** — confirm client IDs + both mutexes still on by default.
2. **Vendor or submodule this repo** on the TDX host (or copy a release tarball).
3. **Run portable tests with `TACVM_TEE_BACKEND=mock`** (once mock lands) to confirm policy join/confirm locally on the TDX host without needing Quotes.
4. **Wire Quote path (adapter A)** to existing `quote_verifier.cc`; add domain-separated REPORTDATA helper from this repo when available.
5. **Wire policy path (adapter C)** — start by calling Python join from a narrow FFI/CLI, or reimplement join in C++ against the same fixtures (`three-party` + homogeneous N).
6. **Only then** wire Workload `lambda_w` / `B_w` and admission.
7. **Point E4** at `cvm-fleet-test.sh` with run_id isolation and post-run `ps`/`ss` liveness checks.
8. **Do not** import old smoke timings into final `results/`; regenerate with the harness.

---

## 5. Configuration knobs (planned)

| Variable | Values | Meaning |
|---|---|---|
| `TACVM_TEE_BACKEND` | `mock` \| `tdx` | Hardware vs fake Quotes/provision |
| `TACVM_VERIFIER_ENDPOINT` | e.g. `127.0.0.1:50051` | Your `policy_server` |
| `TACVM_FLEET_SCRIPT` | path to `cvm-fleet-test.sh` | Concurrent auth driver |
| `TACVM_RUN_ID` | `YYYYMMDD-HHMMSS-...` | Isolate logs/results |

Exact names may be finalized when harness code lands; keep this table updated.

---

## 6. What “done adapting” looks like

- [ ] Mock policy E2 / join tests pass on your host using this repo’s fixtures  
- [ ] Real participant RA still passes with global client IDs and both mutexes  
- [ ] Policy activation requires all confirmations; partial set never enables workload control  
- [ ] Workload path creates fresh `lambda_w`, rejects replay, establishes/invalidates `B_w`  
- [ ] E1–E7 scripts produce `results/<run_id>/` CSVs with environment metadata  
- [ ] Concurrent run: all requested clients succeed **and** `policy_server` still listening afterward  

---

## 7. Contact points / questions to resolve during wiring

If message layouts differ from the portable schemas, prefer **extending existing protobufs** over renaming everything. Document any semantic conflict with the paper **before** changing protocol behavior.

When in doubt: fail closed; keep production and evaluation on the same authorization path.

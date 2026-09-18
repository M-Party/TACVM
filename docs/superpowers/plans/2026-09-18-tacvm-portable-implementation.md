# TACVM Portable Implementation Plan (Strategy A)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build portable TACVM protocol/evaluation assets in this repo with mock TEE, plus docs so the coauthor can adapt their existing TDX `policy_server`/fleet without a parallel stack.

**Architecture:** Protocol and harness live here behind `mock`/`tdx` adapters. Coauthor keeps native verifier, mutexes, and global client IDs; they implement adapter hooks described in `docs/integration/tdx_adapter_guide.md`.

**Tech Stack:** Python (existing policy components), shell evaluation harnesses, documented C++/gRPC adapter contracts for the TDX host; no real TDX required on the authoring machine.

---

## File map (initial)

| Path | Responsibility |
|---|---|
| `docs/superpowers/specs/2026-09-18-tacvm-portable-implementation-design.md` | Approved design |
| `docs/evaluation/repo_mapping.md` | Paper ↔ repo ↔ coauthor map |
| `docs/evaluation/implementation_status.md` | Status matrix |
| `docs/integration/tdx_adapter_guide.md` | Coauthor integration contract |
| `evaluation-assets/**` | Existing policy prototypes to extend |
| Future `src/` or `tacvm_*/` | Encode, FSMs, adapters (later tasks) |
| Future `evaluation/scripts/` | E1–E7 runners (later tasks) |

---

### Task 0: Phase A docs (current)

- [x] Write design spec
- [x] Write `repo_mapping.md`
- [x] Write `implementation_status.md`
- [x] Write `tdx_adapter_guide.md`
- [ ] Commit Phase A documentation

### Task 1: Canonical encoding skeleton

- [x] Add failing tests for domain-separated encode/hash determinism (`TACVM-BOOT`, `TACVM-PROPOSAL`, …)
- [x] Implement minimal encoder module
- [x] Run tests; commit

### Task 2: Align policy components with encoder + error codes

- [ ] Map existing coordinator/confirmer messages to stable `ERR_*` codes from the design spec
- [ ] Add tests for wrong pid/v/r and incomplete participant sets (extend current tests)
- [ ] Commit

### Task 3: Mock TEE + adapter interfaces

- [ ] Define interfaces: quote, provision, binding
- [ ] Implement `mock` backend
- [ ] Stub `tdx` backend with clear `NotImplemented` / hook docs
- [ ] Commit

### Task 4: Participant acceptance + registry FSM (portable)

- [ ] Tests for duplicate acceptance / duplicate policy key
- [ ] Implement registry + barrier before policy collection
- [ ] Commit

### Task 5: Launch context + `B_w` FSM (mock)

- [ ] Tests for fresh `lambda_w`, replay reject, invalidate on channel loss
- [ ] Implement pending launch + live binding state machine
- [ ] Commit

### Task 6: Dispatcher / transition checks (portable, mock TS)

- [ ] Tests for replay `u`, policy hash mismatch, binding-not-live, state mismatch
- [ ] Implement ordered authorization + mock Trusted Service enforce
- [ ] Commit

### Task 7: Evaluation skeleton

- [ ] Create `evaluation/{scripts,common,config}` layout from evaluation spec
- [ ] CSV helpers + run_id + healthcheck stubs
- [ ] E2 dry-run against homogeneous fixtures (no TDX)
- [ ] Commit

### Task 8: Handoff package

- [ ] Update READMEs with mock vs TDX instructions
- [ ] Refresh `implementation_status.md`
- [ ] Tag/package notes for coauthor

---

## Progress

Phase A documentation is in tree; implementation tasks 1+ start after commit and user go-ahead for coding.

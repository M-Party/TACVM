# TACVM

Portable TACVM protocol helpers, policy agreement prototypes, and evaluation
harness skeletons for handoff to a TDX-capable coauthor host.

## Quick start (this host — no TDX)

```bash
PYTHONPATH=protocol python3 -m pytest protocol/tests -q
bash evaluation/scripts/e2_policy_scalability.sh
```

## Docs

- [docs/HANDOFF.md](docs/HANDOFF.md) — what to give the coauthor
- [docs/integration/tdx_adapter_guide.md](docs/integration/tdx_adapter_guide.md) — how they wire `policy_server`
- [docs/evaluation/repo_mapping.md](docs/evaluation/repo_mapping.md) — component map
- [docs/evaluation/implementation_status.md](docs/evaluation/implementation_status.md) — status matrix

## Layout

| Path | Role |
|---|---|
| `protocol/` | Encode, registry, TEE adapters, launch/B_w FSM, dispatcher |
| `evaluation-assets/` | Policy join/coordinator/confirmer + fixtures |
| `evaluation/` | E1–E7 scripts (E2 runnable on mock) |
| `docs/` | Design, mapping, adapter guide |

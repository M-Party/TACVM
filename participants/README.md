# Participant components

Code that runs at **each TACVM participant** (not inside Operation/Workload CVM).

| Directory | Responsibility |
|---|---|
| `policy_confirmer/` | Verify candidate does not weaken local proposal; emit `TACVM-CONFIRM` |

Participants also authenticate the Operation CVM and submit `TACVM-PROPOSAL` /
`TACVM-ACCEPT`; those client flows are wired on the TDX host against
`policy_server` (see `docs/integration/tdx_adapter_guide.md`).

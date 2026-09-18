# TACVM Protocol Helpers

Portable canonical encoding for TACVM domain-separated hashes.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
pytest
```

```python
from tacvm_protocol import canonical_encode, hash_domain, get_tee_backend

digest = hash_domain(
    "TACVM-BOOT",
    {"n_i": "...", "pk_ch": "...", "d_M": "..."},
)

backend = get_tee_backend("mock")  # or TACVM_TEE_BACKEND=tdx
evidence = backend.generate_operation_quote(n_i="..", pk_ch="..", d_M="..")
```

Supported domains: `TACVM-BOOT`, `TACVM-ACCEPT`, `TACVM-POLICY`,
`TACVM-PROPOSAL`, `TACVM-CONFIRM`, `TACVM-WORKLOAD`,
`TACVM-WORKLOAD-ATTEST`, `TACVM-TRANS`.

Portable state machines in this package:

- `ParticipantRegistry` — TACVM-ACCEPT + all-registered barrier
- `WorkloadLaunchFSM` — `lambda_w` pending records + `B_w` lifecycle
- `TransitionDispatcher` — signed transition checks + mock local-state enforce

TEE adapters:

- `mock` — deterministic fake Quotes / provision / `B_w` for local tests
- `tdx` — explicit stub raising `ERR_TDX_ADAPTER_NOT_WIRED` until the coauthor
  wires `policy_server` / QVL / launch scripts (see
  `docs/integration/tdx_adapter_guide.md`)

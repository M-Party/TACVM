# TACVM Protocol Helpers

Portable canonical encoding for TACVM domain-separated hashes.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
pytest
```

```python
from tacvm_protocol import canonical_encode, hash_domain

digest = hash_domain(
    "TACVM-BOOT",
    {"n_i": "...", "pk_ch": "...", "d_M": "..."},
)
```

Supported domains: `TACVM-BOOT`, `TACVM-ACCEPT`, `TACVM-POLICY`,
`TACVM-PROPOSAL`, `TACVM-CONFIRM`, `TACVM-WORKLOAD`,
`TACVM-WORKLOAD-ATTEST`, `TACVM-TRANS`.

This package does not talk to TDX hardware. Coauthor hosts should reuse these
helpers (or an equivalent C++ port) when building REPORTDATA and signed
envelopes.

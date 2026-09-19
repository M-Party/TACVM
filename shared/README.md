# Shared protocol helpers

Cross-component libraries used by Operation CVM, participants, and evaluation.

| Path | Responsibility |
|---|---|
| `protocol/tacvm_protocol/encode.py` | Domain-separated canonical encode + hash |
| `protocol/tacvm_protocol/tee.py` | TEE adapter interface (`mock` / `tdx` stub) |
| `protocol/tacvm_protocol/backends/` | Mock Quotes/provision/binding; TDX stub |

These are not a separate online service. On the coauthor host, implement the
`tdx` backend against real QVL / launch scripts.

Full package root: `shared/protocol/`.

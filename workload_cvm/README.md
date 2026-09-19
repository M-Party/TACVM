# Workload CVM components

Code that runs inside the **Workload CVM**.

| Directory | Paper role | Responsibility |
|---|---|---|
| `trusted_service/` | Trusted Service | Authoritative local lifecycle state; reject wrong prior state / bad artifact before commit |

The Operation CVM `dispatcher/` authorizes requests and then invokes Trusted
Service enforcement. Secrets/commands must not be applied without a LIVE `B_w`
established by Operation CVM `workload_launch/`.

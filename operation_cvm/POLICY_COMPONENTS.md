# TACVM Policy Agreement Components

The prototype is divided into three implementation units with one shared wire
contract.

| Component | Path | Runs at | Input | Output | Does not do |
|---|---|---|---|---|---|
| Policy aggregation | `operation_cvm/policy_aggregation/` | Operation CVM | Round context, manifest participant order, one verified proposal per participant | Candidate policy and canonical digest | Keys, transport, confirmation collection, activation |
| Policy coordinator | `operation_cvm/policy_coordinator/` | Operation CVM | Participant-key map, signed proposals, signed confirmations | Candidate messages and active immutable policy snapshot | Participant-side policy decisions, workload authorization |
| Policy confirmer | `participants/policy_confirmer/` | Each participant | Own proposal, expected round, received candidate, policy private key | One signed `TACVM-CONFIRM` | Proposal aggregation, checking other participants' identities, activation |

## Message sequence

```text
Operation CVM -> participants: TACVM-POLICY-REQUEST(pid, version, round)
participants -> Operation CVM: TACVM-PROPOSAL(..., H(proposal))

Operation CVM -> aggregation core: verified proposals
aggregation core -> Operation CVM: candidate, H(candidate)

Operation CVM -> each participant: TACVM-POLICY-CANDIDATE(candidate, H(candidate))
each participant -> Operation CVM: TACVM-CONFIRM(..., H(candidate))

Operation CVM: verify all confirmations and atomically activate candidate
Operation CVM -> participants: TACVM-POLICY-ACTIVATED(..., H(candidate))
```

The candidate becomes an active authorization policy only at the activation
step. Reference implementations live under `operation_cvm/policy_aggregation/`,
`operation_cvm/policy_coordinator/`, and `participants/policy_confirmer/`; they
are libraries/FSMs, not external services in the deployed TACVM architecture.

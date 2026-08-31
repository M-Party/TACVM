# TACVM Policy Agreement Components

The prototype is divided into three implementation units with one shared wire
contract.

| Component | Runs at | Input | Output | Does not do |
|---|---|---|---|---|
| `policy-aggregation-core` | Inside the Operation CVM | Round context, manifest participant order, one verified proposal per participant | Candidate policy and canonical digest | Keys, transport, confirmation collection, activation |
| `operation-cvm-policy-coordinator` | Inside the Operation CVM | Participant-key map, signed proposals, signed confirmations | Candidate messages and active immutable policy snapshot | Participant-side policy decisions, workload authorization |
| `participant-policy-confirmer` | At each participant | Own proposal, expected round, received candidate, policy private key | One signed `TACVM-CONFIRM` | Proposal aggregation, checking other participants' identities, activation |

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
step. `evaluation-assets/` contains reference and test code for these units; it
is not an external service in the deployed TACVM architecture.

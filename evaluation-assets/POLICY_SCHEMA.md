# TACVM Policy Schema and Test Checklist

This document defines the provisional policy format used by the TACVM policy
agreement prototypes. Policies name every governed object, defaults are
explicit, every field has a deterministic restrictive join, and an incompatible
join returns `BOTTOM` instead of silently dropping a constraint.

## 1. Policy objects

| TACVM field | Template section | What a participant constrains | Join rule |
|---|---|---|---|
| Context | `context` | Policy identifier, version, and negotiation round | Exact equality |
| \(M_i\) | `roles` | Mapping from manifest participant identifiers to protocol roles | Compatible union, conflict otherwise |
| \(V_i\) | `workload_cvms` | TDX measurements, platform status, rootfs identity, launch context, and channel-binding requirements | Intersection of accepted values and conjunction of required checks |
| \(A_i\) | `artifacts` | Artifact identifiers, content digests, encryption requirements, and authorized registrars | Intersection |
| \(S_i\) | `secret_release` | Destination, operation, artifact, state, and channel conditions for releasing a secret | Conjunction |
| \(C_i\) | `communications` | Direction, protocol, endpoint, and authenticated peer identity | Intersection |
| \(T_i^o\) | `lifecycle` | Which participant identifier or role may request each lifecycle edge | Intersection per requester, workload, and operation |

`T_i^o` governs lifecycle phases only. Artifact digests remain in \(A_i\). The
Trusted Service records the actual phase and current artifact digest, while the
Operation CVM checks the requested phase edge and artifact rule separately.

## 2. Required checklist

### Common context

- This aggregation layer begins after the Operation CVM has verified one signed
  acceptance from every manifest participant. Those acceptances form the
  internal ordered map `R[participant_id] -> policy_public_key`. The shared
  proposal-round context contains only `policy_id`, `version`, and `round`.
- `schema` is a supported policy-schema version.
- `policy_id`, `version`, and `round` exactly match the proposal request issued
  by the Operation CVM. The initial policy uses version 1. A failed attempt
  increments the round without changing the target version.
- The Operation CVM derives `policy_id` as
  `H(Encode("TACVM-POLICY", boot_manifest_digest,
  operation_cvm_channel_key))`.
- `author.participant_id` is present in the fixed boot manifest, and the
  proposal signature verifies with the policy key bound in that participant's
  signed Operation CVM acceptance.
- The proposal is canonically encoded before hashing and signing.
- Duplicate YAML mapping keys are rejected. Test fixtures may use YAML anchors,
  which are resolved before normalization and hashing. Strict unknown-field
  handling and the production canonical wire encoding remain provisional.

### Defaults

- Every map declares `ANY` or `DENY` for an unlisted identifier.
- `ANY` means that this participant adds no restriction. It never overrides a
  restriction submitted by another participant.
- `DENY` means that this participant prohibits every unlisted identifier.
- Production policies should normally be deny by default. A participant uses
  `ANY` only for fields it intentionally delegates to the other proposals.

### Roles

- Every role refers to a protocol identifier registered in the boot manifest,
  not necessarily a legal or organizational identity.
- Two proposals assigning different roles to the same participant identifier
  cause `BOTTOM`.
- A lifecycle or artifact rule referring to an unmapped role is invalid.

### Workload CVM identity

- Name every Workload CVM class that may be launched.
- Declare accepted TDX measurements and Quote-verification status predicates.
- Declare how the root filesystem is identified. The prototype must choose
  either a complete image digest or a dm-verity root hash and report which path
  is used in each experiment.
- Require the measured launch context to bind the Workload CVM identifier,
  `policy_id`, and the authenticated Operation CVM channel public key.
- Require the single post-boot Quote to bind a fresh challenge,
  `H(launch_context)`, and the Trusted Service channel key generated after
  startup. The active policy version and digest remain in the Operation CVM's
  pending launch record rather than the launch context or `REPORTDATA`.

### Artifacts

- Give every artifact a stable identifier and semantic type.
- List acceptable plaintext content digests.
- State whether encryption is required.
- List the participant identifiers or roles allowed to register its signed
  manifest. This prevents another participant from registering an artifact
  under an identifier it is not authorized to control.

### Secret release

- Name every secret or artifact key.
- Bind release to an authenticated Workload CVM class and channel binding.
- Bind release to the intended artifact and operation where applicable.
- Express conditions as structured fields combined with logical `AND`. Do not
  accept executable policy code.
- A missing or unsatisfied condition denies release.

### Communication

- Specify ingress or egress, transport protocol, endpoint, and port range.
- Pin an authenticated peer identity when endpoint impersonation is in scope.
- An empty joined endpoint set disables that communication profile.

### Lifecycle

- Use the current operation set `admit`, `update`, `stop`, and `delete`.
- Define phases independently of artifact digests. The initial test state machine
  is `absent -> running -> stopped -> absent`, with `running -> running` for an
  update.
- Name one allowed requester identifier or role for every rule.
- An empty joined rule set denies that requester the operation. It does not abort
  the entire policy unless the deployment separately marks that operation as
  required.
- `resume` is not currently part of the paper's operation set. A stopped workload
  cannot resume without an explicit future design decision.

### Activation and provenance

- The Operation CVM policy coordinator collects exactly one authenticated
  proposal per participant in the boot manifest.
- The policy aggregation core joins the proposals in boot-manifest order,
  although the join should also satisfy commutativity, associativity, and
  idempotence. It records `(participant_id, proposal_digest)` for every input.
- The coordinator sends the complete candidate and its digest to every
  participant over that participant's authenticated channel.
- Each participant policy confirmer checks the candidate against its local
  proposal and returns a signed confirmation.
- The coordinator verifies confirmations with the policy keys bound during
  Operation CVM acceptance. It publishes the candidate atomically only after
  every manifest participant confirms the same `policy_id`, version, round,
  and candidate digest.

The signed protocol envelopes are:

```text
TACVM-PROPOSAL, participant_id, policy_id, version, round, H(proposal)
TACVM-CONFIRM, participant_id, policy_id, version, round, H(candidate)
```

The candidate contains the round context, the ordered
`(participant_id, proposal_digest)` inputs, and the joined policy. The Open
Policy Parser uses `R[participant_id]` to verify both envelopes.

## 3. Restrictive join oracle

The policy implementation should expose a test oracle with these rules:

1. Context mismatch returns `REJECT_CONTEXT` before policy joining.
2. Exact-value conflicts and incompatible role assignments return `BOTTOM`.
3. Allowlist fields join by set intersection.
4. Exact-value fields must agree, while accepted-status allowlists are
   intersected.
5. Boolean `require_*` flags combine with logical OR: if any participant
   requires a check, the candidate requires it. This represents conjunction of
   the participants' required checks.
6. Secret-release conditions join by conjunction after canonical normalization.
7. Lifecycle rules join by intersection for the same requester and object.
8. For every successful candidate \(\pi\), the behaviors accepted by \(\pi\)
   must be a subset of the behaviors accepted by every input proposal.

The last property is the main property-based test for the Open Policy Parser.

## 4. Policy profile catalog for evaluation

Keep these profiles stable across the evaluation and record their canonical
digests in every run manifest.

| Profile | Contents | Expected use |
|---|---|---|
| P0 `single-permissive` | One participant, explicit `ANY` for non-security-critical fields, one allowed lifecycle path | Fixed-cost and parser baseline |
| P1 `single-strict` | One participant, pinned Workload CVM, rootfs, artifact, secret, endpoint, and requester | Full single-party enforcement baseline |
| P2 `three-party-compatible` | The supplied model-owner, data-owner, and operator fixture | Main successful multi-party join and end-to-end run |
| P3 `join-conflict` | Conflicting role, Workload CVM identity, or artifact digest | Conflict detection and fail-closed behavior |
| P4 `lifecycle-deny` | Valid candidate with an empty edge set for one requester and operation | Verify that one operation is disabled without aborting the policy |
| P5 `secret-deny` | Valid lifecycle rule but unsatisfied Workload CVM, artifact, or channel condition | Key-vault negative tests |
| P6 `policy-update` | Version 2 changes one accepted artifact digest and one lifecycle edge | Update latency, stale-version rejection, and existing-binding revalidation |
| P7 `scale-generated` | Synthetic policies with 10 to 10,000 named objects and rules | Parser time and memory scaling only |

P0 is not a production recommendation. P7 should not be used as evidence of a
realistic deployment unless its object distribution matches an actual use case.

## 5. Files

- `policy-aggregation-core/templates/participant-proposal.yaml` is the commented
  participant-proposal template. The signed proposal envelope is deliberately
  separate from this policy body.
- `policy-aggregation-core/fixtures/three-party-proposals.yaml` contains the
  three proposals used by the Python tests and end-to-end demo.
- `policy-aggregation-core/` implements the stateless restrictive join.
- `operation-cvm-policy-coordinator/` implements candidate distribution,
  confirmation collection, and activation inside the Operation CVM.
- `participant-policy-confirmer/` implements participant-side candidate
  verification and confirmation signing.
- `EVALUATION_PLAN.md` maps policy and protocol claims to experiments.
- `results/run-manifest-template.yaml` records an experiment's environment and
  factors.
- `results/measurements-template.csv` defines the common raw-result columns.

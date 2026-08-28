# TACVM Policy Template and Test Checklist

This document defines a provisional policy format for prototype evaluation. It
adapts four ideas from `SRAS/main.tex`: policies name every governed object,
wildcards are explicit, every field has a deterministic restrictive join, and
an incompatible join returns `BOTTOM` instead of silently dropping a
constraint. It does not copy SRAS's SGX-specific RPE and enclave fields.

## 1. Policy objects

| TACVM field | Template section | What a participant constrains | Join rule |
|---|---|---|---|
| Context | `context` | Policy identifier, version, round, and roster digest | Exact equality |
| \(M_i\) | `roles` | Mapping from boot slots to protocol roles | Compatible union, conflict otherwise |
| \(V_i\) | `workload_cvms` | TDX measurements, platform status, rootfs identity, launch context, and channel-binding requirements | Intersection of accepted values and conjunction of required checks |
| \(A_i\) | `artifacts` | Artifact identifiers, content digests, encryption requirements, and authorized registrars | Intersection |
| \(S_i\) | `secret_release` | Destination, operation, artifact, state, and channel conditions for releasing a secret | Conjunction |
| \(C_i\) | `communications` | Direction, protocol, endpoint, and authenticated peer identity | Intersection |
| \(T_i^o\) | `lifecycle` | Which slot or role may request each lifecycle edge | Intersection per requester, workload, and operation |

`T_i^o` governs lifecycle phases only. Artifact digests remain in \(A_i\). The
Trusted Service records the actual phase and current artifact digest, while the
Operation CVM checks the requested phase edge and artifact rule separately.

## 2. Required checklist

### Common context

- `schema` is a supported policy-schema version.
- `policy_id`, `version`, `round`, and `roster_digest` exactly match the proposal
  request issued by the Operation CVM.
- `author.slot` is present in the boot-bound roster.
- The proposal is canonically encoded before hashing and signing.
- Unknown fields, duplicate keys, aliases, and non-canonical encodings are
  rejected.

### Defaults

- Every map declares `ANY` or `DENY` for an unlisted identifier.
- `ANY` means that this participant adds no restriction. It never overrides a
  restriction submitted by another participant.
- `DENY` means that this participant prohibits every unlisted identifier.
- Production policies should normally be deny by default. A participant uses
  `ANY` only for fields it intentionally delegates to the other proposals.

### Roles

- Every role refers to a roster slot, not a legal or organizational identity.
- Two proposals assigning different roles to the same slot cause `BOTTOM`.
- A lifecycle or artifact rule referring to an unmapped role is invalid.

### Workload CVM identity

- Name every Workload CVM class that may be launched.
- Declare accepted TDX measurements and Quote-verification status predicates.
- Declare how the root filesystem is identified. The prototype must choose
  either a complete image digest or a dm-verity root hash and report which path
  is used in each experiment.
- Require the measured launch context to bind the Workload CVM identifier,
  `policy_id`, and the authenticated Operation CVM channel public key.
- Require a second Quote to bind the Trusted Service channel key generated after
  startup.

### Artifacts

- Give every artifact a stable identifier and semantic type.
- List acceptable plaintext content digests.
- State whether encryption is required.
- List the slots or roles allowed to register its signed manifest. This extends
  the current paper's \(A_i\) field and prevents an arbitrary roster member from
  registering another participant's artifact identifier.

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
- Name one allowed requester slot or role for every rule.
- An empty joined rule set denies that requester the operation. It does not abort
  the entire policy unless the deployment separately marks that operation as
  required.
- `resume` is not currently part of the paper's operation set. A stopped workload
  cannot resume without an explicit future design decision.

### Activation and provenance

- Collect exactly one authenticated proposal per roster slot.
- Join proposals in canonical slot order, although the join should also satisfy
  commutativity, associativity, and idempotence.
- Record the ordered pair `(slot, proposal_digest)` for every input.
- Return the complete candidate and its digest to each participant for final
  confirmation.
- Publish the candidate atomically only after every roster slot confirms the
  same digest.

## 3. Restrictive join oracle

The policy implementation should expose a test oracle with these rules:

1. Context mismatch returns `REJECT_CONTEXT` before policy joining.
2. Exact-value conflicts and incompatible role assignments return `BOTTOM`.
3. Allowlist fields join by set intersection.
4. Minimum-version or minimum-status requirements select the stronger minimum.
5. Boolean requirements join by conjunction.
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

- `policies/tacvm-policy-template.yaml` is the commented participant-proposal
  template.
- `policies/three-party-example.yaml` contains three proposals and their expected
  joined constraints.
- `experiment-plan.md` maps policy and protocol claims to experiments.
- `results/run-manifest-template.yaml` records an experiment's environment and
  factors.
- `results/measurements-template.csv` defines the common raw-result columns.

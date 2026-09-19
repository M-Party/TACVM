# TACVM Design & Implementation Specification for Cursor

**Target:** Current TACVM codebase  
**Paper basis:** *TACVM: Trusted and Verifiable Runtime Workload Control in Confidential Virtual Machines* (latest uploaded revision)  
**Purpose:** Implement the paper design faithfully, preserve existing working code where possible, add missing protocol/state-management logic, and expose the instrumentation required by the final evaluation.

---

## 0. How Cursor Should Use This Document

This document is the implementation contract for the current TACVM prototype.

Before changing code, Cursor must:

1. Inspect the repository and identify the existing implementation corresponding to:
   - Operation CVM attestation / participant verification.
   - `policy_server`.
   - DCAP/QVL quote verification and appraisal.
   - policy proposal/reconciliation logic.
   - Workload CVM guest launcher / Trusted Service logic.
   - `launch-client.sh`.
   - `cvm-fleet-test.sh`.
   - VM launch/provisioning scripts.
2. Reuse the existing protocol and code paths instead of implementing a second parallel stack.
3. Produce a mapping from this specification to actual repository files before large refactors.
4. Preserve already validated concurrency fixes:
   - globally unique client IDs using `CVM_INSTANCE_ID`;
   - synchronization for `pending_challenges_` and `sessions_`;
   - process-wide serialization of the DCAP QVL/appraisal sequence unless thread safety is independently demonstrated.
5. Treat the paper protocol semantics below as authoritative. If existing code conflicts with the paper, flag the conflict before silently changing protocol semantics.
6. Fail closed: a missing, malformed, stale, replayed, mismatched, or unauthenticated object must not enable policy activation, live binding, secret release, or workload state transition.

Do **not** optimize away security checks merely to improve benchmark results.

---

# 1. System Security Model and Core Invariants

TACVM establishes two authority links:

```text
Participants
    │
    │ authenticate + jointly activate policy
    ▼
Operation CVM
    │
    │ authenticate Workload CVM + establish live binding
    ▼
Trusted Service in Workload CVM
    │
    │ verify local prior state + artifact
    ▼
Controlled Workload State
```

The implementation must preserve the following invariants.

## I1. No Operation CVM authority before joint trust establishment

A newly launched Operation CVM has **no workload-control authority**.

Authority becomes enabled only after:

```text
Operation CVM protected boot
→ all required participants authenticate the same running instance
→ all participant policy keys are registered
→ one valid policy proposal from every participant is collected
→ a candidate policy is constructed
→ all participants confirm the same candidate
→ candidate is atomically activated
```

Before the final activation barrier:

```text
workload_control_enabled == false
```

## I2. All participants authenticate the same Operation CVM instance

The current Operation CVM channel public key `pk_ch` and fixed deployment manifest digest `d_M` are bound into participant-specific attestation evidence:

```text
r_i = H(Encode(
    "TACVM-BOOT",
    n_i,
    pk_ch,
    d_M
))
```

A successful participant acceptance is valid only for the current:

```text
deployment manifest
Operation CVM channel key
participant identity
participant policy key
```

## I3. Participant registration is unique

For each participant `id_i`:

- it must exist in the boot manifest;
- only one acceptance is valid for the current instance;
- one policy public key may not be bound to two different participant identities;
- invalid boot-key signature or invalid policy-key proof is rejected;
- policy collection cannot begin until all manifest participants are registered.

## I4. Active policy is immutable

Once activated, a policy snapshot is identified by:

```text
pid
version v
round r
H(pi)
```

The active snapshot is immutable.

A policy update must create a new candidate. The old active policy remains active until the new candidate is unanimously confirmed and atomically activated.

A failed update must not partially modify the active policy.

## I5. Workload CVM trust is launch-specific

Every Workload CVM launch receives a fresh instance identifier `w` and launch context:

```text
lambda_w = Encode(
    "TACVM-WORKLOAD",
    w,
    pid,
    pk_ch
)
```

The Operation CVM stores `lambda_w` as a pending launch record.

A Workload CVM can become authenticated only if its measured state contains the expected `H(lambda_w)` and satisfies the active policy.

A consumed or expired launch context must not authenticate another launch.

## I6. Live binding is instance-specific

After successful Workload CVM attestation, TACVM establishes:

```text
B_w
```

which binds:

```text
instance w
Trusted Service channel public key pk_w
attested Workload CVM identity/state
current authenticated channel
```

No workload, secret, or transition command may be released to the Workload CVM before `B_w` is live.

Restart or loss of the authenticated channel invalidates `B_w`.

## I7. Authorization precedes execution

For a requested transition:

```text
S_i --o--> S_i+1
```

the Operation CVM must authorize the transition **before** the Trusted Service applies it.

## I8. Execution is bound to actual local state

The Trusted Service must verify immediately before applying a transition:

```text
S_actual == S_i
```

and, when applicable, verify the expected artifact.

If any check fails:

```text
workload state remains unchanged
no new secret is released
transition result == rejected
```

## I9. Security-relevant workload operations use one exclusive enforcement path

Creation, mounting, execution, replacement, stop, and deletion must be mediated by the Trusted Service.

Do not leave an alternative privileged interface that can make the same state changes while bypassing policy checks.

## I10. Replay resistance

At minimum, the implementation must prevent replay of:

```text
participant challenges
participant acceptances
policy proposals
policy confirmations
Workload CVM launch contexts
transition operation IDs
```

---

# 2. Architecture Components

## 2.1 Participants

Each participant has:

```text
participant_id
boot signing key pair
policy signing key pair
policy proposal
accepted deployment manifest digest
```

Logical responsibilities:

- approve deployment manifest;
- authenticate the running Operation CVM;
- bind a policy key to its identity;
- submit a signed proposal;
- verify the candidate policy does not weaken its own proposal;
- confirm the candidate.

Participants are **not** on the critical path of ordinary runtime workload transitions after policy activation.

---

## 2.2 Operation CVM

The Operation CVM is the common trusted control plane.

It contains four logical services:

```text
Open Policy Parser
Quote Verifier
Key Vault
Workload Dispatcher
```

It also maintains the state required for:

```text
participant enrollment
policy rounds
active policy
pending Workload CVM launches
live Workload CVM bindings
registered artifacts
outstanding operations
```

The cloud may launch the Operation CVM but must not gain policy or transition authorization authority.

---

## 2.3 Open Policy Parser

Responsibilities:

- create policy rounds;
- validate signed proposals;
- reject duplicates/malformed/stale proposals;
- perform restrictive join;
- construct candidate policy;
- distribute candidate;
- validate confirmations;
- atomically activate policy.

The parser is the **producer/activator** of policy state. Quote Verifier, Key Vault, and Workload Dispatcher are consumers/enforcers of the active policy.

---

## 2.4 Quote Verifier

Responsibilities:

- verify TDX certificate chain/platform status;
- verify REPORTDATA;
- replay/validate measured event log against RTMRs;
- verify expected initrd measurement;
- verify canonical dm-verity mapping;
- validate Workload CVM launch context;
- validate Workload CVM measurements/configuration against active policy.

Existing QVL/appraisal code should be reused.

---

## 2.5 Key Vault

Responsibilities:

- receive and store protected artifact keys separately from artifact ciphertext;
- associate each key with artifact metadata and authorization conditions;
- never release a key merely because a Workload CVM exists;
- release only after Dispatcher authorization against:
  - active policy;
  - valid `B_w`;
  - requested operation;
  - artifact;
  - relevant policy conditions.

Key material must not be written to normal logs or evaluation CSVs.

---

## 2.6 Workload Dispatcher

Responsibilities:

- authenticate runtime requester;
- verify transition request signature;
- verify `pid` and `H(pi)`;
- verify target `w`;
- require live `B_w`;
- check requested operation/state transition against active policy;
- coordinate conditional key release;
- dispatch authorized command and material through the authenticated Workload CVM channel;
- track outstanding operation ID `u`;
- accept a completion result only for a matching outstanding request.

---

## 2.7 Workload CVM Trusted Service

The Trusted Service is the exclusive privileged workload enforcement path.

Responsibilities:

- participate in measured boot;
- load `lambda_w`;
- generate fresh `(sk_w, pk_w)`;
- create attestation evidence binding `n_w`, `H(lambda_w)`, and `pk_w`;
- establish authenticated channel with Operation CVM;
- maintain authoritative local workload state;
- reject replayed operation IDs;
- verify prior state;
- verify artifact before execution;
- invoke local runtime only after all checks succeed;
- update local state only after successful execution;
- return authenticated result to Operation CVM.

The Trusted Service does **not** independently redefine policy.

---

# 3. Canonical Data Structures

Cursor may map these structures to existing C++/protobuf/JSON types. Do not create duplicate representations if equivalent types already exist.

## 3.1 BootManifest

```text
BootManifest {
    deployment_id
    expected_initrd_measurement: d_I
    canonical_dm_verity_mapping
    expected_root_hash: d_R

    participants: [
        {
            participant_id
            protocol_id
            boot_public_key
        }
    ]
}
```

Derived:

```text
d_M = H(CanonicalEncode(BootManifest))
```

Requirements:

- deterministic/canonical encoding;
- fixed before Operation CVM launch;
- participants verify their own registration before accepting it;
- manifest contents are immutable for the deployment.

---

## 3.2 OperationChannelIdentity

```text
OperationChannelIdentity {
    sk_ch
    pk_ch
}
```

Generated fresh after protected Operation CVM startup.

Private key never leaves Operation CVM.

---

## 3.3 ParticipantAcceptance

Conceptual signed body:

```text
Encode(
    "TACVM-ACCEPT",
    participant_id,
    d_M,
    pk_ch,
    pk_policy_i
)
```

Signatures:

```text
boot_key_signature
policy_key_signature
```

Purpose:

- boot key authorizes acceptance and policy-key registration;
- policy key proves possession.

---

## 3.4 ParticipantRegistry

```text
ParticipantRegistry {
    participant_id -> {
        policy_public_key
        acceptance_status
    }
}
```

The internal ordered map `R` must follow manifest participant order:

```text
R = <e_1, ..., e_N>
e_i = <id_i, pk_policy_i>
```

---

## 3.5 PolicyRound

```text
PolicyRound {
    pid
    target_version: v
    round: r
    status:
        COLLECTING
        JOINING
        CANDIDATE_READY
        CONFIRMING
        ACTIVATED
        FAILED

    proposals[participant_id]
    proposal_hashes[participant_id]
    confirmations[participant_id]
    candidate_policy
    candidate_hash
}
```

Derived:

```text
pid = H(Encode(
    "TACVM-POLICY",
    d_M,
    pk_ch
))
```

---

## 3.6 PolicyProposal

Conceptual signature body:

```text
Encode(
    "TACVM-PROPOSAL",
    participant_id,
    pid,
    v,
    r,
    H(rho_i)
)
```

Each proposal follows a typed schema.

At minimum support paper categories:

```text
defaults
roles
workload_cvms
artifacts
secret_release
communications
lifecycle
```

Example policy semantics from the paper:

```yaml
defaults: DENY

roles:
  id_O: service_operator

workload_cvms:
  inference:
    measurements: [m_w]
    configurations: [c_w]

artifacts:
  model: [h_m]
  dataset: [h_d]

secret_release:
  dataset_key:
    workload_cvm: inference
    operations: [admit]
    requires: [authenticated_workload_binding]

communications:
  result_channel:
    direction: egress
    endpoint: e_result
    protocol: TLS

lifecycle:
  inference:
    admit:
      service_operator: [[absent, running]]
    stop:
      service_operator: [[running, stopped]]
    update: DENY
    delete:
      service_operator: [[stopped, absent]]
```

---

## 3.7 CandidatePolicy / ActivePolicySnapshot

```text
CandidatePolicy {
    pid
    v
    r

    ordered_proposals: [
        <participant_id, proposal_hash>
    ]

    joined_constraints
}
```

Active snapshot:

```text
ActivePolicySnapshot {
    CandidatePolicy pi
    policy_hash: H(pi)
    activation_time
}
```

Atomic publication is required.

Readers must never observe a partially updated policy.

---

## 3.8 PendingLaunchRecord

```text
PendingLaunchRecord {
    w
    pid
    pk_ch
    lambda_w
    lambda_hash
    status:
        PENDING
        AUTHENTICATING
        CONSUMED
        INVALID
}
```

Derived:

```text
lambda_w = Encode(
    "TACVM-WORKLOAD",
    w,
    pid,
    pk_ch
)
```

`w` must be globally unique for the deployment or generated from a cryptographically strong random identifier.

Do not reuse `w`.

---

## 3.9 LiveBinding

```text
LiveBinding {
    w
    pk_w
    authenticated_channel_id
    attestation_identity
    policy_namespace: pid
    status: LIVE | INVALID
}
```

The binding must be invalidated on channel loss or Workload CVM restart.

---

## 3.10 ArtifactRecord

```text
ArtifactRecord {
    artifact_id
    owner_id

    ciphertext_digest
    plaintext_digest
    encryption_scheme

    signed_metadata
    ciphertext_location_or_handle

    key_handle
}
```

Keep key material separate from ciphertext metadata.

---

## 3.11 TransitionRequest

Conceptual encoding:

```text
q_i = Encode(
    "TACVM-TRANS",
    participant_id,
    pid,
    H(pi),
    operation_id: u,
    workload_cvm_id: w,
    operation: o,
    prior_state: s,
    next_state: s_prime,
    artifact_digest: h_a
)
```

The requester signs `q_i` using its registered policy private key.

---

## 3.12 Trusted Service Workload State

The Trusted Service must maintain an authoritative local state such as:

```text
WorkloadState {
    workload_name_or_slot
    lifecycle_state:
        ABSENT
        RUNNING
        STOPPED

    accepted_artifact_digest
    runtime_instance_handle
    last_successful_operation_id
}
```

Do not let Operation CVM's remote view replace this local state check.

The local state is the final authority immediately before execution.

---

# 4. Canonical Encoding and Cryptographic Domain Separation

The paper uses `Encode(...)` and domain strings such as:

```text
TACVM-BOOT
TACVM-ACCEPT
TACVM-POLICY
TACVM-PROPOSAL
TACVM-CONFIRM
TACVM-WORKLOAD
TACVM-TRANS
```

Implement one common canonical encoder.

Requirements:

1. deterministic field ordering;
2. unambiguous length-prefixing or canonical structured encoding;
3. fixed integer representation;
4. no JSON whitespace/key-order dependence unless canonical JSON is explicitly implemented;
5. reject unknown mandatory fields;
6. version the encoding if the format may evolve;
7. every hash/signature uses the correct domain string.

Do **not** sign ad-hoc string concatenations in different modules.

Recommended abstraction:

```text
CanonicalEncode(domain, typed_fields...) -> bytes
HashDomain(domain, typed_fields...) -> digest
SignDomain(private_key, domain, typed_fields...) -> signature
VerifyDomain(public_key, signature, domain, typed_fields...) -> bool
```

Reuse the repository's existing cryptographic library.

---

# 5. Operation CVM Protected Boot

This section implements paper Sec. 5.1.

## 5.1 Root Filesystem Protection

The Operation CVM root filesystem contains:

```text
Open Policy Parser
Quote Verifier
Key Vault
Workload Dispatcher
security configuration
```

The initrd must configure the root filesystem as read-only using dm-verity.

The measured event record must include at least:

```text
root hash d_R
hash algorithm
data device identity / canonical identifier
hash device identity / canonical identifier
block sizes
verity tree parameters
security-relevant dm-verity options
```

Create a canonical structure:

```text
DmVerityMeasurementRecord
```

During early boot:

```text
record = CanonicalEncode(DmVerityMeasurementRecord)
event_log.append(record)
RTMR_x = Extend(RTMR_x, H(record))
configure dm-verity
switch_root
```

A participant must later be able to replay the event log and verify that the RTMR value matches the Quote.

---

## 5.2 Boot Manifest

Provide an offline/deployment-time tool or reuse existing deployment tooling to:

1. collect participant identities/protocol IDs/boot public keys;
2. capture expected initrd measurement `d_I`;
3. capture canonical dm-verity mapping and root hash `d_R`;
4. construct `BootManifest`;
5. canonicalize and hash it to `d_M`;
6. export the exact manifest participants will accept.

Suggested generated artifacts:

```text
deployment/boot_manifest.bin
deployment/boot_manifest.json        # human-readable mirror only
deployment/boot_manifest.sha256
```

The binary/canonical representation is authoritative.

---

## 5.3 Operation CVM Startup State Machine

Suggested state machine:

```text
BOOTING
  ↓
PROTECTED_ROOT_READY
  ↓
CHANNEL_KEY_READY
  ↓
WAITING_FOR_PARTICIPANTS
  ↓
PARTICIPANTS_AUTHENTICATED
  ↓
POLICY_NEGOTIATION
  ↓
POLICY_ACTIVE
```

Any workload-control RPC received before `POLICY_ACTIVE` must fail.

---

# 6. Participant Authentication of Operation CVM

This implements Figure 4 / Sec. 5.1.

## 6.1 Challenge

Participant `i` creates fresh:

```text
n_i = 32 random bytes
```

Challenge freshness must be enforced.

Existing challenge/session server state must remain thread-safe.

Known required synchronization:

```text
pending_challenges_
sessions_
```

must not be read/written concurrently without `state_mutex_` or an equivalent synchronization mechanism.

Client identifiers must remain globally unique across CVMs/processes.

Current convention:

```text
cvm_01_client_01
cvm_01_client_02
...
cvm_16_client_02
```

Do not revert to `client_01`, `client_02` globally.

---

## 6.2 Quote Construction

Operation CVM computes:

```text
r_i = H(Encode(
    "TACVM-BOOT",
    n_i,
    pk_ch,
    d_M
))
```

and requests a TDX Quote with:

```text
REPORTDATA = r_i
```

Return:

```text
Quote
measured event log
pk_ch
manifest/deployment identifier as needed
```

Do not place secrets in REPORTDATA.

---

## 6.3 Participant Verification

Participant verifies:

```text
TDX certificate chain
platform/TCB status
fresh challenge n_i
REPORTDATA exact match
event-log replay == Quote RTMRs
expected initrd measurement d_I
expected dm-verity mapping/root hash
manifest digest d_M
proof of possession of sk_ch / authenticated channel
```

Only then issue acceptance.

---

## 6.4 Policy-Key Registration

Participant signs:

```text
m_i = Encode(
    "TACVM-ACCEPT",
    id_i,
    d_M,
    pk_ch,
    pk_policy_i
)
```

with:

```text
boot private key
policy private key
```

Operation CVM must reject:

```text
unknown participant ID
manifest mismatch
pk_ch mismatch
invalid boot signature
invalid policy-key proof
duplicate acceptance
same policy key already bound to another participant
```

On success:

```text
R[id_i] = pk_policy_i
```

Policy collection starts only when:

```text
registered_participants == manifest_participants
```

---

# 7. Policy Construction and Activation

This implements paper Sec. 5.2.

## 7.1 Round Creation

After all policy keys are registered:

```text
pid = H(Encode(
    "TACVM-POLICY",
    d_M,
    pk_ch
))
```

Initial policy:

```text
v = 1
r = 0 or 1
```

Policy update:

```text
v = active.v + 1
r = initial round number
```

Join/negotiation retry:

```text
v unchanged
r = r + 1
```

---

## 7.2 Proposal Validation

For each participant:

```text
signed_body = Encode(
    "TACVM-PROPOSAL",
    id_i,
    pid,
    v,
    r,
    H(rho_i)
)
```

Reject:

```text
unknown id
invalid signature
wrong pid
wrong v
wrong r
duplicate submission
malformed proposal
unsupported schema/version
unknown mandatory field/operator
```

A missing proposal means the round remains incomplete. Do not activate with a partial participant set.

---

## 7.3 Restrictive Join

The join must never silently widen authority.

General rules:

```text
ANY + constraint     -> constraint
DENY + permission    -> DENY / empty permission
set A + set B        -> intersection
allowed transitions  -> intersection by requester/role and state pair
required attributes  -> intersection / compatible conjunction
```

The exact join is category-specific.

Implementation should expose one typed join function per policy category, for example:

```text
join_roles()
join_workload_cvms()
join_artifacts()
join_secret_release()
join_communications()
join_lifecycle()
```

Do not implement one generic string-merging function.

A restrictive join may remove permission without making the whole policy inconsistent.

Examples:

```text
participant A permits model digests {h_m}
participant B permits {h_m, h_m2}
result = {h_m}
```

```text
participant A denies update
participant B permits update
result = update denied
```

The round fails only when the remaining constraints cannot support a required object or are semantically incompatible, e.g.:

```text
no common digest for a required model
same participant assigned incompatible roles
```

---

## 7.4 Candidate Construction

Candidate contains:

```text
pid
v
r
ordered <participant_id, H(proposal)> entries
joined constraints
```

Compute:

```text
candidate_hash = H(pi)
```

Canonical ordering must match `R` / manifest order.

---

## 7.5 Candidate Confirmation

Participant verifies:

1. its own proposal digest is present at the correct entry;
2. every behavior allowed by candidate `pi` is allowed by its own proposal `rho_i`.

Then signs:

```text
Encode(
    "TACVM-CONFIRM",
    id_i,
    pid,
    v,
    r,
    H(pi)
)
```

Operation CVM rejects mismatched confirmations.

---

## 7.6 Atomic Activation

Activate only after one valid confirmation from **every** participant for the exact same:

```text
pid
v
r
H(pi)
```

Use atomic publication, e.g.:

```text
shared_ptr<const ActivePolicySnapshot>
```

or equivalent immutable snapshot.

Do not mutate the existing active policy in place.

During an update:

```text
old active policy remains readable and enforceable
candidate built separately
new snapshot published only at activation barrier
```

---

# 8. Workload CVM Launch Context and Provisioning

This implements paper Sec. 5.3.

## 8.1 Create Fresh Launch Context

Before asking the platform to create a Workload CVM:

```text
w = FreshInstanceID()

lambda_w = Encode(
    "TACVM-WORKLOAD",
    w,
    active_policy.pid,
    pk_ch
)
```

Store:

```text
pending_launches[w] = {
    lambda_w,
    H(lambda_w),
    pid,
    pk_ch,
    status=PENDING
}
```

The launch context must be created before provisioning.

---

## 8.2 Provisioning Adapter

The cloud platform is untrusted and should receive `lambda_w` only as opaque launch data.

Create or reuse a provisioning adapter with a narrow interface:

```text
ProvisionWorkloadCVM(
    image/config,
    opaque_launch_context=lambda_w
) -> platform_instance_handle
```

The evaluation will measure provisioning separately, so expose timestamps:

```text
T_W_PROVISION_START
T_W_PROVISION_DONE
```

Do not put authorization logic in the cloud-side adapter.

---

## 8.3 Workload CVM Early Boot

The initrd obtains `lambda_w` through the configured launch-data mechanism.

Construct a canonical measurement record containing:

```text
H(lambda_w)
dm-verity root hash
security-relevant dm-verity parameters
```

Then:

```text
append to measured event log
extend digest into designated RTMR
configure read-only root filesystem with dm-verity
start protected root filesystem
start Trusted Service
```

The Trusted Service must reside on the protected root filesystem.

---

# 9. Workload CVM Authentication and Live Binding

## 9.1 Trusted Service Channel Identity

After protected root starts:

```text
Trusted Service reads:
    w
    pid
    pk_ch

Trusted Service generates:
    (sk_w, pk_w)
```

The key pair must be fresh per boot/live instance.

---

## 9.2 Workload Attestation Challenge

Operation CVM creates fresh:

```text
n_w
```

Trusted Service computes REPORTDATA binding:

```text
n_w
H(lambda_w)
pk_w
```

Use a domain-separated encoding such as:

```text
H(Encode(
    "TACVM-WORKLOAD-ATTEST",
    n_w,
    H(lambda_w),
    pk_w
))
```

If the current implementation already uses a specific paper-compatible domain label, preserve it consistently.

---

## 9.3 Operation CVM Verification

Verify:

```text
TDX certificate chain/platform status
REPORTDATA exact match
challenge freshness
event log replay vs Quote RTMRs
H(lambda_w) == pending launch record
initrd measurement
dm-verity root/configuration
active policy workload_cvms constraints
proof of possession of sk_w
```

Any failure leaves:

```text
binding == absent
pending launch not consumed as success
no workload
no secret
no transition command
```

---

## 9.4 Establish B_w

After verification:

1. establish authenticated channel to Trusted Service;
2. atomically consume the pending launch record;
3. create `B_w`;
4. mark binding LIVE.

Conceptually:

```text
B_w = {
    w,
    pk_w,
    channel_id,
    attestation_identity,
    pid,
    LIVE
}
```

The pending launch record must not remain reusable after successful binding.

---

## 9.5 Binding Invalidation

At minimum invalidate `B_w` when:

```text
authenticated channel closes unexpectedly
Trusted Service restarts
Workload CVM restarts
explicit teardown occurs
```

All later workload/secret/transition requests must re-check that the binding is LIVE.

Do not cache a boolean authorization result indefinitely.

---

# 10. Artifact Registration and Key Vault

This implements the model-admission example in Sec. 5.4.

## 10.1 Artifact Registration

Model provider supplies:

```text
ciphertext
signed artifact metadata:
    artifact_id
    plaintext digest
    ciphertext digest
    encryption scheme
```

Operation CVM verifies:

```text
provider identity/signature
ciphertext digest
metadata consistency
```

The corresponding key is sent separately to Key Vault.

---

## 10.2 Key Storage

Key Vault stores:

```text
artifact_id -> protected key handle
```

Do not co-locate raw key material in normal artifact metadata.

Never log:

```text
raw artifact key
plaintext secret
decrypted model
```

---

## 10.3 Release Gate

Key release requires all of:

```text
request authorized by active policy
target Workload CVM has LIVE B_w
requested operation permits release
artifact matches registered metadata
secret_release conditions satisfied
```

If the transition later fails before key use, do not release additional secrets. If a key has already been delivered over the authenticated channel, report this precisely in security-test logging rather than pretending it was not sent.

---

# 11. Workload Lifecycle Control

This implements Sec. 5.4.

## 11.1 Runtime Request

Requester creates:

```text
q_i = Encode(
    "TACVM-TRANS",
    id_i,
    pid,
    H(pi),
    u,
    w,
    o,
    s,
    s_prime,
    h_a
)
```

and signs it with the registered policy key.

`u` must be fresh and unique.

---

## 11.2 Operation CVM Authorization

Dispatcher must perform checks in this order or an equivalent fail-closed order:

```text
1. parse canonical request
2. verify participant identity
3. verify signature
4. verify pid == active pid
5. verify H(pi) == active policy hash
6. reject replay/duplicate u
7. require target w exists
8. require B_w is LIVE
9. check requester role/authority
10. check operation o
11. check requested state transition s -> s_prime
12. check artifact h_a if applicable
13. evaluate secret_release conditions
14. create outstanding operation
15. dispatch over B_w
```

No participant re-attestation or all-party interaction is required for an ordinary operation already permitted by `pi`.

---

## 11.3 Admit

For model admission:

```text
o = ADMIT
s = ABSENT
s_prime = RUNNING
h_a = registered model digest
```

Authorized payload may include:

```text
q_i
ciphertext or artifact handle
approved settings
conditionally released key/material
```

---

## 11.4 Trusted Service Enforcement

Trusted Service accepts runtime control only over the authenticated Operation CVM channel.

Checks:

```text
valid authenticated channel
operation ID u not previously processed
local S_actual == request.s
artifact digest expected
ciphertext digest valid before decryption
plaintext digest valid after decryption
local runtime invocation succeeds
```

Only after success:

```text
local state = s_prime
accepted_artifact_digest = h_a
mark u processed
```

For admission:

```text
ABSENT -> RUNNING
```

---

## 11.5 Update

Update follows the same path.

Additionally require:

```text
current recorded artifact digest == prior artifact expected by request/policy
```

Only then replace workload.

---

## 11.6 Stop

Typical transition:

```text
RUNNING -> STOPPED
```

No new artifact/key is required.

---

## 11.7 Delete

Typical transition:

```text
STOPPED -> ABSENT
```

No new artifact/key is required.

---

## 11.8 Result Commit

Trusted Service returns authenticated result containing at least:

```text
u
w
result
new state
artifact digest if applicable
```

Operation CVM updates its remote view only when:

```text
result matches an outstanding operation
u matches
w matches
authenticated channel matches B_w
```

The Operation CVM's remote view is advisory for later authorization; the Trusted Service still checks actual local state before every transition.

---

# 12. Exclusive Enforcement Path

The paper's G2 requires complete mediation.

Cursor must inspect Workload CVM privileged interfaces and identify every mechanism capable of:

```text
creating containers/processes
mounting workload content
starting workloads
replacing workload files
stopping workloads
deleting workloads
changing managed workload state
```

For the prototype configuration used in the paper/evaluation:

- these operations must be reachable only through Trusted Service;
- alternative management interfaces must be disabled, removed, permission-restricted, or demonstrably unable to modify the protected workload state.

Document exactly how exclusivity is achieved in the implementation.

Do not claim complete mediation if SSH/root/container-runtime sockets remain intentionally exposed in a way that can bypass Trusted Service.

---

# 13. Concurrency and Thread Safety

The existing concurrency bugs demonstrate that this is a first-class implementation requirement.

## 13.1 Shared Server State

At minimum protect:

```text
pending_challenges_
sessions_
participant_registry
policy_round
pending_launches
live_bindings
artifact_registry
outstanding_operations
processed_operation_ids
```

Do not use one giant mutex around slow external operations unless necessary.

Preferred pattern:

```text
lock
  lookup/copy/update minimal shared state
unlock

perform expensive crypto/QVL/I/O

lock
  validate state has not changed
  commit
unlock
```

Use generation/version checks when releasing locks across long operations.

---

## 13.2 DCAP/QVL Appraisal

The currently patched process-wide appraisal mutex must remain until QVL/appraisal thread safety is proven for the exact used API path.

Instrument:

```text
appraisal_queue_enter_ns
appraisal_lock_acquired_ns
appraisal_done_ns
```

Derived:

```text
appraisal_wait_us
appraisal_service_us
```

This is required to explain concurrent-authentication saturation.

---

## 13.3 Client Identity

Every client identity used as a state-map key must be globally unique within a run.

Required convention already deployed:

```text
cvm_<instance>_client_<local>
```

Store run ID separately. Prefer compound key:

```text
(run_id, global_client_id)
```

for evaluation/log isolation.

---

## 13.4 Lock Ordering

Define and document lock ordering if multiple locks are needed.

Avoid:

```text
state_mutex -> appraisal_mutex
```

in one path and:

```text
appraisal_mutex -> state_mutex
```

in another.

No network call or process launch should occur while holding a broad state lock.

---

# 14. Logging and Audit Events

Use structured log events, not only free-form text.

Every run/event should include:

```text
timestamp_monotonic_ns
timestamp_wallclock
run_id
component
event
participant_id if relevant
w if relevant
operation_id if relevant
status
error_code
```

Security-sensitive material must be redacted.

Suggested events:

```text
OP_CVM_BOOT_START
OP_CVM_PROTECTED_ROOT_READY
OP_CVM_CHANNEL_READY

PARTICIPANT_CHALLENGE_ISSUED
PARTICIPANT_QUOTE_READY
PARTICIPANT_VERIFY_SUCCESS
PARTICIPANT_ACCEPT_REGISTERED
ALL_PARTICIPANTS_REGISTERED

POLICY_ROUND_OPEN
POLICY_PROPOSAL_ACCEPTED
POLICY_ALL_PROPOSALS_RECEIVED
POLICY_JOIN_START
POLICY_JOIN_DONE
POLICY_CANDIDATE_READY
POLICY_CONFIRM_ACCEPTED
POLICY_ACTIVE

WORKLOAD_LAUNCH_CONTEXT_CREATED
WORKLOAD_PROVISION_START
WORKLOAD_PROVISION_DONE
WORKLOAD_BOOT_START
WORKLOAD_TRUSTED_SERVICE_READY
WORKLOAD_ATTEST_START
WORKLOAD_QUOTE_READY
WORKLOAD_QUOTE_VERIFIED
WORKLOAD_CHANNEL_READY
WORKLOAD_BINDING_ACTIVE
WORKLOAD_BINDING_INVALIDATED

TRANSITION_REQUEST_RECEIVED
TRANSITION_AUTHORIZED
SECRET_RELEASED
COMMAND_DISPATCHED
TS_STATE_CHECK_OK
TS_ARTIFACT_CHECK_OK
TS_RUNTIME_START
TS_RUNTIME_READY
TRANSITION_COMMITTED
TRANSITION_REJECTED
```

---

# 15. Error Codes

Use stable machine-readable codes.

Examples:

```text
ERR_UNKNOWN_PARTICIPANT
ERR_DUPLICATE_ACCEPTANCE
ERR_BOOT_SIGNATURE
ERR_POLICY_KEY_PROOF
ERR_MANIFEST_MISMATCH
ERR_CHANNEL_KEY_MISMATCH

ERR_POLICY_PID
ERR_POLICY_VERSION
ERR_POLICY_ROUND
ERR_POLICY_SIGNATURE
ERR_DUPLICATE_PROPOSAL
ERR_POLICY_MALFORMED
ERR_POLICY_JOIN_CONFLICT
ERR_CONFIRM_HASH

ERR_LAUNCH_UNKNOWN
ERR_LAUNCH_REPLAY
ERR_LAUNCH_CONTEXT
ERR_WORKLOAD_MEASUREMENT
ERR_WORKLOAD_CONFIG
ERR_BINDING_NOT_LIVE

ERR_TRANS_SIGNATURE
ERR_TRANS_POLICY_HASH
ERR_TRANS_REPLAY
ERR_TRANS_NOT_ALLOWED
ERR_STATE_MISMATCH
ERR_ARTIFACT_CIPHERTEXT_DIGEST
ERR_ARTIFACT_PLAINTEXT_DIGEST
ERR_SECRET_RELEASE_NOT_ALLOWED
ERR_RUNTIME_FAILURE
```

Evaluation scripts should count codes, not scrape arbitrary prose.

---

# 16. Repository Integration Strategy

Because exact repository layout must be discovered by Cursor, perform this mapping first.

Create:

```text
docs/evaluation/repo_mapping.md
```

with:

```text
Paper component                Existing implementation
--------------------------------------------------------------
Operation CVM server           <file/class>
Participant client             <file/class>
Quote verifier/QVL             <file/class>
Policy parser                  <file/class>
Key vault                      <file/class>
Dispatcher                     <file/class>
Workload Trusted Service       <file/class>
VM provisioning                <script/module>
Guest launcher                 launch-client.sh / actual path
Fleet harness                  cvm-fleet-test.sh / actual path
```

Known current files from prior fixes include:

```text
server/policy_server.cc
QuoteAppraisal/quote_verifier.cc
launch-client.sh
cvm-fleet-test.sh
```

Use these only if they exist in the current checkout.

Do not create a second `policy_server_v2` or equivalent parallel stack unless absolutely necessary.

---

# 17. Recommended Logical API Surface

Map these logical APIs onto existing protobuf/RPCs instead of renaming everything unnecessarily.

## Operation CVM / Participant

```text
GetOperationChallenge()
GetOperationEvidence(challenge)
SubmitParticipantAcceptance(...)
OpenPolicyRound()
SubmitPolicyProposal(...)
GetCandidatePolicy(...)
SubmitPolicyConfirmation(...)
GetPolicyStatus()
```

## Operation CVM / Platform

```text
CreateLaunchContext(...)
ProvisionWorkloadCVM(...)
```

## Operation CVM / Trusted Service

```text
GetWorkloadChallenge(w)
SubmitWorkloadEvidence(...)
EstablishAuthenticatedChannel(...)
DispatchTransition(...)
ReturnTransitionResult(...)
```

## Artifact / Key Management

```text
RegisterArtifactMetadata(...)
UploadArtifactCiphertext(...)
RegisterArtifactKey(...)
```

## Runtime Request

```text
SubmitTransition(...)
```

These are conceptual. Prefer extending existing RPC messages if the repository already has equivalent calls.

---

# 18. State Persistence and Restart Behavior

The paper explicitly requires:

```text
Workload CVM restart or authenticated-channel loss => B_w invalid
```

Implement that exactly.

For other server state, do not invent silent recovery semantics.

At minimum, on uncertain recovery:

```text
fail closed
do not reconstruct LIVE B_w from stale memory/disk state
do not mark a candidate policy active unless activation state is unambiguous
```

If the existing prototype persists active policy or artifact metadata, document the persistence boundary and integrity protection.

---

# 19. Evaluation Instrumentation

The implementation must expose timestamps without changing protocol semantics.

Use:

```text
CLOCK_MONOTONIC_RAW
```

or equivalent monotonic nanosecond clock.

Every formal run receives:

```text
run_id = YYYYMMDD-HHMMSS-<experiment>-<iteration>
```

Never aggregate old log lines from previous runs.

---

# 20. Final Evaluation Implementation

The final paper outline is:

```text
8.1 Experimental Setup
8.2 Multi-party Trust Establishment
8.3 Workload CVM Authentication
8.4 Workload Management and Execution
8.5 Security Validation
```

Implement the following harnesses.

---

## E1. Multi-party Trust Establishment

### Purpose

Measure:

```text
Operation CVM launch
→ protected boot
→ participant authentication
→ policy construction/confirmation
→ POLICY_ACTIVE
```

Participant counts:

```text
N = {2, 4, 8, 16, 32}
```

If the existing 3/4/8/16/24/32 reconciliation data is retained, keep it as auxiliary data. Use one consistent set for the final figure.

### Required timestamps

```text
t_launch_start
t_protected_root_ready
t_channel_ready

t_participant_auth_start
t_all_participants_registered

t_policy_round_open
t_all_proposals_received
t_candidate_ready
t_all_confirmations_received
t_policy_active
```

Derived:

```text
boot_ms
participant_auth_ms
policy_establishment_ms
total_trust_establishment_ms
```

Output:

```text
results/e1_trust_establishment/raw.csv
results/e1_trust_establishment/summary.csv
```

Do not count cloud scheduling queue time if it is outside the explicit Operation CVM launch command boundary; document exact start event.

---

## E2. Policy Processing Scalability

Fixed:

```text
N = 8
```

Rules/entries per participant:

```text
P = {10, 100, 1000}
```

Generate semantically valid typed policies.

Measure isolated parser work:

```text
proposal_verify_us
join_us
candidate_construct_us
total_policy_processing_us
```

Do not include participant network RTT in the isolated parser plot.

Output:

```text
results/e2_policy_scalability/raw.csv
results/e2_policy_scalability/summary.csv
```

---

## E3. Single Workload CVM Authentication

Measure the complete path used by Sec. 5.3:

```text
launch context created
→ platform provisioning
→ Workload CVM boot
→ Trusted Service ready
→ Workload CVM attestation
→ authenticated channel
→ B_w active
```

This experiment **does include provisioning** in the total path.

Required timestamps:

```text
t_launch_context_created
t_provision_start
t_provision_done
t_boot_start
t_trusted_service_ready
t_attest_start
t_quote_ready
t_quote_verified
t_channel_ready
t_binding_active
```

Derived:

```text
provisioning_ms
boot_to_trusted_service_ms
attestation_ms
channel_binding_ms
total_ms
```

Baseline:

```text
TDX-Direct-Launch
```

Baseline must use:

```text
same VM image class
same VM resources
same host
same TDX stack
same quote generation/verification path where applicable
```

The baseline is a **performance reference**, not security-equivalent to TACVM.

Output:

```text
results/e3_workload_auth/raw.csv
results/e3_workload_auth/summary.csv
```

---

## E4. Concurrent Workload CVM Authentication

Concurrency:

```text
M = {1, 2, 4, 8, 16, 24}
```

If hardware capacity limits 24, document it; do not fabricate.

Each Workload CVM must have globally unique identities.

Use a barrier/synchronized release to reduce launch skew.

Measure:

```text
batch_makespan_s
throughput_cvms_s = M / batch_makespan_s
per_cvm_latency_ms
median_latency_ms
p95_latency_ms
fleet_first_message_spread_ms
appraisal_wait_us
appraisal_service_us
```

Compare:

```text
TACVM
TDX-Direct-Launch
```

Reuse and extend `cvm-fleet-test.sh`.

Do not treat the old verifier-only concurrency numbers as equivalent to end-to-end launch/authentication unless they use the same start/end boundary.

Output:

```text
results/e4_concurrent_auth/raw.csv
results/e4_concurrent_auth/summary.csv
```

---

## E5. Representative Workload Admission

Do **not** build a CRUD workload-control benchmark.

Use only representative `admit`, because it exercises the full path:

```text
signed request
→ policy authorization
→ live binding check
→ conditional key release
→ dispatch
→ Trusted Service state check
→ artifact verification
→ local runtime start
→ workload READY
```

Precondition:

```text
Operation CVM policy active
Workload CVM authenticated
B_w LIVE
local workload state = ABSENT
artifact registered
```

Use one fixed representative encrypted artifact. Prefer the real model used by the application experiment. If a 100 MiB synthetic/representative artifact is used, state that explicitly.

Baseline:

```text
TDX-Direct
```

Start:

```text
admission request submitted
```

End:

```text
application READY / first valid service request can be served
```

Record:

```text
authorization_us
key_release_us
dispatch_us
artifact_transfer_ms
trusted_service_validation_us
runtime_startup_ms
end_to_end_admission_ms
```

Output:

```text
results/e5_admission/raw.csv
results/e5_admission/summary.csv
```

---

## E6. Steady-State Application Performance

Run only after TACVM admission succeeds.

Applications:

```text
Redis
ResNet-50 with ONNX Runtime
```

Compare:

```text
TDX-Direct
TACVM
```

Same:

```text
Workload CVM resources
application version
runtime
dataset/model
client load
network setup
```

Redis metrics:

```text
throughput_ops_s
p50_ms
p95_ms
p99_ms
```

ResNet metrics:

```text
inferences_s
mean_latency_ms
p95_latency_ms
```

Do not add a 1→24 Workload CVM scaling sweep unless needed to explain a specific result.

Output:

```text
results/e6_apps/redis_raw.csv
results/e6_apps/resnet_raw.csv
results/e6_apps/summary.csv
```

---

## E7. Security Validation

Automate the following tests.

### S1. Modified Operation CVM root filesystem

Expected:

```text
dm-verity failure and/or participant evidence rejection
workload_control_enabled == false
```

### S2. Invalid Operation CVM evidence

Variants:

```text
wrong REPORTDATA
wrong challenge
wrong pk_ch
wrong d_M
```

Expected:

```text
participant rejects
no policy-key registration
```

### S3. Workload launch-context replay

Reuse consumed `lambda_w`.

Expected:

```text
no new B_w
```

### S4. Wrong Workload CVM measurement/configuration

Modify expected initrd/root hash/dm-verity configuration.

Expected:

```text
Workload CVM authentication rejected
B_w absent
```

### S5. Invalid/stale transition request

Variants:

```text
bad signature
wrong pid
wrong H(pi)
replayed u
unauthorized operation
```

Expected:

```text
Dispatcher rejects
state unchanged
no new secret release
```

### S6. Wrong prior state

Request:

```text
ABSENT -> RUNNING
```

while:

```text
S_actual = RUNNING
```

Expected:

```text
Trusted Service rejects
state unchanged
```

### S7. Wrong artifact digest

Expected:

```text
Trusted Service rejects
transition not committed
```

### S8. Workload CVM restart/channel loss

Expected:

```text
B_w invalidated
subsequent transition rejected
re-authentication required
```

Output:

```text
results/e7_security/security_validation.csv
```

Columns:

```text
test_id
case
injected_fault
expected_enforcement_point
observed_error_code
binding_state
secret_release
state_before
state_after
pass
```

---

# 21. Measurement Methodology

Formal latency experiment default:

```text
warm-up runs: 5
measured runs: 30
fresh sessions: 3
```

Report:

```text
mean
median
p95
standard deviation
95% confidence interval
```

Steady-state application default:

```text
warm-up: 30 s
measurement: 120 s
windows: 5
fresh sessions: 3
```

If runtime constraints require different durations, parameterize them and record actual values.

---

# 22. Result Directory Layout

Use:

```text
evaluation/
  config/
  common/
  scripts/
  generators/
  analysis/
  plots/

results/
  <run_id>/
    environment.json
    git_commit.txt
    config.json
    logs/
    raw/
    summary/
```

Each experiment should also have a stable symlink or copied aggregate location if useful.

`environment.json` should record:

```text
host CPU
physical/logical cores
memory
storage
NIC/network
host OS
kernel
QEMU/KVM
TDX module
QGS
DCAP/QVL versions
Operation CVM resources
Workload CVM resources
application versions
```

---

# 23. Suggested Evaluation Scripts

Prefer orchestration scripts that call the production code path.

Suggested names:

```text
evaluation/scripts/e1_trust_establishment.sh
evaluation/scripts/e2_policy_scalability.sh
evaluation/scripts/e3_workload_auth.sh
evaluation/scripts/e4_concurrent_auth.sh
evaluation/scripts/e5_admission.sh
evaluation/scripts/e6_redis.sh
evaluation/scripts/e6_resnet.sh
evaluation/scripts/e7_security.sh
evaluation/scripts/run_all.sh
```

Common helpers:

```text
evaluation/common/run_context.sh
evaluation/common/timestamps.sh
evaluation/common/csv.sh
evaluation/common/cleanup.sh
evaluation/common/healthcheck.sh
```

Do not make benchmark-only shortcuts that bypass normal security checks.

---

# 24. Health Checks

Before each measured run verify:

```text
correct Operation CVM process is running
correct verifier port is listening
container-backed old verifier is not accidentally active
all expected CVMs reachable
QGS/QVL reachable
no stale policy_server instance
no stale client processes
no stale B_w/pending launch state from prior run
```

After each run:

```text
all requested operations completed
server remains alive
no new segmentation fault
no VERIFY_RESULT=FAILED unless injected by a security test
expected number of success/failure events exactly matches the run configuration
```

This explicitly distinguishes:

```text
"all requests passed"
```

from:

```text
"server stayed alive afterward"
```

---

# 25. Formal CSV Schemas

## Trust establishment

```text
run_id,session,iteration,N,
boot_ms,
participant_auth_ms,
policy_establishment_ms,
total_ms,
success
```

## Policy scalability

```text
run_id,session,iteration,N,P,
proposal_verify_us,
join_us,
candidate_construct_us,
total_us,
success
```

## Workload authentication

```text
run_id,session,iteration,system,w,
provisioning_ms,
boot_ms,
attestation_ms,
binding_ms,
total_ms,
success
```

## Concurrent authentication

```text
run_id,session,iteration,system,M,w,
per_cvm_latency_ms,
batch_makespan_ms,
throughput_cvms_s,
fleet_spread_ms,
appraisal_wait_us,
appraisal_service_us,
success
```

## Admission

```text
run_id,session,iteration,system,w,artifact_id,
authorization_us,
key_release_us,
dispatch_us,
artifact_transfer_ms,
trusted_service_validation_us,
runtime_startup_ms,
total_ms,
success
```

## Application

```text
run_id,session,application,system,
throughput,
p50_ms,
p95_ms,
p99_ms,
notes
```

---

# 26. Final Paper Figure Inputs

The implementation should generate source CSVs sufficient for:

## Figure 6 — Multi-party Trust Establishment

```text
(a) trust establishment latency vs participants
    stacked:
      Operation CVM boot
      participant authentication
      policy establishment

(b) policy processing latency vs policy size
    stacked:
      proposal verification
      restrictive join
      candidate construction
```

## Figure 7 — Workload CVM Authentication

```text
(a) Workload CVM authentication latency breakdown
    TACVM vs TDX-Direct-Launch
    provisioning
    boot
    attestation
    binding

(b) concurrent authentication throughput
    x = concurrent Workload CVMs
    y = CVMs/s
    TACVM vs TDX-Direct-Launch
```

## Figure 8 — Workload Management and Execution

```text
(a) end-to-end workload admission latency
    TDX-Direct vs TACVM

(b) steady-state normalized throughput
    Redis
    ResNet-50
```

## Security Table

Source:

```text
security_validation.csv
```

---

# 27. Unit Tests

Add unit tests for at least:

```text
canonical encoding determinism
domain separation
manifest digest
duplicate participant acceptance
policy-key duplicate binding
proposal signature verification
wrong pid/v/r rejection
duplicate proposal rejection
restrictive set intersection
DENY semantics
policy conflict detection
candidate hash determinism
confirmation mismatch
atomic policy activation
launch-context uniqueness
launch-context replay
live-binding invalidation
transition replay
state mismatch
artifact digest mismatch
```

---

# 28. Integration Tests

Required happy paths:

```text
N participants authenticate same Operation CVM
→ policy activates

policy update succeeds
→ old policy remains active until atomic replacement

Workload CVM provision
→ measured boot
→ attestation
→ B_w

model admission
ABSENT -> RUNNING

stop
RUNNING -> STOPPED

delete
STOPPED -> ABSENT
```

Required negative paths correspond to S1–S8.

---

# 29. Existing Data and How to Treat It

Current historical results include:

1. participant/Operation-CVM attestation timing;
2. policy reconciliation timing;
3. verifier concurrency across multiple CVMs/clients.

These are useful preliminary/microbenchmark data.

Do not mix them blindly with the new formal dataset because their measurement boundaries may differ.

For every legacy result imported into the final dataset, document:

```text
start event
end event
whether provisioning was included
whether boot was included
whether only verifier RPC time was measured
whether the same baseline/configuration was used
```

If boundaries differ, keep the old result as auxiliary validation only.

---

# 30. Implementation Order

Cursor should implement in this order.

## Phase A — Repository audit

- map paper components to code;
- document current RPCs/state structures;
- identify missing paper semantics;
- identify existing evaluation scripts.

## Phase B — Common correctness primitives

- canonical encoding;
- domain-separated hash/sign helpers;
- stable error codes;
- structured logging;
- run IDs;
- global client IDs;
- concurrency safety.

## Phase C — Operation CVM trust establishment

- boot manifest;
- channel key binding;
- participant acceptance and policy-key registration;
- all-participants completion barrier.

## Phase D — Policy

- typed schema;
- validation;
- restrictive join;
- candidate;
- confirmation;
- atomic activation/update.

## Phase E — Workload CVM trust extension

- launch context;
- provisioning handoff;
- measured boot record;
- Trusted Service channel key;
- Workload attestation;
- `B_w`;
- invalidation.

## Phase F — Runtime workload control

- artifact registry;
- Key Vault;
- transition request;
- Dispatcher;
- Trusted Service state/artifact checks;
- result commit.

## Phase G — Evaluation instrumentation

- timestamps;
- CSV writers;
- run isolation;
- health checks.

## Phase H — Formal evaluation scripts

- E1–E7.

Do not start by writing plotting code before protocol timing points are stable.

---

# 31. Cursor Deliverables

Cursor must produce:

```text
1. docs/evaluation/repo_mapping.md
2. docs/evaluation/implementation_status.md
3. protocol/design code changes
4. evaluation harnesses E1–E7
5. unit tests
6. integration tests
7. raw CSV schemas
8. one-command or clearly staged formal-run procedure
```

`implementation_status.md` should classify each paper requirement as:

```text
IMPLEMENTED
EXISTING_AND_VERIFIED
PARTIAL
NOT_IMPLEMENTED
BLOCKED
```

and cite actual files/functions.

---

# 32. Acceptance Criteria

Implementation is complete only if all of the following are true:

- [ ] Operation CVM cannot control workloads before policy activation.
- [ ] Every manifest participant authenticates the same Operation CVM instance.
- [ ] Participant policy keys are uniquely registered.
- [ ] Proposal rounds are scoped by `pid/v/r`.
- [ ] Restrictive join cannot silently widen authority.
- [ ] Candidate activation requires confirmations from all participants.
- [ ] Policy update is atomic.
- [ ] Every Workload CVM gets a fresh `lambda_w`.
- [ ] Replayed launch context cannot create a new `B_w`.
- [ ] Workload evidence binds launch context and `pk_w`.
- [ ] `B_w` is required before secrets/commands are sent.
- [ ] Restart/channel loss invalidates `B_w`.
- [ ] Runtime request binds `pid`, `H(pi)`, `u`, `w`, operation, state transition, and artifact.
- [ ] Trusted Service checks actual prior state.
- [ ] Trusted Service checks artifact integrity.
- [ ] Replayed `u` is rejected.
- [ ] No alternate privileged workload-management path bypasses Trusted Service in the evaluated configuration.
- [ ] Concurrency tests do not crash the verifier.
- [ ] QVL/appraisal contention is instrumented.
- [ ] Formal runs are isolated with `run_id`.
- [ ] E1–E7 produce machine-readable raw results.
- [ ] Server liveness is checked after concurrency runs.
- [ ] No benchmark path disables a paper-required security check.

---

# 33. Non-Goals

Do not expand the implementation scope with unrelated features.

In particular, do not add:

```text
Kubernetes K-Bench integration solely for evaluation
a general CRUD workload generator
a second policy engine
a second attestation stack
multi-cloud orchestration
high-availability Operation CVM replication
new TEE support beyond the current Intel TDX prototype
```

unless separately requested.

---

# 34. First Prompt to Give Cursor

Use the following instruction with this file in the repository:

> Read this specification completely. First inspect the current TACVM repository and produce `docs/evaluation/repo_mapping.md`, mapping every protocol component and evaluation hook in this document to the current files/classes/scripts. Do not implement a parallel protocol stack. Identify which paper semantics are already implemented, partially implemented, or missing. Preserve the existing globally unique CVM client IDs, `state_mutex_` protection for challenge/session state, and process-wide DCAP appraisal mutex. After the mapping, implement the missing functionality in the order defined in Section 30. For every change, keep the normal production protocol path and evaluation path identical except for timestamp/log instrumentation. Do not remove security checks to improve performance.

---

# 35. Source-of-Truth Summary

The current paper's implementation-critical sequence is:

```text
Operation CVM:
  protected measured boot
  → fresh pk_ch
  → all participants authenticate same instance
  → register policy keys
  → collect signed proposals
  → restrictive join
  → unanimous confirmation
  → activate immutable pi

Workload CVM:
  create fresh lambda_w
  → platform provisions VM
  → measure H(lambda_w) + dm-verity configuration
  → Trusted Service creates pk_w
  → Quote binds challenge + H(lambda_w) + pk_w
  → Operation CVM verifies evidence and active-policy constraints
  → authenticated channel
  → consume pending launch
  → establish B_w

Runtime:
  signed q_i
  → Dispatcher verifies active policy + B_w + requested transition
  → conditional key release
  → command over B_w
  → Trusted Service verifies actual prior state + artifact
  → local runtime executes
  → authenticated completion result
  → Operation CVM updates remote view
```

All code and evaluation work should preserve this chain.

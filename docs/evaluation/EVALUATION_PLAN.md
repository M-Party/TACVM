# TACVM Evaluation Plan

This plan evaluates three performance questions for the EuroSys paper. Policy
correctness and adversarial cases are prerequisites rather than independent
performance campaigns. Planned measurements must not be reported as results
until raw data are collected.

## 1. Design assumption

The reviewed initrd configures dm-verity before entering the Operation CVM root
filesystem. It binds the expected dm-verity root hash and security-relevant boot
configuration to an RTMR event log. dm-verity checks protected blocks when they
are read, so TACVM does not claim to load or hash the complete root filesystem
during boot.

Participants authenticate the Operation CVM after its root filesystem and
authentication service start. Each participant verifies a fresh Quote, the
measured boot chain, the event log, the expected dm-verity root hash, and the
attested channel endpoint. The running Operation CVM has no workload-control
authority until all committed participants accept it and their joined policy is
activated. Before activation, it rejects secrets, Workload CVM launches, and
workload transitions.

The Workload CVM experiment measures TACVM's single post-boot Quote. After the
protected root filesystem starts, the Trusted Service generates its channel key.
The Quote binds a fresh Operation CVM challenge, the measured launch-context
digest, and that key to the Workload CVM's boot evidence. The Operation CVM
creates the authenticated binding only after verifying the Quote, replaying the
event log, checking the active policy constraints, and completing proof of key
possession.

## 2. Research questions

| RQ | Question | Evidence |
|---|---|---|
| RQ1 | What one-time cost does TACVM add to post-boot multi-party Operation CVM authentication and policy activation, and how does it scale with participants? | End-to-end and per-phase latency |
| RQ2 | How efficiently can the Operation CVM authenticate Workload CVMs? | Authentication latency, phase breakdown, and authentications per second |
| RQ3 | What deployment and steady-state overhead does TACVM add to a workload? | Matched-baseline authorization and admission latency, deployment throughput, and application throughput and tail latency |

These are the core metrics required for the paper. CPU time, peak RSS, network
bytes, and disk bytes are optional diagnostic counters. Collect them when the
instrumentation is reliable and comparable across variants, but do not make
completion of the core experiments depend on them. Their columns in the common
measurement CSV may be left empty when they are not collected.

## 3. Variants

Use the same VM resources, guest kernel, dm-verity root filesystem, artifact, and
application in every matched comparison.

| Variant | Purpose |
|---|---|
| `TDX-Direct` | RQ3 baseline. A test driver deploys to the same TDX Workload CVM and Trusted Service without Operation CVM policy evaluation. |
| `TDX-Direct-Launch` | RQ2 baseline. The platform launches the same Workload CVM without Operation CVM attestation appraisal or channel binding. |
| `TACVM-NP` | Full multi-participant trust establishment. |
| `TACVM-Active` | Full TACVM after policy activation, used for Workload CVM authentication and recurring deployment cost. |

A TDX image without dm-verity is an optional ablation, not a
security-equivalent baseline.

## 4. Common instrumentation

Use a monotonic clock. Store environment and invariant factors in one run
manifest and store every trial or phase observation in the measurement CSV.
Each record carries `run_id`, trial, experiment, variant, phase, result, and an
error code. Add participant, Workload CVM, policy version, and operation
identifiers when applicable. Never log plaintext secrets.

Instrument these boundaries:

- Operation CVM: launch request, initrd entry, dm-verity setup, root filesystem
  ready, authentication service ready, Quote generation and participant
  verification, signed acceptance and policy-key binding, complete-participant
  acceptance, proposal verification, policy join, candidate distribution,
  participant candidate verification and signing, confirmation verification,
  and policy activation.
- Workload CVM: launch request, dm-verity setup, Trusted Service ready, single
  post-boot Quote generation and verification, channel establishment, and
  authenticated binding ready.
- Deployment: request receipt, policy decision, artifact transfer, secret
  release, Trusted Service dispatch, workload ready, and steady-state interval.

## 5. E1: Operation CVM authentication and policy activation

Measure from the Operation CVM launch request until the authorization policy
becomes active. Report a breakdown of VM and root-filesystem startup, Quote
generation, participant verification, proposal authentication, policy join, and
candidate distribution and confirmation.

### Factors

- Participants: `N = 2, 4, 8, 16, 32` at a fixed 100-rule policy.
- Policy size: `P = 10, 100, 1000` at `N = 8`.
- Quote collateral: cold and warm cache, when applicable.
- Network: measured local RTT. Add one 50 ms case only if remote participation
  is an intended deployment setting.

Vary participant count at a fixed policy size, then policy size at a fixed
participant count. Do not run the full cross-product unless the first results
show an interaction.

### Outputs

- median and p95 end-to-end latency
- stacked phase latency and latency versus participant count
- Quote generation and verification time
- policy verification and join time
- candidate distribution, participant verification and signing, confirmation
  verification, and activation time
- one fail-closed check showing that an absent participant leaves policy inactive

Optional diagnostics are Operation CVM CPU time, peak RSS, and network bytes.

## 6. E2: Workload CVM authentication

Measure from the Operation CVM's launch request until the Workload CVM binding
is usable for workload and secret release. Compare this path with
`TDX-Direct-Launch` to separate ordinary VM startup from TACVM authentication.

### Factors

- Concurrent authentications: `M = 1, 2, 4, 8, 16, 24`, stopping before machine
  resource pressure invalidates the comparison.
- One fixed, representative Workload CVM image.
- Cold and warm Quote collateral, when applicable.

### Outputs

- Median and p95 authentication latency.
- VM launch, dm-verity setup, Trusted Service startup, Quote generation and
  verification, and channel-establishment time.
- Authentications per second.

Optional diagnostics are Operation CVM and host CPU time, peak RSS, disk reads,
and network bytes.

Root-filesystem size is not a primary scaling factor because dm-verity verifies
blocks on demand. The paper should show one latency breakdown and one
throughput-versus-concurrency plot.

## 7. E3: Workload deployment and system overhead

Run E3 after policy activation and Workload CVM authentication so that E1 and E2
are not charged to every deployment. Compare `TDX-Direct` and `TACVM-Active`.
Admission is the main end-to-end operation. Measure admission, update, stop, and
delete separately with one Workload CVM to expose their different data-transfer
and state-transition paths. The steady-state experiments run only after
admission and do not include Operation CVM authentication or policy activation.

### Workloads and factors

- One service workload with measurable request throughput and tail latency.
- One compute-oriented workload supported by the prototype.
- A fixed 100 MiB artifact, plus one representative real artifact size when
  available.
- Deployment concurrency `1, 2, 4, 8, 16, 24`, stopping before host saturation.

### Outputs

- authorization latency excluding transfer
- artifact transfer time and complete admission latency
- successful deployments per second
- steady-state application throughput and median and tail latency

Optional diagnostics are Operation CVM, Workload CVM, and host CPU and memory
use, together with network and disk bytes.

Report authorization and transfer time separately. The steady-state comparison
tests the hypothesis that the Operation CVM is not on the application's
per-request data path.

## 8. Method and minimal first pass

- Use 5 warm-up runs and at least 30 measured runs for end-to-end latency.
- Repeat each major configuration in three fresh VM or process sessions.
- Report median, p95, and a 95% bootstrap confidence interval. Add p99 only when
  the paper makes a tail-latency claim.
- Do not silently remove outliers. Preserve raw and filtered counts.
- Record source, builds, machine allocation, storage, kernels, TDX/QGS/QVS,
  policy fixture, root hashes, and network setup in the run manifest.
- Generate summaries and plots from preserved raw data.

Run this pilot first:

1. Validate the policy fixture and its conflicts.
2. Run E1 for `N = 2, 4, 8`, 100 rules, local RTT, and 30 trials.
3. Run 30 single Workload CVM authentications, then E2 at `M = 1, 2, 4, 8`.
4. Run 30 admissions of a 100 MiB artifact under `TDX-Direct` and
   `TACVM-Active`, separating authorization and transfer time.
5. Run one service workload after admission under both variants.

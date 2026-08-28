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

The Workload CVM experiment must measure the attestation sequence implemented by
the prototype. If the implementation uses separate boot-state and Trusted
Service channel Quotes, report both phases. If it uses one post-boot Quote, report
that choice instead.

## 2. Research questions

| RQ | Question | Evidence |
|---|---|---|
| RQ1 | What one-time cost does TACVM add to post-boot multi-party Operation CVM authentication and policy activation, and how does it scale with participants? | End-to-end and per-phase latency, CPU, memory, and network traffic |
| RQ2 | How efficiently can the Operation CVM authenticate Workload CVMs? | Authentication latency, throughput under concurrency, and resource use |
| RQ3 | What deployment and steady-state overhead does TACVM add to a workload? | Matched-baseline deployment latency, throughput, resource use, and application performance |

## 3. Variants

Use the same VM resources, guest kernel, dm-verity root filesystem, artifact, and
application in every matched comparison.

| Variant | Purpose |
|---|---|
| `TDX-Direct` | RQ3 baseline. A test driver deploys to the same TDX Workload CVM and Trusted Service without Operation CVM policy evaluation. |
| `TACVM-1P` | Fixed-cost reference with one participant. |
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
  verification, all-participant acceptance, proposal verification, policy join,
  candidate confirmation, and policy activation.
- Workload CVM: launch request, dm-verity setup, Trusted Service ready, each
  implemented Quote step, channel establishment, and authenticated binding ready.
- Deployment: request receipt, policy decision, artifact transfer, secret
  release, Trusted Service dispatch, workload ready, and steady-state interval.

## 5. E1: Operation CVM authentication and policy activation

Measure from the Operation CVM launch request until the authorization policy
becomes active. Report a breakdown of VM and root-filesystem startup, Quote
generation, participant verification, proposal authentication, policy join, and
candidate confirmation.

### Factors

- Participants: `N = 1, 2, 4, 8, 16`. The first pass uses `N = 2, 4, 8`.
- Policy size: 10 and 100 rules. A 1,000-rule parser stress point is optional.
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
- Operation CVM CPU time, peak RSS, and network bytes
- one fail-closed check showing that an absent participant leaves policy inactive

## 6. E2: Workload CVM authentication

Measure from the Operation CVM's launch request until the Workload CVM binding
is usable for workload and secret release.

### Factors and metrics

- Concurrent authentications: `M = 1, 2, 4, 8, 16`, stopping before machine
  resource pressure invalidates the comparison.
- One fixed, representative Workload CVM image.
- Cold and warm Quote collateral, when applicable.
- Median and p95 authentication latency.
- VM launch, dm-verity setup, Trusted Service startup, Quote generation and
  verification, and channel-establishment time.
- Authentications per second, Operation CVM and host CPU, peak RSS, disk reads,
  and network bytes.

Root-filesystem size is not a primary scaling factor because dm-verity verifies
blocks on demand. The paper should show one latency breakdown and one
throughput-versus-concurrency plot.

## 7. E3: Workload deployment and system overhead

Run E3 after policy activation and Workload CVM authentication so that E1 and E2
are not charged to every deployment. Compare `TDX-Direct` and `TACVM-Active`.
Admission is the main operation. Add update only if its implementation has a
materially different path. Treat stop and delete as correctness cases unless the
paper claims their performance.

### Workloads and factors

- One service workload with measurable request throughput and tail latency.
- One compute-oriented workload supported by the prototype.
- A fixed 100 MiB artifact, plus one representative real artifact size when
  available.
- Deployment concurrency `1, 2, 4, 8, 16`, stopping before host saturation.

### Outputs

- authorization latency excluding transfer
- artifact transfer time and complete admission latency
- successful deployments per second
- Operation CVM, Workload CVM, and host CPU and memory use
- network and disk bytes
- steady-state application throughput and median and tail latency

Report authorization and transfer time separately. The steady-state comparison
tests the hypothesis that the Operation CVM is not on the application's
per-request data path.

## 8. Compact security validation

These are pass/fail checks, not statistical performance experiments.

| Case | Mutation | Expected result |
|---|---|---|
| S1 | Modify a protected rootfs block | dm-verity reports an integrity failure and the affected data are not used. |
| S2 | Use an unexpected dm-verity root hash or inconsistent event log | Quote appraisal fails. |
| S3 | Replay a Quote for another challenge or channel endpoint | Freshness or endpoint binding fails. |
| S4 | Launch a Workload CVM or provision a secret before policy activation | The Operation CVM rejects the request. |
| S5 | Use an unexpected Workload CVM measurement, launch context, or Trusted Service key | No usable Workload CVM binding is created. |
| S6 | Submit an unauthorized or stale workload request | The Operation CVM rejects it before dispatch. |

Record the enforcing component, error code, and whether a workload, secret, or
state change became observable. Also run the compatible policy fixture and its
conflict mutations before collecting performance data.

## 9. Method and minimal first pass

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
6. Execute S1 through S6 once and fix any instrumentation gap before scaling up.

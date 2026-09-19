# TACVM Evaluation Questions (Q1–Q3)

**Status:** Paper-facing organization for §8.2–§8.4  
**Chain:**

```text
Q1: Establish the trusted control plane
 → Q2: Extend trust to Workload CVMs
 → Q3: Control workloads through the established trust
```

Writing style: EuroSys/OSDI — state the question and design, present results, analyze trends and system meaning. Do not mechanically restate every table cell.

---

## Q1 — Multi-party Trust Establishment

> **Q1: What is the cost and scalability of establishing TACVM's multi-party trusted control plane?**

Two dimensions:

1. How end-to-end trust-establishment cost scales with participant count \(N\).
2. How policy-processing cost scales with policy size \(P\).

**Outputs:** Fig. 6(a) and Fig. 6(b).

### Fig. 6(a) — Trust-establishment latency vs \(N\)

$$
T_{\text{trust}}
=
T_{\text{boot}}
+
T_{\text{participant-auth}}
+
T_{\text{policy-establishment}}
$$

- Scale: \(N=\{2,4,8,16,32\}\)
- Plot: stacked bars (Boot / Participant Authentication / Policy Establishment)
- Harness: `evaluation/scripts/e1_trust_establishment.sh` (formal numbers require TDX host for boot + RA)

**Paper numbers (TDX host):**

| \(N\) | Boot (ms) | Participant Auth (ms) | Policy Establishment (ms) | Total (ms) |
| ---: | ---: | ---: | ---: | ---: |
| 2 | 823 | 35 | 59.367 | 917.367 |
| 4 | 819 | 71 | 59.228 | 949.228 |
| 8 | 826 | 136 | 59.410 | 1021.410 |
| 16 | 821 | 279 | 62.679 | 1162.679 |
| 32 | 828 | 546 | 68.053 | 1442.053 |

**Takeaway:** Boot ~0.82 s (stable). Policy establishment grows slightly. Growth is dominated by participant authentication. 32-party trusted control plane ≈ **1.44 s**.

### Fig. 6(b) — Policy-processing scalability vs \(P\)

- Fixed \(N=3\); \(P=\{10,100,1000\}\) rules/participant; median of 3 runs
- Stacks: Proposal Verification / Restrictive Join / Candidate Construction
- Harness: `N=3 RULES="10 100 1000" bash evaluation/scripts/e2_policy_scalability.sh`
- Excludes RA / network / CONFIRM (parser path only)

**Paper numbers:**

| \(P\) | Verify (ms) | Join (ms) | Construct (ms) | Total (ms) |
| ---: | ---: | ---: | ---: | ---: |
| 10 | 0.35 | 1.05 | 0.14 | 1.54 |
| 100 | 1.89 | 9.34 | 0.65 | 11.88 |
| 1000 | 18.00 | 92.90 | 6.10 | 117.00 |

**Takeaway:** Approximately linear in \(P\). Restrictive join dominates. At \(P=1000\), processing ≈ **117 ms**. Report scalability of processing cost — do not claim algorithmic superiority over alternatives.

---

## Q2 — Workload CVM Authentication

> **Q2: What is the overhead and scalability of authenticating Workload CVMs and establishing their live bindings \(B_w\)?**

- Scale: \(M=\{1,2,4,8,16\}\) Workload CVMs (one auth client each)
- Output: **one compact table** (no figure required)
- Harness target: TDX fleet / `e3`–`e4` path (`evaluation/scripts/e3_workload_auth.sh`, concurrent hooks)

**Paper numbers:**

| \(M\) | Total Auth Time (ms) | Avg Latency (ms) | Throughput (auth/s) |
| ---: | ---: | ---: | ---: |
| 1 | 49 | 49.00 | 20.41 |
| 2 | 85 | 42.50 | 23.53 |
| 4 | 181 | 45.25 | 22.10 |
| 8 | 334 | 41.75 | 23.95 |
| 16 | 684 | 42.75 | 23.39 |

\(\mathrm{Throughput}=M/(T_{\mathrm{total}}/1000)\). All attempts succeeded.

**Takeaway:** Avg latency stays ~**42–49 ms**; throughput ~**22–24 auth/s**. TACVM establishes \(B_w\) in tens of milliseconds per Workload CVM without clear scalability degradation in this range.

---

## Q3 — Workload Management and Control Overhead

> **Q3: What performance overhead does TACVM introduce to workload management and control?**

After Q1+Q2 trust is in place, measure **incremental** control-path cost for a representative `admit`.

| Mode | Path |
|---|---|
| Direct (baseline) | Request → Trusted Service |
| TACVM | Request → Operation CVM (verify/authorize) → Trusted Service |

Same Workload CVM, same in-guest Trusted Service, same subsequent local management/execution path.

**Primary boundary (identical both modes):**

```text
request issued → Trusted Service accepts request
```

Exclude container/model startup and workload execution.

**Primary metric:**

$$
\Delta T = T_{\mathrm{TACVM}} - T_{\mathrm{Direct}}
$$

Harness: `evaluation/scripts/e5_admission.sh` → `e5_control_overhead.py`

**Paper number (local mock control path):**

$$
\Delta T = 0.131027\ \mathrm{ms} \approx 131\ \mu\mathrm{s}
$$

Report \(\Delta T\) in prose (no required figure/table). Do not further decompose into components unless separate component timings exist.

**Takeaway:** Trusted, Operation-CVM-mediated workload control adds only **sub-millisecond** incremental latency on the management path.

---

## Mapping to harness scripts

| Question | Paper artifact | Script(s) | Notes |
|---|---|---|---|
| Q1 / Fig.6(a) | Trust establishment vs \(N\) | `e1_trust_establishment.sh` | Formal boot/RA on TDX host |
| Q1 / Fig.6(b) | Policy processing vs \(P\) | `e2_policy_scalability.sh` (`N=3`) | Portable; matches paper table |
| Q2 / Table | Workload auth vs \(M\) | `e3_workload_auth.sh` (+ fleet) | Needs TDX host |
| Q3 / \(\Delta T\) | Control overhead | `e5_admission.sh` | Mock portable; remeasure on TDX for RPC-real Direct |

Older specs that numbered “Q3=Workload auth / Q5=admission” are superseded by this Q1–Q3 chain for the paper Evaluation section.

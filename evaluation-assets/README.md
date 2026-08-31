# TACVM Evaluation Planning and Policy Assets

This directory currently contains policy specifications, three separate policy
agreement components, an experiment plan, and result-recording templates. It
does not yet contain the E1--E3 launch, attestation, workload, or measurement
harnesses.

The three policy components are:

1. `policy-aggregation-core/`: a stateless restrictive join and candidate
   construction library;
2. `operation-cvm-policy-coordinator/`: the Operation CVM round state machine
   for proposal verification, candidate distribution, confirmation collection,
   and activation; and
3. `participant-policy-confirmer/`: the participant-side candidate check and
   `TACVM-CONFIRM` generator.

The aggregation core and coordinator are both integrated into the Operation CVM
in a deployed TACVM. They are separated here to make implementation ownership,
testing, and RQ1 phase measurements explicit. `evaluation-assets/` is not an
external online service used by TACVM.

Use the files in this directory in the following order:

1. Freeze the provisional schema in `POLICY_SCHEMA.md`.
2. Instantiate and validate
   `policy-aggregation-core/templates/participant-proposal.yaml`.
3. Test deterministic candidate construction in `policy-aggregation-core/`
   using `policy-aggregation-core/fixtures/three-party-proposals.yaml`.
4. Test candidate verification and confirmation generation in
   `participant-policy-confirmer/`.
5. Run the signed proposal-to-activation flow in
   `operation-cvm-policy-coordinator/`.
6. Add the timestamp events required by `EVALUATION_PLAN.md` when the E1--E3
   harnesses are implemented.
7. Instantiate `results/run-manifest-template.yaml` for each experiment
   configuration.
8. Write every trial and phase measurement using the columns in
   `results/measurements-template.csv`.
9. Run the minimal first evaluation pass before adding optional scale points or
   ablations.

The manifest records the environment and configuration that remain fixed for a
run. The measurement CSV records the observations produced by its individual
trials and phases. Their shared `run_id` links the two files.

The policy wire format, signature suite, launch-context injection mechanism, and
persistent freshness mechanism remain provisional until they match the system
prototype. The design uses one post-boot Workload CVM Quote that binds the
launch-context digest and Trusted Service channel key. Do not copy planned
numbers into the paper as measured results.

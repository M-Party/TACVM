# TACVM Evaluation Assets

Use the files in this directory in the following order:

1. Freeze the provisional schema in `policy-template.md`.
2. Implement and validate `policies/tacvm-policy-template.yaml`.
3. Run the join and negative fixtures in
   `policies/three-party-example.yaml`.
4. Add the timestamp events required by `experiment-plan.md`.
5. Instantiate `results/run-manifest-template.yaml` for each experiment
   configuration.
6. Write every trial and phase measurement using the columns in
   `results/measurements-template.csv`.
7. Run the minimal first evaluation pass before adding optional scale points or
   ablations.

The manifest records the environment and configuration that remain fixed for a
run. The measurement CSV records the observations produced by its individual
trials and phases. Their shared `run_id` links the two files.

The policy format, exact Workload CVM attestation sequence, signature suite, and
persistent freshness mechanism remain provisional until they match the
prototype. Do not copy planned numbers into the paper as measured results.

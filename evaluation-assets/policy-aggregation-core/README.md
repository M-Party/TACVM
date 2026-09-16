# TACVM Policy Aggregation Core

This directory implements only TACVM's deterministic restrictive policy join.
It has no participant private keys, network transport, proposal collection
state, confirmation collection state, or policy activation state.

## Interface

The main function is:

```python
build_candidate(context, participant_order, proposals_by_participant)
```

It verifies that exactly one structurally valid proposal is supplied for every
manifest participant, joins the proposals in manifest order, and returns:

```yaml
candidate:
  schema: tacvm-policy-candidate/v0.2
  context: {policy_id: "...", version: 1, round: 0}
  inputs:
    - {participant_id: "id_M", proposal_digest: "sha384:..."}
  policy: { ... }
candidate_digest: "sha384:..."
```

The caller must authenticate proposal signatures before invoking this core.
That responsibility belongs to the Operation CVM policy coordinator.

## Join rules

- allowlists, lifecycle transitions, artifact digests, measurements, endpoints,
  and requester sets are intersected;
- security requirements are combined so that a check required by any proposal
  remains required;
- compatible role assignments are merged and conflicting assignments abort;
- an empty required identity or artifact set aborts the round;
- an empty optional communication, secret, or lifecycle capability denies that
  capability; and
- the result must admit no behavior forbidden by an input proposal.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
pytest
```

Use `templates/participant-proposal.yaml` to create participant inputs. The
compatible three-party test case is in `fixtures/three-party-proposals.yaml`.

For local scale tests, generate a homogeneous fixture (identical bodies,
distinct `author.participant_id` only):

```bash
python fixtures/generate_homogeneous.py --n 16 --rules 4 \
  -o fixtures/sixteen-party-homogeneous.yaml
# Optional E1-style rule count:
python fixtures/generate_homogeneous.py --n 32 --rules 100 \
  -o fixtures/thirty-two-party-homogeneous-100rules.yaml
pytest
```

Committed homogeneous fixtures used by `tests/test_homogeneous_scale.py`:

| N | File |
|---|---|
| 4 | `fixtures/four-party-homogeneous.yaml` |
| 8 | `fixtures/eight-party-homogeneous.yaml` |
| 16 | `fixtures/sixteen-party-homogeneous.yaml` |
| 32 | `fixtures/thirty-two-party-homogeneous.yaml` |

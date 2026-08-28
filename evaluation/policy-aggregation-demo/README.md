# TACVM Policy Aggregation Protocol Prototype

This directory contains a Python prototype of the policy flow between enrolled
TACVM participants and the Operation CVM.

It implements:

1. YAML policy proposals bound to one policy ID, version, negotiation round, and
   roster digest;
2. one Ed25519-signed proposal per enrolled boot slot;
3. signature, context, duplicate-slot, and complete-roster checks;
4. deterministic restrictive field-specific joins;
5. a canonical candidate containing the ordered proposal digests;
6. participant-side checking that the candidate does not weaken a proposal;
7. one Ed25519 confirmation per roster slot; and
8. activation only after every roster member confirms the same candidate digest.

## Install and run

Python 3.9 or newer is required.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
pytest
python demo.py
```

The demo prints the active candidate, its SHA-384 digest, and the three signed
confirmations.

## Source layout

- `tacvm_policy/policy.py`: canonical encoding profile, Ed25519 envelopes,
  restrictive joins, candidate verification, confirmation, and activation.
- `tacvm_policy/yamlio.py`: YAML loading with duplicate-key rejection.
- `fixtures/three-party-proposals.yaml`: complete model-owner, data-owner, and
  operator proposals.
- `demo.py`: end-to-end proposal-to-activation flow.
- `tests/test_policy.py`: compatible join, deterministic ordering, fail-closed
  activation, signature rejection, role conflict, artifact conflict, lifecycle
  restriction, and weakened-candidate tests.

## Join behavior

- Workload CVM measurements, root hashes, TCB statuses, artifact digests,
  registrars, communication endpoints, peer identities, secret scopes, and
  lifecycle edges are intersected.
- Required launch-context fields are unioned, representing logical AND.
- Boolean security requirements are combined with logical OR: a check required
  by any participant remains required in the candidate.
- Compatible role assignments are merged. Conflicting assignments return
  `BOTTOM_ROLE_CONFLICT`.
- An empty Workload CVM identity or artifact intersection aborts the round.
- An empty communication, secret, or lifecycle intersection disables that
  capability without weakening another proposal.

## Prototype boundary

This is executable protocol and evaluation code, not a production policy
engine. In particular:

- roster public keys are passed in as already enrolled policy keys;
- sorted-key JSON with normalized set-valued arrays is the local canonical
  encoding profile, while the production encoding remains an open design choice;
- transport, persistent version storage, rollback protection, rate limiting,
  audit storage, and Workload CVM enforcement are outside this directory; and
- symbolic measurement and artifact digests in the fixture must be replaced by
  real values for integration testing.

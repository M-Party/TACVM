# TACVM Participant Policy Confirmer

This directory implements only the participant-side confirmation step. It does
not aggregate proposals or activate a policy.

## Algorithm

Given the participant's own proposal, locally expected
`<policy_id, version, round>`, and a candidate received from the authenticated
Operation CVM channel, `confirm_policy_candidate()`:

1. checks that the proposal belongs to the local protocol identifier;
2. checks that the candidate belongs to the expected round;
3. recomputes and checks the candidate digest;
4. checks that the candidate records the digest of the participant's proposal;
5. checks that the candidate admits no behavior forbidden by that proposal; and
6. signs `TACVM-CONFIRM` with the policy private key registered during
   Operation CVM acceptance.

Failure returns no confirmation.

## Install and run

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ../policy_aggregation
python -m pip install -r requirements.txt

python confirm_policy.py \
  --participant-id id_M \
  --proposal participant-id_M.yaml \
  --candidate candidate-bundle.yaml \
  --policy-private-key id_M-policy-key.pem \
  --policy-id sha384:POLICY_TEST_001 \
  --version 1 \
  --round 0 > id_M-confirmation.json
```

The output binds the participant identifier, policy identifier, version,
round, and locally computed candidate digest. It is submitted to the Operation
CVM policy coordinator.

The policy aggregation core is a shared semantics library, not an online
service contacted by the participant.

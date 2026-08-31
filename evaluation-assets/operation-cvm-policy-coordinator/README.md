# TACVM Operation CVM Policy Coordinator

This directory implements the Operation CVM state machine for one policy
negotiation round. It coordinates the protocol but delegates deterministic
policy composition to `policy-aggregation-core`.

## Responsibilities

1. Issue `TACVM-POLICY-REQUEST` for `<policy_id, version, round>`.
2. Receive exactly one signed proposal from every manifest participant.
3. Verify each proposal with the policy key in the internal participant-key map
   `R[participant_id]`.
4. Invoke the aggregation core to construct one candidate policy.
5. Send the same `TACVM-POLICY-CANDIDATE` to every participant over its
   authenticated Operation CVM channel.
6. Verify one `TACVM-CONFIRM` from every manifest participant.
7. Atomically activate the candidate only after all confirmations target the
   same policy identifier, version, round, and candidate digest.
8. Optionally return `TACVM-POLICY-ACTIVATED` notices.

Before step 7, the object is a candidate policy rather than an active consensus
policy. A missing or invalid proposal or confirmation leaves the round
inactive. For a policy update, the caller must keep the previous version active
until this state machine successfully returns a new active snapshot.

## Transport interface

`PolicyCoordinator.distribute_candidate(send_message)` accepts a callback:

```python
send_message(participant_id, candidate_message)
```

The callback is where the TACVM implementation connects its mutually
authenticated participant channels. The coordinator itself does not implement
sockets, retries, or durable storage.

## Install and run the end-to-end demo

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ../policy-aggregation-core
python -m pip install -e ../participant-policy-confirmer
python -m pip install -r requirements.txt
python -m pip install -e .
pytest
python demo.py
```

The demo uses generated Ed25519 keys and symbolic fixture measurements. It is a
protocol test, not a production transport or persistent policy store.

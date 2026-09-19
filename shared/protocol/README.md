# TACVM Protocol Helpers (shared)

Portable canonical encoding and TEE adapters.

```bash
cd shared/protocol
python3 -m pip install -e '.[test]'
pytest
```

```python
from tacvm_protocol import canonical_encode, hash_domain, get_tee_backend
```

Role-specific state machines now live under:

- `operation_cvm/participant_registry`
- `operation_cvm/workload_launch`
- `operation_cvm/dispatcher`
- `workload_cvm/trusted_service`

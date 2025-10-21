# Policy-as-Code for Nimbus

Nimbus can enforce lightweight policy checks against incoming GitHub workflow jobs before they are admitted to the queue. The control plane reads a YAML policy file pointed to by `NIMBUS_JOB_POLICY_PATH` and rejects any job that violates the configured rules.

## Configuration

1. Write a policy file:

```yaml
# policy/job-policy.yaml
deny_labels:
  - production
  - insecure

require_labels:
  - safety-review

allow_repositories:
  - evalops/sandbox
  - evalops/prompt-sweeps

block_title_patterns:
  - (?i)deploy
```

2. Point the control plane at the file and restart:

```bash
export NIMBUS_JOB_POLICY_PATH=/etc/nimbus/job-policy.yaml
uvicorn nimbus.control_plane.app:create_app --factory
```

## Supported Rules

- `deny_labels`: Jobs containing any of these labels are rejected.
- `require_labels`: Each job must include all listed labels.
- `allow_repositories`: If set, the job repository must match one of the entries.
- `deny_repositories`: Explicitly disallow specific repositories.
- `block_title_patterns`: Regular expressions evaluated against the workflow display title or workflow name.

Rules are case-insensitive. When a job is rejected, the control plane returns `403` with a reason so the calling system can surface the failure.

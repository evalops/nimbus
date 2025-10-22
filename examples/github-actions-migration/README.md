# GitHub Actions ➜ Nimbus Migration Example

This directory demonstrates how to mirror an existing GitHub Actions workflow while offloading evaluation jobs to Nimbus.

## Layout

```
examples/github-actions-migration/
├── README.md
├── workflow-original.yml         # GitHub Actions workflow before migration
├── workflow-nimbus.yml           # Transitional workflow calling Nimbus
└── importer-config.yaml          # Input for scripts/import/github_workflow.py
```

### `workflow-original.yml`

Standard GH Actions workflow running evaluations on hosted runners.

### `workflow-nimbus.yml`

Same trigger, but evaluation steps submit to Nimbus via the CLI while the remainder of the pipeline stays in GitHub Actions. Once the team is comfortable, the workflow can be retired completely and the Nimbus GitHub App will trigger evaluations directly.

### `importer-config.yaml`

Configuration consumed by `scripts/import/github_workflow.py` to translate job metadata and cache scopes.

## Usage

1. Update the repository owner/repo values inside `importer-config.yaml`.
2. Run the importer:
   ```bash
   uv run python scripts/import/github_workflow.py --config examples/github-actions-migration/importer-config.yaml
   ```
3. Commit the generated Nimbus configuration (under `config/`).
4. Swap `workflow-original.yml` with `workflow-nimbus.yml` in your GitHub repo and add the `NIMBUS_API_TOKEN` secret.
5. Monitor the Nimbus dashboard to ensure the evaluations run as expected.

Feel free to duplicate this directory and customise it for your own migration playbooks.

# Migrating Eval Suites from GitHub Actions to Nimbus

This playbook shows how to move an evaluation workflow from GitHub Actions (GHA) to Nimbus while staying productive throughout the transition.

## 1. Audit your current workload

| What to capture | Why it matters |
| --- | --- |
| Average eval runs/day, peak concurrency | Puts a ceiling on runner pool sizing |
| Total runtime + queue latency | Highlights GH Actions bottlenecks |
| Cache hit rate / reused layers | Quantifies waste that Nimbus cache can reclaim |
| Secrets + artefacts used | Drives agent bootstrap + vault wiring |

Use the GitHub Actions usage dashboard or export with `gh api repos/:owner/:repo/actions/runs`.

## 2. Stand up Nimbus side-by-side

1. Follow the [Onboarding Playbook](./onboarding.md) to deploy the control plane, caches, and logging pipeline.
2. Provision at least one host agent per concurrency class (CPU/GPU/region). Label them to mirror your GH self-hosted runner labels.
3. Import your evaluation repo into Nimbus:

   ```bash
   uv run python scripts/import/github_workflow.py --org acme --repo evals --workflow eval.yml
   ```

   The importer translates GH workflow steps into Nimbus job metadata and cache scopes. Review and commit the generated config.

## 3. Keep GH Actions as the orchestrator (optional bridge)

If you are not ready for a hard cutover, reroute only the heavy evaluation steps to Nimbus:

```yaml
# .github/workflows/eval.yml
jobs:
  eval:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Submit eval to Nimbus
        run: |
          pip install nimbus-cli
          nimbus submit \
            --base-url https://nimbus.example.com \
            --token ${{ secrets.NIMBUS_API_TOKEN }} \
            --suite smoke \
            --metadata git_sha=${{ github.sha }}
```

GitHub Actions becomes the trigger; Nimbus executes the heavy lifting and reports back via webhook.

## 4. Switch to Nimbus-native orchestration

After validating pipeline parity:

1. Disable the GH Actions job and let Nimbus event subscriptions (GitHub App webhook) fire evals directly.
2. Run the `nimbus.cli.report overview --json` command nightly to capture queue depth, cache hit ratio, and resource hot spots for stakeholders.
3. Use the new `/api/observability/performance` endpoint to integrate dashboard metrics into your internal reporting.

## 5. Measure the impact

Leverage the ROI calculator (`tools/roi_calculator.py`) to demonstrate cost and latency deltas:

```bash
uv run python tools/roi_calculator.py \
  --gh-minute-cost 0.008 \
  --gh-queue-latency-mins 5 \
  --nimbus-minute-cost 0.0025 \
  --runs-per-day 180 \
  --avg-runtime-mins 12
```

Share before/after plots for:

- Average queue latency per eval
- Monthly billable minutes vs Nimbus runner spend
- Cache hit rate improvements (artifact + Docker)

## 6. Update docs & train the team

- Publish a Confluence/Notion page linking to `docs/onboarding.md` and this migration guide.
- Record a loom/walkthrough showing the Nimbus dashboard, cache performance cards, and the new job detail page.
- Encourage engineers to use the `nimbus` CLI locally to reproduce evals (parity with `act` for GH).

With a structured plan, migration gravity is minimised: teams get faster evaluations, deeper observability, and lower costs without giving up their GitHub investment.

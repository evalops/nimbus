# Nimbus ROI Calculator

Moving off managed CI requires a business case. The `tools/roi_calculator.py` helper turns your workload assumptions into an actionable comparison against GitHub Actions.

## Usage

```bash
uv run python tools/roi_calculator.py \
  --runs-per-day 200 \
  --avg-runtime-mins 15 \
  --gh-minute-cost 0.008 \
  --nimbus-minute-cost 0.0025 \
  --gh-queue-latency-mins 6 \
  --nimbus-queue-latency-mins 1 \
  --hardware-cost-per-hour 4.0
```

The script reports:

- **Monthly cost** for GH Actions vs Nimbus (including your self-hosted hardware estimate)
- **Annualised savings**
- **Time saved per eval** from reduced queue latency
- **Break-even eval volume** (“at N runs/day Nimbus overtakes GH Actions even with conservative hardware estimates”)

You can also supply a YAML file:

```yaml
runs_per_day: 180
avg_runtime_mins: 12
gh_minute_cost: 0.008
nimbus_minute_cost: 0.002
hardware_cost_per_hour: 5.5
gh_queue_latency_mins: 5
nimbus_queue_latency_mins: 1
```

```bash
uv run python tools/roi_calculator.py --config roi-example.yaml
```

## Presenting the results

- Drop the CSV output (`--csv out.csv`) into a slide to show monthly/annual savings.
- Chart the **cost per eval** over volume to highlight the break-even point.
- Combine with cache analytics from the dashboard to emphasise how higher hit ratios compound the runtime savings.

Keep the calculator in your sales/demo toolkit and refresh the inputs quarterly as cloud pricing changes.

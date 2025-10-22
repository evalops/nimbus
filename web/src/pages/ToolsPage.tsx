import { useMemo, useState } from "react";

import "./ToolsPage.css";

interface RoiInputs {
  runsPerDay: number;
  avgRuntimeMins: number;
  ghMinuteCost: number;
  nimbusMinuteCost: number;
  hardwareCostPerHour: number;
  ghQueueLatencyMins: number;
  nimbusQueueLatencyMins: number;
}

interface RoiResult {
  ghMonthlyCost: number;
  nimbusMonthlyCost: number;
  annualSavings: number;
  timeSavedPerEval: number;
  breakevenLabel: string;
}

const DEFAULT_INPUTS: RoiInputs = {
  runsPerDay: 180,
  avgRuntimeMins: 12,
  ghMinuteCost: 0.008,
  nimbusMinuteCost: 0.0025,
  hardwareCostPerHour: 4,
  ghQueueLatencyMins: 5,
  nimbusQueueLatencyMins: 1,
};

export function ToolsPage() {
  const [inputs, setInputs] = useState<RoiInputs>(DEFAULT_INPUTS);

  const result = useMemo<RoiResult>(() => {
    const minutesPerDay = inputs.runsPerDay * inputs.avgRuntimeMins;
    const ghDailyCost = minutesPerDay * inputs.ghMinuteCost;
    const ghMonthlyCost = ghDailyCost * 30;

    const nimbusComputeDaily = minutesPerDay * inputs.nimbusMinuteCost;
    const nimbusHardwareDaily = (minutesPerDay / 60) * inputs.hardwareCostPerHour;
    const nimbusMonthlyCost = (nimbusComputeDaily + nimbusHardwareDaily) * 30;

    const annualSavings = (ghMonthlyCost - nimbusMonthlyCost) * 12;
    const timeSavedPerEval = Math.max(inputs.ghQueueLatencyMins - inputs.nimbusQueueLatencyMins, 0);

    const ghPerEval = inputs.avgRuntimeMins * inputs.ghMinuteCost;
    const nimbusPerEval = inputs.avgRuntimeMins * inputs.nimbusMinuteCost +
      (inputs.avgRuntimeMins / 60) * inputs.hardwareCostPerHour;

    let breakevenLabel = "Equal cost per eval";
    if (nimbusPerEval > ghPerEval) {
      breakevenLabel = "Nimbus more expensive per eval (adjust inputs)";
    } else if (nimbusPerEval < ghPerEval) {
      breakevenLabel = "Immediate savings";
    }

    return {
      ghMonthlyCost,
      nimbusMonthlyCost,
      annualSavings,
      timeSavedPerEval,
      breakevenLabel,
    };
  }, [inputs]);

  const handleChange = (field: keyof RoiInputs) => (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = Number(event.target.value);
    setInputs((prev) => ({
      ...prev,
      [field]: Number.isFinite(value) ? value : 0,
    }));
  };

  return (
    <div className="tools__container">
      <header className="tools__header">
        <div>
          <h1>Tools & ROI</h1>
          <p>Estimate the operational savings of running evaluations on Nimbus.</p>
        </div>
      </header>

      <section className="tools__section">
        <h2>Compute ROI</h2>
        <div className="tools__grid">
          <label>
            Runs per day
            <input type="number" min="1" value={inputs.runsPerDay} onChange={handleChange("runsPerDay")} />
          </label>
          <label>
            Avg runtime (min)
            <input type="number" min="1" step="0.1" value={inputs.avgRuntimeMins} onChange={handleChange("avgRuntimeMins")} />
          </label>
          <label>
            GH Actions cost/min
            <input type="number" min="0" step="0.0001" value={inputs.ghMinuteCost} onChange={handleChange("ghMinuteCost")} />
          </label>
          <label>
            Nimbus cost/min
            <input type="number" min="0" step="0.0001" value={inputs.nimbusMinuteCost} onChange={handleChange("nimbusMinuteCost")} />
          </label>
          <label>
            Hardware cost/hour
            <input type="number" min="0" step="0.1" value={inputs.hardwareCostPerHour} onChange={handleChange("hardwareCostPerHour")} />
          </label>
          <label>
            GH queue latency (min)
            <input type="number" min="0" step="0.1" value={inputs.ghQueueLatencyMins} onChange={handleChange("ghQueueLatencyMins")} />
          </label>
          <label>
            Nimbus queue latency (min)
            <input type="number" min="0" step="0.1" value={inputs.nimbusQueueLatencyMins} onChange={handleChange("nimbusQueueLatencyMins")} />
          </label>
        </div>
      </section>

      <section className="tools__section">
        <h2>Results</h2>
        <div className="tools__results-grid">
          <ResultCard label="GitHub Actions monthly cost" value={`$${result.ghMonthlyCost.toFixed(2)}`} />
          <ResultCard label="Nimbus monthly cost" value={`$${result.nimbusMonthlyCost.toFixed(2)}`} />
          <ResultCard label="Annual savings" value={`$${result.annualSavings.toFixed(2)}`} emphasize />
          <ResultCard label="Time saved per eval" value={`${result.timeSavedPerEval.toFixed(1)} minutes`} />
          <ResultCard label="Breakeven" value={result.breakevenLabel} />
        </div>
      </section>

      <section className="tools__section">
        <h2>Next steps</h2>
        <ul className="tools__next">
          <li>
            Export the numbers with <code>uv run python tools/roi_calculator.py</code> for executive decks.
          </li>
          <li>
            Pair this with the migration example in <code>examples/github-actions-migration</code> to quantify savings.
          </li>
          <li>
            Tune the cache hit ratios via the dashboard’s cache performance cards to squeeze runtime further.
          </li>
        </ul>
      </section>
    </div>
  );
}

function ResultCard({ label, value, emphasize }: { label: string; value: string; emphasize?: boolean }) {
  return (
    <article className={emphasize ? "tools__result-card tools__result-card--emphasize" : "tools__result-card"}>
      <span className="tools__result-label">{label}</span>
      <span className="tools__result-value">{value}</span>
    </article>
  );
}

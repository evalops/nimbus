import { createEval2Otel, convertOllamaToEvalResult } from 'eval2otel';
import { Ollama } from 'ollama';

// This script runs a single AI evaluation and exports the results to an
// OpenTelemetry collector. It is intended to be run as a Nimbus job.

// 1. Initialize Eval2Otel
// It automatically reads OTLP endpoint and service name from environment variables
// like OTEL_EXPORTER_OTLP_ENDPOINT and OTEL_SERVICE_NAME, which are provided
// by the Nimbus platform.
const eval2otel = createEval2Otel({
  serviceName: process.env.OTEL_SERVICE_NAME || 'nimbus-eval-job',
  captureContent: true, // Opt-in to capture AI model inputs and outputs
});

// 2. Setup the AI model client
// We use Ollama for this example to allow for local testing.
// The host is configured by an environment variable passed into the job by Nimbus.
const ollama = new Ollama({
  host: process.env.OLLAMA_HOST || 'http://localhost:11434',
});

async function runEvaluation() {
  console.log('Starting AI evaluation...');
  const model = process.env.MODEL || 'llama3';
  const prompt = process.env.PROMPT || 'Why is the sky blue?';

  try {
    // 3. Run the evaluation
    // We record the start time to measure latency.
    const startTime = Date.now();
    const response = await ollama.chat({
      model: model,
      messages: [{ role: 'user', content: prompt }],
    });
    const endTime = Date.now();
    console.log(`Received response from ${model}:`, response.message.content);

    // 4. Convert the provider-native result to the Eval2Otel format
    const evalResult = convertOllamaToEvalResult(
      { model, messages: [{ role: 'user', content: prompt }] },
      response,
      startTime,
      endTime
    );

    // 5. Process the evaluation result to generate and export OTel telemetry
    eval2otel.processEvaluation(evalResult, {
      attributes: {
        'eval.source': 'nimbus-runner',
        'eval.type': 'chat-completion',
      },
    });

    console.log('Successfully processed evaluation and sent to OpenTelemetry collector.');

  } catch (error) {
    console.error('An error occurred during the evaluation:', error);
    // Optionally, you could create an OTel span to record the error
    process.exit(1);
  } finally {
    // 6. Gracefully shutdown the OTel exporter
    // This ensures all buffered telemetry is sent before the process exits.
    await eval2otel.shutdown();
    console.log('OpenTelemetry shutdown complete.');
  }
}

runEvaluation();

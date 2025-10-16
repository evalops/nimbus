#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

echo "===> Running Python dependency audit"
uv tool run pip-audit --skip-editable --require-hashes --path "$ROOT_DIR"

echo "===> Auditing web frontend dependencies"
if [ -f "$ROOT_DIR/web/package.json" ]; then
  (cd "$ROOT_DIR/web" && npm install --ignore-scripts --no-audit >/dev/null && npm audit --omit=dev)
fi

echo "===> Auditing ai-eval-runner container dependencies"
if [ -f "$ROOT_DIR/containers/ai-eval-runner/package.json" ]; then
  (cd "$ROOT_DIR/containers/ai-eval-runner" && npm install --ignore-scripts --no-audit >/dev/null && npm audit --omit=dev)
fi

echo "All dependency audits completed"

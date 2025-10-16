#!/bin/bash
# Backwards-compatible wrapper for the enhanced privileged setup script.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/nimbus-privileged-setup.sh" "$@"

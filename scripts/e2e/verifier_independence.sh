#!/usr/bin/env bash
# Exact entrypoint for FG-072 verifier independence classification and enforcement suite
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "${SCRIPT_DIR}/suites/agent/verifier_independence.sh" "$@"

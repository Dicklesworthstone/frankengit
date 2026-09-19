#!/usr/bin/env bash
# Exact entrypoint for FG-043c policy rollout and snapshot replay evidence suite
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "${SCRIPT_DIR}/suites/policy/policy_rollout_replay.sh" "$@"

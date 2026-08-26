#!/usr/bin/env bash
# Exact entrypoint for FG-042c auth recovery races
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "${SCRIPT_DIR}/suites/security/auth_recovery_races.sh" "$@"

#!/usr/bin/env bash
# Retain the existing replay command for callers of the standalone script.
set -euo pipefail
exec bash "$(dirname "${BASH_SOURCE[0]}")/check.sh" --dpor "$@"

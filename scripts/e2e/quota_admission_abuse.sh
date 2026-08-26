#!/usr/bin/env bash
# Exact entrypoint for FG-056b quota admission abuse campaign
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "${SCRIPT_DIR}/suites/quota/quota_admission_abuse.sh" "$@"

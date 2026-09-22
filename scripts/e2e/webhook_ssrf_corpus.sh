#!/usr/bin/env bash
# Exact entrypoint for FG-046b webhook SSRF and retry adversarial corpus
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "${SCRIPT_DIR}/suites/security/webhook_ssrf_corpus.sh" "$@"

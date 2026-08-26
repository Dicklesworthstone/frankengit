#!/usr/bin/env bash
# Exact entrypoint for FG-042c account security corpus
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "${SCRIPT_DIR}/suites/security/account_security_corpus.sh" "$@"

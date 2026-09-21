#!/usr/bin/env bash
# FG-047b SSH transport security entrypoint
# Delegates to discovered suite scripts/e2e/suites/transport/ssh_transport_security.sh
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "$DIR/suites/transport/ssh_transport_security.sh" "$@"
